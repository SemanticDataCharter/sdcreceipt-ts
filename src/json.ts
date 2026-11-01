/**
 * Read JSON, refusing what two parsers could read differently (sdcreceipt `strict_json_loads`).
 *
 * `JSON.parse` keeps the last of two identical object keys, and another implementation may keep the
 * first, so the two would read different documents from the same bytes (Lee, 4.3.x review, F-06).
 * It also rounds an integer beyond 2^53 - 1 without a word, so a Receipt carrying one would hash
 * differently here than in the issuer and look tampered with; RFC 8785 refuses such a value, and so
 * does this. Nesting deep enough to exhaust the stack is refused too (F-05).
 */

export class StrictJsonError extends Error {
  override name = 'StrictJsonError';
}

const MAX_DEPTH = 256;
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

export function strictParse(text: string): unknown {
  let i = 0;
  const fail = (what: string): never => {
    throw new StrictJsonError(`${what} at offset ${i}`);
  };
  const ws = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++;
  };

  const string = (): string => {
    // The text between the quotes is handed to JSON.parse, which applies JSON's escapes exactly.
    const start = i++;
    while (i < text.length && text[i] !== '"') {
      if (text[i] === '\\') i++;
      else if (text.charCodeAt(i) < 0x20) fail('unescaped control character in a string');
      i++;
    }
    if (i >= text.length) fail('unterminated string');
    i++;
    return JSON.parse(text.slice(start, i)) as string;
  };

  const value = (depth: number): unknown => {
    if (depth > MAX_DEPTH) fail('nested too deeply to read');
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      const out: Record<string, unknown> = {};
      const seen = new Set<string>();
      ws();
      if (text[i] === '}') {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected an object key');
        const key = string();
        if (seen.has(key)) fail(`duplicate object key ${JSON.stringify(key)}`);
        seen.add(key);
        ws();
        if (text[i++] !== ':') fail("expected ':'");
        // defineProperty, so a key named __proto__ is data, as it is to JSON.parse.
        Object.defineProperty(out, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return out;
        } else fail("expected ',' or '}'");
      }
    }
    if (c === '[') {
      i++;
      const out: unknown[] = [];
      ws();
      if (text[i] === ']') {
        i++;
        return out;
      }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === ']') {
          i++;
          return out;
        } else fail("expected ',' or ']'");
      }
    }
    if (c === '"') return string();
    if (text.startsWith('true', i)) return (i += 4), true;
    if (text.startsWith('false', i)) return (i += 5), false;
    if (text.startsWith('null', i)) return (i += 4), null;
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) return fail('unexpected character');
    i += m[0].length;
    const n = Number(m[0]);
    if (!/[.eE]/.test(m[0]) && !Number.isSafeInteger(n)) {
      fail(`integer ${m[0]} is beyond 2^53 - 1 and cannot round-trip through a JSON number`);
    }
    if (!Number.isFinite(n)) fail(`number ${m[0]} is out of range`);
    return n;
  };

  const out = value(0);
  ws();
  if (i !== text.length) fail('unexpected text after the JSON value');
  return out;
}
