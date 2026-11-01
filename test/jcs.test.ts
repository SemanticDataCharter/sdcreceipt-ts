/**
 * sdcgovernance's RFC 8785 vectors (test-vectors/rfc8785-canonicalization.json): a sibling
 * sdcgovernance checkout, or JCS_VECTORS. Each input is canonicalized and compared as a string.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalize, JCSError, strictParse, StrictJsonError } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const FILE = resolve(process.env.JCS_VECTORS ?? join(here, '..', '..', 'sdcgovernance', 'test-vectors', 'rfc8785-canonicalization.json'));
const vectors = strictParse(readFileSync(FILE, 'utf8')) as { vector_count: number; vectors: { description: string; input: unknown; output: string }[] };

test('every sdcgovernance vector canonicalizes to its published output', () => {
  assert.equal(vectors.vectors.length, vectors.vector_count);
  const problems = vectors.vectors.filter((v) => canonicalize(v.input) !== v.output).map((v) => v.description);
  assert.deepEqual(problems, []);
});

test('what has no interoperable form is refused, not rendered', () => {
  for (const bad of [{ a: NaN }, { a: Infinity }, { a: undefined }, { a: 1n }]) {
    assert.throws(() => canonicalize(bad), JCSError);
  }
  assert.equal(canonicalize({ a: 2 ** 53 - 1 }), '{"a":9007199254740991}');
});

test('an integer beyond 2^53 - 1 is refused where it is written; the float 1e16 is not an integer', () => {
  assert.throws(() => strictParse('{"a":10000000000000001}'), StrictJsonError);
  assert.equal(canonicalize(strictParse('{"a":1e16}')), '{"a":10000000000000000}');
});

test('strict JSON refuses what two parsers could read differently', () => {
  assert.throws(() => strictParse('{"a":1,"a":2}'), StrictJsonError);
  assert.throws(() => strictParse('{"a":9007199254740993}'), StrictJsonError);
  assert.throws(() => strictParse('['.repeat(300) + ']'.repeat(300)), StrictJsonError);
  assert.throws(() => strictParse('{"a":1} x'), StrictJsonError);
  assert.deepEqual(strictParse('{"__proto__":{"x":1},"b":[1.5,"\\u00e9",null,true]}'), JSON.parse('{"__proto__":{"x":1},"b":[1.5,"\\u00e9",null,true]}'));
});
