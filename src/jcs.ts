/**
 * RFC 8785 canonicalization (sdcreceipt `canonical`, which re-exports sdcgovernance `jcs`).
 *
 * Deliberately not an implementation. A second implementation of a canonicalization scheme can
 * disagree with the first, and the disagreement is silent: the bytes differ, so the hash differs,
 * and the artifact reads as tampered with rather than misencoded. `canonicalize` is the RFC
 * authors' own, and RFC 8785 defines numbers by ECMAScript `Number::toString`, which is what a
 * JavaScript engine already uses. This module adds only RFC 8785's refusals, which sdcgovernance
 * makes and `canonicalize` does not.
 */
import canonicalizeJcs from 'canonicalize';

export const CANONICALIZATION_ID = 'rfc8785';

export class JCSError extends Error {
  override name = 'JCSError';
}

/**
 * Refuse what has no interoperable canonical form, as sdcgovernance does.
 *
 * sdcgovernance also refuses an integer beyond 2^53 - 1. A JavaScript number is already a double, so
 * that is a property of the source text (an integer literal, not `1e16`), and `strictParse` refuses
 * it there; a bigint, the only exact large integer here, is refused below.
 */
function check(value: unknown, path: string): void {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new JCSError(`${path}: ${value} has no JSON representation`);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => check(v, `${path}[${i}]`));
  } else if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) check(v, `${path}.${k}`);
  } else if (typeof value === 'bigint' || typeof value === 'undefined' || typeof value === 'function' || typeof value === 'symbol') {
    throw new JCSError(`${path}: a ${typeof value} has no JSON representation`);
  }
}

export function canonicalize(value: unknown): string {
  check(value, '$');
  const out = canonicalizeJcs(value);
  if (out === undefined) throw new JCSError('$: no JSON representation');
  return out;
}

export function canonicalizeBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
