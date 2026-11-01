/**
 * Verify a VSL Settlement Receipt (sdcreceipt `verify`).
 *
 * Implements the published verification procedure. Nothing here contacts a network or requires an
 * account: keys are supplied by the caller, because the procedure permits verifying from a key
 * retained earlier. If this module ever needs to fetch something to do its job, the property it
 * exists to demonstrate has quietly stopped being true.
 *
 * Keys are parameters, and that is a security property rather than a convenience. The caller
 * decides which keys are acceptable before this reads the Receipt, so a Receipt cannot nominate
 * the key used to judge it. Do not add an overload that fetches.
 *
 * Check names are sdcreceipt's, because the conformance kit names the check each invalid vector
 * must break.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import Ajv2020 from 'ajv/dist/2020.js';
import { canonicalizeBytes } from './jcs.js';
import type { KeySet, PublicKey } from './keys.js';

/**
 * Excluded from `receipt_hash`. Signatures sign the hash, so they cannot be inside it, and
 * triggers are appended after hashing so the parties can sign independently and out of order.
 */
export const HASH_EXCLUDED = ['receipt_hash', 'signatures'] as const;

export class Check {
  constructor(
    readonly name: string,
    readonly passed: boolean,
    public detail = '',
  ) {}

  toString(): string {
    return `${this.passed ? 'PASS' : 'FAIL'}  ${this.name}: ${this.detail}`;
  }
}

/**
 * Every check that ran, not just the first failure.
 *
 * Stopping early tells an implementer one thing per run, and hides the case that matters most: a
 * Receipt whose signature verifies but whose governance binding does not.
 */
export class Result {
  readonly checks: Check[] = [];

  record(name: string, passed: boolean, detail = ''): void {
    this.checks.push(new Check(name, passed, detail));
  }

  get ok(): boolean {
    return this.checks.length > 0 && this.checks.every((c) => c.passed);
  }

  get failures(): Check[] {
    return this.checks.filter((c) => !c.passed);
  }

  toString(): string {
    return this.checks.map(String).join('\n');
  }
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const get = (o: unknown, k: string): unknown => (isObject(o) && Object.hasOwn(o, k) ? o[k] : undefined);
/** `dict.get(k, default)`: the default only when the key is absent, never for an explicit null. */
const opt = (o: unknown, k: string, d: unknown): unknown => (isObject(o) && Object.hasOwn(o, k) ? o[k] : d);
const repr = (v: unknown) => (v === undefined ? 'None' : JSON.stringify(v));

/** The exact bytes `receipt_hash` commits to. */
export function canonicalContent(receipt: Json): Uint8Array {
  const content: Json = {};
  for (const [k, v] of Object.entries(receipt)) if (!(HASH_EXCLUDED as readonly string[]).includes(k)) content[k] = v;
  if (Object.hasOwn(content, 'settlement')) {
    const settlement: Json = {};
    for (const [k, v] of Object.entries(receipt.settlement as Json)) if (k !== 'triggers') settlement[k] = v;
    content.settlement = settlement;
  }
  return canonicalizeBytes(content);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** The 32 raw bytes a signature covers: the value `receipt_hash` records in hex. */
export async function receiptDigest(receipt: Json): Promise<Uint8Array> {
  return sha256(canonicalContent(receipt));
}

/**
 * What a party signs to trigger a settlement.
 *
 * `receipt_id` is included deliberately: a signature over `condition_hash` alone is replayable into
 * any other Receipt sharing that release condition, and repeat trading relationships reuse
 * conditions as a matter of course.
 */
export function triggerMessage(receiptId: string, conditionHash: string): Uint8Array {
  return canonicalizeBytes({ condition_hash: conditionHash, receipt_id: receiptId });
}

/**
 * The signature algorithms a Receipt may name, and the raw length each one fixes. ES256 (RFC 7518
 * §3.4) is ECDSA P-256 with the P1363 r||s pair, 64 bytes, 86 base64url characters. ML-DSA-65
 * (Receipt 1.1) is the pure FIPS 204 signature over the same 32 digest bytes as its message, 3309
 * bytes, 4412 characters. Naming the algorithm pins the encoding.
 */
export const SIGNATURE_BYTES = { ES256: 64, 'ML-DSA-65': 3309 } as const;

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function b64urlEncode(raw: Uint8Array): string {
  let out = '';
  for (let i = 0; i < raw.length; i += 3) {
    const n = (raw[i] << 16) | ((raw[i + 1] ?? 0) << 8) | (raw[i + 2] ?? 0);
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63];
    if (i + 1 < raw.length) out += B64URL[(n >> 6) & 63];
    if (i + 2 < raw.length) out += B64URL[n & 63];
  }
  return out;
}

/**
 * Decode a base64url signature strictly, at the length `alg` fixes.
 *
 * A signature is accepted only in the one spelling the specification produces: exactly the
 * characters its algorithm's length needs, from the base64url alphabet, no padding (Lee, F-09). 86
 * characters carry 516 bits for 512, so 16 spellings decode to one ES256 signature; only the one
 * that re-encodes exactly is accepted (Lee, 4.3.x review, F-04).
 */
export function b64urlToRaw(value: unknown, alg: keyof typeof SIGNATURE_BYTES = 'ES256'): Uint8Array {
  const length = SIGNATURE_BYTES[alg];
  const chars = Math.ceil((length * 4) / 3);
  if (typeof value !== 'string' || value.length !== chars || !/^[A-Za-z0-9_-]*$/.test(value)) {
    const hint =
      alg === 'ES256'
        ? 'a 64-byte P1363 signature); a DER signature is variable length and will not fit'
        : 'a 3309-byte ML-DSA-65 signature)';
    throw new Error(`expected ${chars} unpadded base64url characters (${hint}`);
  }
  const raw = new Uint8Array(length);
  let bits = 0;
  let acc = 0;
  let n = 0;
  for (const c of value) {
    acc = (acc << 6) | B64URL.indexOf(c);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n < length) raw[n] = (acc >> bits) & 0xff;
      n++;
    }
  }
  if (n !== length) throw new Error(`expected a ${length}-byte ${alg} signature, got ${n} bytes`);
  if (b64urlEncode(raw) !== value) throw new Error('not the canonical base64url spelling of its bytes');
  return raw;
}

/** "" on success, or the reason an ML-DSA-65 signature failed. Pure ML-DSA signs the message itself. */
function verifyMldsa65(key: PublicKey, message: Uint8Array, signature: unknown): string {
  let raw: Uint8Array;
  try {
    raw = b64urlToRaw(signature, 'ML-DSA-65');
  } catch (e) {
    return `malformed signature: ${(e as Error).message}`;
  }
  if (key.alg !== 'ML-DSA-65' || !key.raw) return 'the stated key is not an ML-DSA-65 key';
  return ml_dsa65.verify(raw, message, key.raw) ? '' : 'does not verify against the stated key';
}

/**
 * "" on success, or the reason an ES256 signature failed.
 *
 * WebCrypto hashes the message itself, so an issuer signature, which sdcreceipt checks as ECDSA over
 * the prehashed digest, is checked here over the canonical content the digest is taken from: the
 * same signature, the same 32 bytes signed.
 */
async function verifyEcdsa(key: PublicKey, message: Uint8Array, signature: unknown): Promise<string> {
  let raw: Uint8Array;
  try {
    raw = b64urlToRaw(signature);
  } catch (e) {
    return `malformed signature: ${(e as Error).message}`;
  }
  // An ES256 signature or a trigger naming an ML-DSA-65 key must be reported, not crash (Lee, F-05).
  if (key.alg !== 'ES256' || !key.cryptoKey) return 'the stated key is not an ECDSA P-256 key';
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.cryptoKey,
    raw as Uint8Array<ArrayBuffer>,
    message as Uint8Array<ArrayBuffer>,
  );
  return ok ? '' : 'does not verify against the stated key';
}

/**
 * The Receipt formats this implementation verifies. A Receipt says "1.0" or "1.1" and that is the
 * wire format. 1.1 is 1.0 signed twice: every listed signature must verify, and these algorithms
 * must all be present.
 */
export const SUPPORTED_RECEIPT_VERSIONS = ['1.0', '1.1'] as const;
export const REQUIRED_ALGS: Record<string, readonly string[]> = { '1.0': ['ES256'], '1.1': ['ES256', 'ML-DSA-65'] };

/**
 * Why a document cannot be verified at all, before any rule is applied.
 *
 * A verifier is the one component whose input is chosen by whoever wants it to fail badly. Every
 * place the procedure indexes into the document is checked here first, so a malformed Receipt is
 * reported as malformed and nothing else runs (Lee, F-03).
 */
function shapeProblems(receipt: unknown): string[] {
  if (!isObject(receipt)) return ['the Receipt is not a JSON object'];
  const problems: string[] = [];
  const str = (o: Json, name: string, label = name) => {
    if (Object.hasOwn(o, name) && typeof o[name] !== 'string') problems.push(`\`${label}\` must be a string`);
  };

  for (const name of ['receipt_id', 'receipt_hash', 'version', 'payload_hash']) str(receipt, name);

  const signatures = opt(receipt, 'signatures', []);
  if (!Array.isArray(signatures)) problems.push('`signatures` must be an array');
  else
    signatures.forEach((s, i) => {
      if (!isObject(s)) problems.push(`\`signatures[${i}]\` must be an object`);
      else for (const name of ['key_id', 'alg', 'sig']) str(s, name, `signatures[${i}].${name}`);
    });

  const settlement = opt(receipt, 'settlement', {});
  if (!isObject(settlement)) problems.push('`settlement` must be an object');
  else {
    const parties = opt(settlement, 'parties', []);
    if (!Array.isArray(parties) || !parties.every((x) => typeof x === 'string')) {
      problems.push('`settlement.parties` must be an array of strings');
    }
    const triggers = opt(settlement, 'triggers', []);
    if (!Array.isArray(triggers)) problems.push('`settlement.triggers` must be an array');
    else
      triggers.forEach((t, i) => {
        if (!isObject(t)) problems.push(`\`settlement.triggers[${i}]\` must be an object`);
        else for (const name of ['key_id', 'signature']) str(t, name, `settlement.triggers[${i}].${name}`);
      });
    str(settlement, 'condition_hash', 'settlement.condition_hash');
  }

  if (!isObject(opt(receipt, 'governance', {}))) problems.push('`governance` must be an object');
  return problems;
}

/** A key map: a KeySet carries published status; a plain Map does not. */
type Keys = Map<string, PublicKey>;
const revoked = (keys: Keys, keyId: string) => typeof (keys as KeySet).revoked === 'function' && (keys as KeySet).revoked(keyId);

export interface VerifyOptions {
  /** `{key_id: public key}`, held or fetched beforehand. A KeySet also carries `status`; a revoked key fails. */
  issuerKeys: Keys;
  /** Keys for triggers. Omit when not held: a settled Receipt then cannot reach VERIFIED. */
  partyKeys?: Keys;
  /** The published JSON Schema, to check shape first. */
  schema?: object;
  /** The governance Receipt, if held. */
  governanceReceipt?: Json;
  /** The payload, if held. A string is hashed as UTF-8. */
  payload?: Uint8Array | string;
}

const validators = new WeakMap<object, ReturnType<Ajv2020['compile']>>();

/** Run the verification procedure over one Receipt. */
export async function verify(receipt: unknown, options: VerifyOptions): Promise<Result> {
  const { issuerKeys, partyKeys, schema, governanceReceipt, payload } = options;
  const result = new Result();

  const problems = shapeProblems(receipt);
  if (problems.length) {
    result.record('shape', false, 'not a Receipt this procedure can read: ' + problems.slice(0, 4).join('; '));
    return result;
  }
  const r = receipt as Json;

  const version = get(r, 'version') as string | undefined;
  if (!SUPPORTED_RECEIPT_VERSIONS.includes(version as never)) {
    // Refused, not assumed. A verifier that applies the wrong rules and says VERIFIED is the
    // schema-check problem again.
    result.record(
      'version',
      false,
      `Receipt version ${repr(version)} is not one this tool implements (${SUPPORTED_RECEIPT_VERSIONS.join(', ')}). ` +
        'Refusing to apply those rules to a document that says it follows others',
    );
    return result;
  }

  if (schema !== undefined) {
    let validate = validators.get(schema);
    if (!validate) {
      // Formats are annotations, as in sdcreceipt (jsonschema asserts none without a format checker).
      validate = new Ajv2020({ strict: false, allErrors: true, validateFormats: false }).compile(schema);
      validators.set(schema, validate);
    }
    const valid = validate(r) as boolean; // the schema has no $async
    const errors = [...(validate.errors ?? [])].sort((a, b) => (a.instancePath < b.instancePath ? -1 : a.instancePath > b.instancePath ? 1 : 0));
    result.record(
      'schema',
      valid,
      valid ? 'conforms' : `${errors.length} violation(s): ${errors[0]?.instancePath || '/'} ${errors[0]?.message ?? ''}`,
    );
    if (!valid) return result;
  }

  let content: Uint8Array;
  try {
    content = canonicalContent(r);
  } catch (e) {
    // RFC 8785 refuses what JSON cannot round-trip. A conformant issuer cannot have hashed it.
    result.record('receipt_hash', false, `cannot canonicalize the Receipt: ${(e as Error).message}`);
    return result;
  }

  const digest = await sha256(content);
  const recomputed = toHex(digest);
  const matches = recomputed === get(r, 'receipt_hash');
  result.record(
    'receipt_hash',
    matches,
    matches
      ? 'matches the canonical content'
      : `recorded ${get(r, 'receipt_hash')} but content hashes to ${recomputed}. If this is your only failure, suspect ` +
          'canonicalization: RFC 8785 renders an integral float as 1, not 1.0',
  );

  const required = REQUIRED_ALGS[version as string];
  const signatures = (opt(r, 'signatures', [])) as Json[];
  for (const signature of signatures) {
    const keyId = (opt(signature, 'key_id', '')) as string;
    const alg = get(signature, 'alg') as string | undefined;
    const label = `signature[${keyId}]`;

    // Every listed signature must verify with the algorithm its `alg` names. One the version does
    // not call for is a failure: a 1.0 Receipt carrying an ML-DSA-65 signature is not what 1.0 means.
    if (!required.includes(alg as string)) {
      result.record(label, false, `alg is ${repr(alg)}; version ${version} allows ${required.join(', ')}`);
      continue;
    }
    const key = issuerKeys.get(keyId);
    if (!key) {
      result.record(
        label,
        false,
        `no key held for ${repr(keyId)}. Resolve it from the published key set, never from a location inside the Receipt`,
      );
      continue;
    }
    if (revoked(issuerKeys, keyId)) {
      // A revoked key is not a missing key: the document that published it says not to trust it.
      result.record(label, false, `key ${repr(keyId)} is marked revoked in the key document`);
      continue;
    }
    const reason =
      alg === 'ML-DSA-65' ? verifyMldsa65(key, digest, opt(signature, 'sig', '')) : await verifyEcdsa(key, content, opt(signature, 'sig', ''));
    result.record(label, !reason, reason || `verifies over receipt_hash (${alg})`);
  }

  if (!signatures.length) {
    result.record('signatures', false, 'the Receipt carries no signature');
  } else {
    // The version says which algorithms must be there. A Receipt that says 1.1 with only its ES256
    // signature is not a 1.1 Receipt, however good that one signature is.
    const present = new Set(signatures.map((s) => get(s, 'alg')));
    const missing = required.filter((a) => !present.has(a));
    result.record(
      'signatures.algorithms',
      !missing.length,
      !missing.length
        ? `carries every signature version ${version} requires (${required.join(', ')})`
        : `version ${version} requires ${required.join(', ')}; missing ${missing.join(', ')}`,
    );
  }

  const settlement = (opt(r, 'settlement', {})) as Json;
  const parties = (opt(settlement, 'parties', [])) as string[];
  const triggers = (opt(settlement, 'triggers', [])) as Json[];
  const triggerIds = triggers.map((t) => get(t, 'key_id'));

  if (partyKeys !== undefined) {
    const message = triggerMessage((opt(r, 'receipt_id', '')) as string, (opt(settlement, 'condition_hash', '')) as string);
    for (const trig of triggers) {
      const keyId = (opt(trig, 'key_id', '')) as string;
      const label = `trigger[${keyId}]`;
      if (!parties.includes(keyId)) {
        result.record(label, false, `${repr(keyId)} is not a listed party`);
        continue;
      }
      const key = partyKeys.get(keyId);
      if (!key) {
        result.record(label, false, `no key held for party ${repr(keyId)}`);
        continue;
      }
      if (revoked(partyKeys, keyId)) {
        result.record(label, false, `key ${repr(keyId)} is marked revoked in the key document`);
        continue;
      }
      const reason = await verifyEcdsa(key, message, opt(trig, 'signature', ''));
      result.record(label, !reason, reason || 'verifies over {condition_hash, receipt_id}');
      if (reason) {
        result.checks[result.checks.length - 1].detail +=
          '. If it is well formed, check whether it belongs to a different Receipt sharing this release condition';
      }
    }
    const duplicated = triggers.length !== new Set(triggerIds).size;
    result.record('triggers.unique', !duplicated, duplicated ? 'a party appears more than once, overstating agreement' : 'one trigger per party');
  }

  if (partyKeys === undefined && triggers.length) {
    // `settlement.complete` is a claim about authorization, not about which strings appear in the
    // document. With no party keys not one trigger signature was checked, so the claim cannot be
    // established; fabricated triggers would otherwise reach VERIFIED on a set comparison alone.
    result.record(
      'settlement.complete',
      false,
      'cannot establish: no party keys were supplied, so no trigger signature was checked. Pass the parties\' published ' +
        'keys, or read this Receipt as unsettled',
    );
  } else {
    const triggered = new Set(triggerIds);
    const awaiting = [...new Set(parties)].filter((p) => !triggered.has(p)).sort();
    const complete = parties.length > 0 && !awaiting.length;
    result.record('settlement.complete', complete, complete ? 'every listed party has triggered' : `awaiting ${JSON.stringify(awaiting)}`);
  }

  if (governanceReceipt !== undefined) {
    const governance = get(r, 'governance');
    const expected = get(governance, 'receipt_hash');
    const actual = get(governanceReceipt, 'receipt_hash');
    result.record(
      'governance.receipt_hash',
      actual === expected,
      actual === expected
        ? 'binds the governance Receipt that produced the verdict'
        : `commits to ${expected} but the held Receipt is ${actual}. The verdict is signed and unsupported`,
    );
    const verdict = get(governance, 'decision');
    const held = get(governanceReceipt, 'decision');
    result.record(
      'governance.decision',
      verdict === held,
      verdict === held ? `matches (${verdict})` : `Receipt says ${repr(verdict)}, governance Receipt says ${repr(held)}`,
    );
  }

  if (payload !== undefined) {
    const expected = get(r, 'payload_hash');
    const actual = toHex(await sha256(typeof payload === 'string' ? new TextEncoder().encode(payload) : payload));
    result.record(
      'payload_hash',
      actual === expected,
      actual === expected ? 'commits to the payload held' : `recorded ${expected} but the payload hashes to ${actual}`,
    );
  }

  return result;
}
