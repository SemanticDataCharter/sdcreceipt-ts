/**
 * Key documents: read a published key document into a KeySet (sdcreceipt `party.load_key_set`).
 *
 * Every key that enters is checked to be ECDSA P-256 or ML-DSA-65, the two types Receipt signatures
 * use. A key on another curve would make a verification "succeed" against a key nobody claimed to
 * sign with, so the type is checked here, once, and `verify` checks that a signature's key is the
 * type its `alg` needs.
 */

export type Alg = 'ES256' | 'ML-DSA-65';

export interface PublicKey {
  alg: Alg;
  /** ES256: a WebCrypto key. */
  cryptoKey?: CryptoKey;
  /** ML-DSA-65: the raw FIPS 204 public key, 1952 bytes. */
  raw?: Uint8Array;
}

export class KeyError extends Error {
  override name = 'KeyError';
}

/**
 * `{key_id: public key}` plus what the key document said about each key.
 *
 * A plain map would lose `status`. A key the document marks `revoked` must not verify anything.
 */
export class KeySet extends Map<string, PublicKey> {
  readonly status = new Map<string, string>();

  revoked(keyId: string): boolean {
    return (this.status.get(keyId) ?? 'active') === 'revoked';
  }

  /**
   * Add one key document's keys, refusing any key_id already held.
   *
   * Merging last-wins would let a document read later replace a key an earlier one published under
   * the same key_id, or clear its `revoked` status, and the verifier would never know (Lee, 4.3.x
   * review, F-02). A key_id is one key, published once.
   */
  addDocument(other: KeySet, source: string): this {
    const clash = [...other.keys()].filter((k) => this.has(k)).sort();
    if (clash.length) {
      throw new KeyError(
        `${source} publishes key_id ${JSON.stringify(clash[0])}, which another key document already supplied. ` +
          'A key_id must come from exactly one document; refusing rather than letting one replace the other.',
      );
    }
    for (const [k, v] of other) this.set(k, v);
    for (const [k, v] of other.status) this.status.set(k, v);
    return this;
  }
}

// DER object identifiers, as encoded in a SubjectPublicKeyInfo.
const OID_EC_PUBLIC_KEY = '2a8648ce3d0201'; // 1.2.840.10045.2.1
const OID_P256 = '2a8648ce3d030107'; // 1.2.840.10045.3.1.7
const OID_ML_DSA_65 = '608648016503040312'; // 2.16.840.1.101.3.4.3.18
const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** One DER element: its tag, its contents, and where the next element starts. */
function element(der: Uint8Array, at: number): { tag: number; body: Uint8Array; end: number } {
  if (at + 2 > der.length) throw new KeyError('truncated DER');
  const tag = der[at];
  let len = der[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3 || start + n > der.length) throw new KeyError('bad DER length');
    len = 0;
    for (let k = 0; k < n; k++) len = (len << 8) | der[start + k];
    start += n;
  }
  if (start + len > der.length) throw new KeyError('truncated DER');
  return { tag, body: der.subarray(start, start + len), end: start + len };
}

function pemToDer(pem: string): Uint8Array {
  const m = /^-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*$/.exec(pem.trim());
  if (!m) throw new KeyError('not a PEM public key (BEGIN PUBLIC KEY)');
  const b = atob(m[1].replace(/\s+/g, ''));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** Load one PEM and insist it is P-256 or ML-DSA-65 (sdcreceipt `party._public_key`). */
export async function publicKeyFromPem(pem: unknown, keyId: string): Promise<PublicKey> {
  if (typeof pem !== 'string') throw new KeyError(`Key ${JSON.stringify(keyId)}: public_key_pem must be a PEM string.`);
  let der: Uint8Array;
  let algorithm: string;
  let parameters: string;
  let bits: Uint8Array;
  try {
    der = pemToDer(pem);
    const spki = element(der, 0);
    if (spki.tag !== 0x30 || spki.end !== der.length) throw new KeyError('not a SubjectPublicKeyInfo');
    const algId = element(spki.body, 0);
    const keyBits = element(spki.body, algId.end);
    if (algId.tag !== 0x30 || keyBits.tag !== 0x03 || keyBits.end !== spki.body.length) {
      throw new KeyError('not a SubjectPublicKeyInfo');
    }
    const oid = element(algId.body, 0);
    if (oid.tag !== 0x06) throw new KeyError('no algorithm identifier');
    algorithm = hex(oid.body);
    parameters = oid.end < algId.body.length ? hex(element(algId.body, oid.end).body) : '';
    if (keyBits.body[0] !== 0) throw new KeyError('public key bit string has unused bits');
    bits = keyBits.body.subarray(1);
  } catch (e) {
    throw new KeyError(`Key ${JSON.stringify(keyId)}: not a readable PEM public key (${(e as Error).message}).`);
  }

  if (algorithm === OID_EC_PUBLIC_KEY && parameters === OID_P256) {
    try {
      const cryptoKey = await crypto.subtle.importKey('spki', der as Uint8Array<ArrayBuffer>, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return { alg: 'ES256', cryptoKey };
    } catch (e) {
      throw new KeyError(`Key ${JSON.stringify(keyId)}: not a readable PEM public key (${(e as Error).message}).`);
    }
  }
  if (algorithm === OID_ML_DSA_65 && bits.length === ML_DSA_65_PUBLIC_KEY_BYTES) {
    return { alg: 'ML-DSA-65', raw: bits.slice() };
  }
  throw new KeyError(
    `Key ${JSON.stringify(keyId)} is not an ECDSA P-256 or an ML-DSA-65 public key. ES256 signatures can only be ` +
      'checked against P-256 and ML-DSA-65 signatures against ML-DSA-65, so this key cannot verify a Receipt and will not be loaded.',
  );
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Turn a published key document into a KeySet.
 *
 * Accepts the issuer key-set shape and a did:web DID document. A key marked `revoked` is kept and
 * recorded as revoked, so a signature made with it fails for that reason rather than as "no key held".
 */
export async function loadKeySet(document: unknown): Promise<KeySet> {
  if (!isObject(document)) {
    throw new KeyError(
      'A key document is a JSON object with a `keys` array (key_id, public_key_pem) or a DID document with verificationMethod.',
    );
  }
  const keys = new KeySet();

  const entries = document.keys ?? [];
  if (!Array.isArray(entries)) throw new KeyError('`keys` must be an array.');
  for (const entry of entries) {
    if (!isObject(entry)) continue;
    const pem = entry.public_key_pem;
    const keyId = entry.key_id;
    if (pem && typeof keyId === 'string') {
      // The same last-wins problem inside one document (F-02).
      if (keys.has(keyId)) throw new KeyError(`Key ${JSON.stringify(keyId)} is listed more than once in one key document.`);
      keys.set(keyId, await publicKeyFromPem(pem, keyId));
      if (typeof entry.status === 'string') keys.status.set(keyId, entry.status);
    }
  }

  const methods = document.verificationMethod ?? [];
  if (!Array.isArray(methods)) throw new KeyError('`verificationMethod` must be an array.');
  for (const method of methods) {
    if (!isObject(method)) continue;
    const pem = method.publicKeyPem;
    const keyId = method.id;
    if (pem && typeof keyId === 'string') keys.set(keyId, await publicKeyFromPem(pem, keyId));
  }

  if (!keys.size) {
    throw new KeyError(
      'No usable keys in that document. Expected a `keys` array with key_id and public_key_pem, or a DID document verificationMethod.',
    );
  }
  return keys;
}

export type Role = 'issuer' | 'party';

/**
 * Assemble the keys a verifier holds from key documents, each given in a role.
 *
 * The roles come from the caller, never from the Receipt. Before sdcreceipt 4.3.3 every document
 * was pooled, so a party that added a key to its own published document could sign as the issuer
 * (Lee, 4.3.x review, F-01). Refused: a key_id two documents claim, a key_id listed twice in one
 * document, and one key in both roles. `partyKeys` is undefined when no party document was given.
 */
export async function assembleKeys(
  documents: { role: Role; document: unknown; source?: string }[],
): Promise<{ issuerKeys: KeySet; partyKeys: KeySet | undefined }> {
  const sets: Record<Role, KeySet> = { issuer: new KeySet(), party: new KeySet() };
  for (const [n, d] of documents.entries()) {
    sets[d.role].addDocument(await loadKeySet(d.document), `${d.role} document ${d.source ?? n + 1}`);
  }
  const both = [...sets.issuer.keys()].filter((k) => sets.party.has(k)).sort();
  if (both.length) {
    throw new KeyError(
      `key_id ${JSON.stringify(both[0])} appears in both an issuer and a party document. One key has one role; refusing to guess which.`,
    );
  }
  return { issuerKeys: sets.issuer, partyKeys: sets.party.size ? sets.party : undefined };
}
