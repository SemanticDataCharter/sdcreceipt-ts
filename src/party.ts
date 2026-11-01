/**
 * The party side: hold a key, publish it, sign a trigger (sdcreceipt `party`).
 *
 * A settlement identifies each party by a `key_id` that the party controls, an `https://` URL or a
 * `did:web:` identifier. That keeps verification independent of the issuer, and it means the party
 * publishes one JSON file. Keys are ECDSA P-256 (ES256), exchanged as PKCS#8 and SPKI PEM, the
 * same files sdcreceipt reads and writes.
 */
import { triggerMessage } from './verify.js';

export class PartyError extends Error {
  override name = 'PartyError';
}

const P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;

/** A P-256 key pair, which is what ES256 means. Extractable, so it can be saved. */
export async function generateKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(P256, true, ['sign', 'verify']);
}

const b64 = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const pem = (label: string, der: ArrayBuffer) => {
  const body = b64(der).match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
};
const unpem = (label: string, text: string): Uint8Array => {
  const m = new RegExp(`-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]+)-----END ${label}-----`).exec(text);
  if (!m) throw new PartyError(`not a PEM ${label.toLowerCase()} (BEGIN ${label})`);
  return Uint8Array.from(atob(m[1].replace(/\s+/g, '')), (c) => c.charCodeAt(0));
};

/** The private key as unencrypted PKCS#8 PEM. Store it with owner-only permissions, or in a KMS. */
export async function privateKeyPem(key: CryptoKey): Promise<string> {
  return pem('PRIVATE KEY', await crypto.subtle.exportKey('pkcs8', key));
}

export async function publicKeyPem(key: CryptoKey): Promise<string> {
  return pem('PUBLIC KEY', await crypto.subtle.exportKey('spki', key));
}

/** Load a P-256 private key from PKCS#8 PEM; another curve or key type is refused. */
export async function loadPrivateKey(text: string): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('pkcs8', unpem('PRIVATE KEY', text) as Uint8Array<ArrayBuffer>, P256, true, ['sign']);
  } catch (e) {
    if (e instanceof PartyError) throw e;
    throw new PartyError(`not an ECDSA P-256 private key, which is the only curve VSL signatures use (alg ES256): ${(e as Error).message}`);
  }
}

/** The document a party publishes at its `key_id`, shaped like the issuer's key set so one verifier reads both. */
export async function keyDocument(publicKey: CryptoKey, keyId: string) {
  return {
    issuer: keyId,
    keys: [
      { key_id: keyId, algorithm: 'EC_SIGN_P256_SHA256', alg: 'ES256', public_key_pem: await publicKeyPem(publicKey), status: 'active' },
    ],
  };
}

/** Where the key document has to be reachable for `key_id` to resolve. */
export function publicationPath(keyId: string): string {
  if (keyId.startsWith('https://')) return keyId;
  if (keyId.startsWith('did:web:')) {
    const segments = keyId.slice('did:web:'.length).split(':');
    const domain = segments[0].replace('%3A', ':');
    return segments.length === 1 ? `https://${domain}/.well-known/did.json` : `https://${domain}/${segments.slice(1).join('/')}/did.json`;
  }
  throw new PartyError(
    `Unsupported key_id ${JSON.stringify(keyId)}. It must be an https URL or a did:web identifier, so that you control it ` +
      'and verification does not route through the issuer.',
  );
}

const b64url = (bytes: ArrayBuffer) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export interface Trigger {
  receipt_id: string;
  key_id: string;
  signature: string;
  timestamp: string;
}

/**
 * Produce a trigger for a Receipt.
 *
 * Signs `{condition_hash, receipt_id}`. Both are fixed before either party signs, so the parties can
 * sign alone and in any order, while the signature still cannot be replayed into another
 * settlement. WebCrypto's ECDSA signature is already the P1363 r||s pair ES256 requires.
 */
export async function signTrigger(privateKey: CryptoKey, receipt: Record<string, any>, keyId: string): Promise<Trigger> {
  const settlement = receipt?.settlement;
  if (!settlement) throw new PartyError('This Receipt has no settlement block to trigger.');
  const parties: string[] = settlement.parties ?? [];
  if (!parties.includes(keyId)) {
    throw new PartyError(`${keyId} is not a party to this settlement. Listed parties:\n  ${parties.join('\n  ')}`);
  }
  if ((settlement.triggers ?? []).some((t: { key_id?: string }) => t?.key_id === keyId)) {
    throw new PartyError(`${keyId} has already triggered this settlement. A second trigger adds no authorization.`);
  }
  const message = triggerMessage(receipt.receipt_id, settlement.condition_hash);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, message as Uint8Array<ArrayBuffer>);
  return {
    receipt_id: receipt.receipt_id,
    key_id: keyId,
    signature: b64url(signature),
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
}
