/**
 * The party side: a trigger signed here verifies, and only for the Receipt it was signed for.
 *
 * Triggers sit outside `receipt_hash`, so a kit Receipt can take a trigger from a key made here:
 * the vendor's party key is replaced with a new one and the vendor's trigger re-signed.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  generateKey, keyDocument, loadKeySet, loadPrivateKey, privateKeyPem, publicationPath, publicKeyFromPem,
  signTrigger, strictParse, verify, PartyError, type PublicKey,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));
const json = (f: string) => strictParse(readFileSync(join(KIT, f), 'utf8')) as any;
const VENDOR = 'https://vendor.example/.well-known/vsl-key.json';

async function kitKeys() {
  const keys = json('keys.json');
  const map = async (pems: Record<string, string>) => {
    const m = new Map<string, PublicKey>();
    for (const [k, v] of Object.entries(pems)) m.set(k, await publicKeyFromPem(v, k));
    return m;
  };
  return { issuerKeys: await map(keys.issuer_keys), partyKeys: await map(keys.party_keys) };
}

test('a trigger signed here verifies, with the key document published for it', async () => {
  const { issuerKeys, partyKeys } = await kitKeys();
  const pair = await generateKey();
  const receipt = json('valid-settled.json');
  receipt.settlement.triggers = receipt.settlement.triggers.filter((t: { key_id: string }) => t.key_id !== VENDOR);
  receipt.settlement.triggers.push(await signTrigger(pair.privateKey, receipt, VENDOR));

  const published = await loadKeySet(await keyDocument(pair.publicKey, VENDOR));
  partyKeys.set(VENDOR, published.get(VENDOR)!);
  const result = await verify(receipt, { issuerKeys, partyKeys });
  assert.ok(result.ok, String(result));
});

test('a trigger signed here does not verify on another Receipt sharing the condition', async () => {
  const { issuerKeys, partyKeys } = await kitKeys();
  const pair = await generateKey();
  const receipt = json('valid-settled.json');
  receipt.settlement.triggers = receipt.settlement.triggers.filter((t: { key_id: string }) => t.key_id !== VENDOR);
  const trigger = await signTrigger(pair.privateKey, { ...receipt, receipt_id: 'another-receipt' }, VENDOR);
  receipt.settlement.triggers.push({ ...trigger, receipt_id: receipt.receipt_id });
  partyKeys.set(VENDOR, (await loadKeySet(await keyDocument(pair.publicKey, VENDOR))).get(VENDOR)!);
  const result = await verify(receipt, { issuerKeys, partyKeys });
  assert.deepEqual(result.failures.map((c) => c.name), [`trigger[${VENDOR}]`]);
});

test('signing refuses a non-party and a second trigger', async () => {
  const { privateKey } = await generateKey();
  const receipt = json('valid-settled.json');
  await assert.rejects(signTrigger(privateKey, receipt, 'https://stranger.example/key.json'), PartyError);
  await assert.rejects(signTrigger(privateKey, receipt, VENDOR), /already triggered/);
});

test('a private key survives PKCS#8 PEM, and another key type is refused', async () => {
  const { privateKey } = await generateKey();
  const again = await loadPrivateKey(await privateKeyPem(privateKey));
  assert.equal((again.algorithm as EcKeyAlgorithm).namedCurve, 'P-256');
  await assert.rejects(loadPrivateKey('not a key'), PartyError);
});

test('publicationPath', () => {
  assert.equal(publicationPath('https://a.example/k.json'), 'https://a.example/k.json');
  assert.equal(publicationPath('did:web:a.example'), 'https://a.example/.well-known/did.json');
  assert.equal(publicationPath('did:web:a.example:users:alice'), 'https://a.example/users/alice/did.json');
  assert.throws(() => publicationPath('http://a.example/k'), PartyError);
});
