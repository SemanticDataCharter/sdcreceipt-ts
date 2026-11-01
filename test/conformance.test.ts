/**
 * The VSL conformance kit, run as sdcreceipt's own `tests/test_conformance.py` runs it.
 *
 * Each invalid vector encodes a real defect, and failing one for the wrong reason does not count:
 * the manifest names the check that must break, and so does this test. The kit is sdcreceipt's
 * (`tests/conformance/`): a sibling sdcreceipt checkout, or SDCRECEIPT_KIT.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { assembleKeys, KeyError, publicKeyFromPem, strictParse, verify, type PublicKey, type Role } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));
const read = (f: string) => readFileSync(join(KIT, f), 'utf8');
const json = (f: string) => strictParse(read(f)) as any;

const manifest = json('manifest.json');
const schemas: Record<string, object> = { '1.0': json('settlement-receipt-1.0.schema.json'), '1.1': json('settlement-receipt-1.1.schema.json') };

async function keyMap(pems: Record<string, string>): Promise<Map<string, PublicKey>> {
  const m = new Map<string, PublicKey>();
  for (const [k, v] of Object.entries(pems)) m.set(k, await publicKeyFromPem(v, k));
  return m;
}

const keys = json('keys.json');
const issuerKeys = await keyMap(keys.issuer_keys);
const partyKeys = await keyMap(keys.party_keys);
const governance = json('governance-receipt.json');
const payload = new Uint8Array(readFileSync(join(KIT, 'payload.xml')));

/** `withhold` names evidence deliberately not supplied (the 4.2.0 trigger defect needed it). */
function run(file: string, withhold: string[] = []) {
  const receipt = json(file);
  const args: Record<string, unknown> = {
    issuerKeys,
    partyKeys,
    schema: schemas[receipt.version],
    governanceReceipt: governance,
    payload,
  };
  const names: Record<string, string> = { party_keys: 'partyKeys', issuer_keys: 'issuerKeys', schema: 'schema', governance_receipt: 'governanceReceipt', payload: 'payload' };
  for (const w of withhold) args[names[w] ?? w] = undefined;
  return verify(receipt, args as any);
}

test('the kit is present', () => {
  assert.equal(manifest.version, '1.1');
  assert.equal(manifest.vectors.length, 17);
  assert.equal(manifest.key_documents.length, 5);
});

test('every vector behaves as the manifest says, failing on the named check', async () => {
  const problems: string[] = [];
  for (const entry of manifest.vectors) {
    const result = await run(entry.file, entry.withhold ?? []);
    const failed = new Set(result.failures.map((c) => c.name));
    if (entry.expect === 'valid') {
      if (failed.size) problems.push(`${entry.name}: expected valid, broke ${[...failed].sort()}`);
    } else if (!failed.has(entry.breaks)) {
      problems.push(`${entry.name}: must break ${entry.breaks}, broke ${[...failed].sort().join(', ') || 'nothing'}`);
    }
  }
  assert.deepEqual(problems, []);
});

for (const kase of manifest.key_documents) {
  test(`key documents: ${kase.name} is ${kase.expect}`, async () => {
    const documents = kase.documents.map((d: { role: Role; file: string }) => ({ role: d.role, document: json(join('key-documents', d.file)), source: d.file }));
    let outcome: string;
    try {
      const assembled = await assembleKeys(documents);
      const result = await verify(json('valid-settled.json'), assembled);
      outcome = result.ok ? 'accepted' : `not verified: ${result.failures.map((c) => c.name)}`;
    } catch (e) {
      outcome = e instanceof KeyError ? 'refused' : `threw ${e}`;
    }
    assert.equal(outcome, kase.expect);
  });
}

test('the party-key vector fails even with the documents a verifier would really hold', async () => {
  const docs = ['issuer.json', 'vendor.json', 'partner.json'].map((f, i) => ({ role: (i ? 'party' : 'issuer') as Role, document: json(join('key-documents', f)) }));
  const result = await verify(json('issuer-signature-by-a-party-key.json'), await assembleKeys(docs));
  const failure = result.failures.find((c) => c.name === 'signature[https://vendor.example/.well-known/vsl-key.json#k2]');
  assert.ok(failure && failure.detail.startsWith("no key held for \"https://vendor.example/.well-known/vsl-key.json#k2\""), String(result));
});

test('every check is reported, not just the first', async () => {
  const result = await run('governance-binding-does-not-match.json');
  const names = result.checks.map((c) => c.name);
  assert.ok(names.includes('governance.receipt_hash'));
  assert.ok(result.checks.some((c) => c.name === 'receipt_hash' && c.passed));
});

test('a missing key is reported, not silently skipped', async () => {
  const result = await verify(json('valid-settled.json'), { issuerKeys: new Map(), schema: schemas['1.0'] });
  assert.ok(!result.ok);
  assert.ok(result.failures.some((c) => c.detail.includes('no key held')));
});

test('the 1.1 vector verifies with both signatures', async () => {
  const result = await run('valid-settled-1.1.json');
  assert.ok(result.ok, String(result));
  const names = result.checks.map((c) => c.name);
  assert.ok(names.includes('signature[sdcstudio-pq-signing-key-v1]'));
  assert.ok(names.includes('signatures.algorithms'));
});

test('a 1.1 Receipt missing its ML-DSA-65 signature fails without the schema', async () => {
  const receipt = json('valid-settled-1.1.json');
  receipt.signatures = receipt.signatures.filter((s: { alg: string }) => s.alg === 'ES256');
  const result = await verify(receipt, { issuerKeys, partyKeys });
  assert.deepEqual(result.failures.map((c) => c.name), ['signatures.algorithms']);
});

test('a 1.0 Receipt carrying an ML-DSA-65 signature is not 1.0', async () => {
  const good = json('valid-settled.json');
  good.signatures.push(json('valid-settled-1.1.json').signatures[1]);
  const result = await verify(good, { issuerKeys, partyKeys });
  assert.ok(result.failures.some((c) => c.name === 'signature[sdcstudio-pq-signing-key-v1]' && c.detail.includes('allows ES256')));
});

test('an ES256 key cannot check an ML-DSA-65 signature', async () => {
  const swapped = new Map(issuerKeys);
  swapped.set('sdcstudio-pq-signing-key-v1', issuerKeys.get('sdcstudio-signing-key-v1')!);
  const result = await verify(json('valid-settled-1.1.json'), { issuerKeys: swapped, partyKeys });
  assert.deepEqual(result.failures.map((c) => c.name), ['signature[sdcstudio-pq-signing-key-v1]']);
  assert.match(result.failures[0].detail, /not an ML-DSA-65 key/);
});

test('verification needs no network', async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    throw new Error('verification attempted a network request');
  }) as typeof fetch;
  try {
    assert.ok((await run('valid-settled.json')).ok);
  } finally {
    globalThis.fetch = realFetch;
  }
});
