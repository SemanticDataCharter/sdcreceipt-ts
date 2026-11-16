/**
 * sdcreceipt 4.4.0, ported: `verify` follows `previous_hash` (verifyChain, `--chain`, the MCP
 * `chain` argument) and compares key validity windows with the Receipt's `timestamp`.
 *
 * The kit 1.2 vectors run through the library in conformance.test.ts; here they also run through
 * the command line and the MCP tool, and each rule is pinned on its own.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { handle } from '../src/mcp.js';
import {
  assembleKeys, chainLinkLabel, generateKey, KeyError, KeySet, keyDocument, loadKeySet, parseInstant, strictParse, verify, verifyChain, type Role,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));
const json = (f: string) => strictParse(readFileSync(join(KIT, f), 'utf8')) as any;
const manifest = json('manifest.json');
const KIT_12 = manifest.vectors.filter((v: any) => 'chain' in v || 'key_documents' in v);

const issuerEntry = () => json(join('key-documents', 'issuer.json')).keys[0];
const issuerDoc = (extra: Record<string, unknown>) => ({ keys: [{ ...issuerEntry(), ...extra }] });

// --- parseInstant and the window in a key document ------------------------------------------

test('parseInstant takes the Z form only, refuses dates that do not exist, keeps six fraction digits', () => {
  assert.equal(parseInstant('1970-01-01T00:00:01Z'), 1_000_000);
  assert.equal(parseInstant('1970-01-01T00:00:00.1234567Z'), 123_456);
  assert.equal(parseInstant('0050-01-01T00:00:00Z') < parseInstant('1950-01-01T00:00:00Z'), true);
  for (const bad of ['2026-10-01T00:00:00+00:00', '2026-10-01', '2026-02-30T00:00:00Z', '2026-10-01T24:00:00Z', 42, null]) {
    assert.throws(() => parseInstant(bad), /not an RFC 3339 UTC time ending in Z/);
  }
});

test('a window bound not in the Z form refuses the document; a revoked key\'s window is not read', async () => {
  await assert.rejects(loadKeySet(issuerDoc({ not_after: '2026-10-01T00:00:00+00:00' })), (e: Error) => e instanceof KeyError && /not_after/.test(e.message));
  const revoked = await loadKeySet(issuerDoc({ status: 'revoked', not_after: 'whenever' }));
  assert.equal(revoked.revoked(issuerEntry().key_id), true);
  assert.equal(revoked.window(issuerEntry().key_id), undefined);
  const set = new KeySet().addDocument(await loadKeySet(issuerDoc({ not_before: '2026-01-01T00:00:00Z' })), 'issuer');
  assert.deepEqual(set.window(issuerEntry().key_id), { not_before: '2026-01-01T00:00:00Z', not_after: null });
});

// --- issuer and party windows ----------------------------------------------------------------

async function evidence(issuerExtra: Record<string, unknown>, vendorExtra: Record<string, unknown> = {}) {
  const vendor = json(join('key-documents', 'vendor.json'));
  vendor.keys = vendor.keys.map((k: any) => (k.key_id === 'https://vendor.example/.well-known/vsl-key.json' ? { ...k, ...vendorExtra } : k));
  return assembleKeys([
    { role: 'issuer' as Role, document: issuerDoc(issuerExtra) },
    { role: 'party' as Role, document: vendor },
    { role: 'party' as Role, document: json(join('key-documents', 'partner.json')) },
  ]);
}

test('issuer window: half-open, retired inside passes, revoked fails whatever the window', async () => {
  const receipt = json('valid-settled.json');
  const ts = receipt.timestamp as string;
  const sig = `signature[${issuerEntry().key_id}]`;
  const failed = async (extra: Record<string, unknown>) => new Set((await verify(receipt, await evidence(extra))).failures.map((c) => c.name));
  assert.equal((await failed({ status: 'retired', not_before: '2020-01-01T00:00:00Z', not_after: '2099-01-01T00:00:00Z' })).size, 0);
  assert.equal((await failed({ not_after: ts })).has(sig), true); // not_after == timestamp: the next key's instant
  assert.equal((await failed({ not_before: '2099-01-01T00:00:00Z' })).has(sig), true);
  assert.equal((await failed({ status: 'revoked', not_before: '2020-01-01T00:00:00Z' })).has(sig), true);
});

test('party window: not_after at or before the timestamp fails the trigger; not_before is not judged', async () => {
  const receipt = json('valid-settled.json');
  const trig = 'trigger[https://vendor.example/.well-known/vsl-key.json]';
  const failed = async (extra: Record<string, unknown>) => new Set((await verify(receipt, await evidence({}, extra))).failures.map((c) => c.name));
  assert.equal((await failed({ not_after: receipt.timestamp })).has(trig), true);
  assert.equal((await failed({ not_before: '2099-01-01T00:00:00Z' })).size, 0);
});

// --- the chain -------------------------------------------------------------------------------

const keysJson = json('keys.json');
const flatEvidence = () =>
  assembleKeys([
    { role: 'issuer' as Role, document: { keys: Object.entries(keysJson.issuer_keys).map(([key_id, public_key_pem]) => ({ key_id, public_key_pem })) } },
    { role: 'party' as Role, document: { keys: Object.entries(keysJson.party_keys).map(([key_id, public_key_pem]) => ({ key_id, public_key_pem })) } },
  ]);

test('the chain prefix is the kit\'s', () => {
  assert.equal(chainLinkLabel(1, '3fa9c1d2' + '0'.repeat(56)), 'chain.link[1 3fa9c1d2…]');
});

test('a chain of three verifies to the head; a head is its own chain; byte-identical copies are one document', async () => {
  const tip = json('valid-chain-of-three.json');
  const [head, middle] = [json('chain/head.json'), json('chain/middle.json')];
  const result = await verifyChain(tip, { ...(await flatEvidence()), held: [head, middle, json('chain/middle.json')] });
  assert.equal(result.ok, true, String(result));
  assert.equal(result.checks.at(-1)!.name, 'chain.head');
  const alone = await verifyChain(head, { ...(await flatEvidence()), held: [] });
  assert.equal(alone.ok, true);
  assert.equal(alone.checks.at(-1)!.detail, 'this Receipt is the head');
});

test('the ceiling stops the walk on the bare prefix', async () => {
  const tip = json('valid-chain-of-three.json');
  const head = json('chain/head.json');
  const result = await verifyChain(tip, { ...(await flatEvidence()), held: [head, json('chain/middle.json')], ceiling: 1 });
  assert.deepEqual(result.failures.map((c) => c.name), [chainLinkLabel(2, head.receipt_hash)]);
});

// --- the command line ------------------------------------------------------------------------

const cli = (...args: string[]) =>
  spawnSync(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), ...args], { encoding: 'utf8', input: '' });

function cliArgs(entry: any, dir: string): string[] {
  const args = ['verify', join(KIT, entry.file), '--governance', join(KIT, 'governance-receipt.json'), '--payload', join(KIT, 'payload.xml')];
  if (entry.key_documents) {
    args.push('--issuer-keys', join(KIT, 'key-documents', entry.key_documents.issuer));
    for (const f of entry.key_documents.party ?? []) args.push('--party-keys', join(KIT, 'key-documents', f));
  } else {
    args.push('--issuer-keys', join(KIT, 'key-documents', 'issuer.json'));
    args.push('--party-keys', join(KIT, 'key-documents', 'vendor.json'), '--party-keys', join(KIT, 'key-documents', 'partner.json'));
  }
  if (entry.chain) {
    const held = join(dir, 'held');
    mkdirSync(held);
    for (const f of entry.chain) copyFileSync(join(KIT, f), join(held, basename(f)));
    args.push('--chain', held);
  }
  return args;
}

for (const entry of KIT_12) {
  test(`the command line: ${entry.name} is ${entry.expect}`, () => {
    const r = cli(...cliArgs(entry, mkdtempSync(join(tmpdir(), 'sdcreceipt-ts-'))));
    const failed = new Set(r.stdout.split('\n').filter((l) => l.startsWith('FAIL  ')).map((l) => l.slice(6).split(': ')[0]));
    if (entry.expect === 'valid') assert.equal(r.status, 0, r.stdout + r.stderr);
    else assert.ok(r.status === 1 && failed.has(entry.breaks), r.stdout + r.stderr);
  });
}

test('the command line: --chain naming nothing is a usage error', () => {
  const r = cli('verify', join(KIT, 'valid-chain-of-three.json'), '--issuer-keys', join(KIT, 'key-documents', 'issuer.json'), '--chain', join(tmpdir(), 'no-such-folder-here'));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /neither a directory nor a file/);
});

// --- the MCP tool ----------------------------------------------------------------------------

const call = async (args: unknown) => {
  const r = (await handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'verify_receipt', arguments: args } })) as any;
  return { isError: Boolean(r.result?.isError), text: r.result?.content?.[0]?.text as string };
};
const flatDocs = () => ({
  issuer: { keys: Object.entries(keysJson.issuer_keys).map(([key_id, public_key_pem]) => ({ key_id, public_key_pem })) },
  party: { keys: Object.entries(keysJson.party_keys).map(([key_id, public_key_pem]) => ({ key_id, public_key_pem })) },
});

for (const entry of KIT_12) {
  test(`the MCP tool: ${entry.name} is ${entry.expect}`, async () => {
    const spec = entry.key_documents;
    const docs = flatDocs();
    const args: Record<string, unknown> = {
      receipt: json(entry.file),
      issuer_keys: spec ? json(join('key-documents', spec.issuer)) : docs.issuer,
      party_keys: spec ? (spec.party ?? []).map((f: string) => json(join('key-documents', f))) : docs.party,
      governance_receipt: json('governance-receipt.json'),
    };
    if (entry.chain) args.chain = entry.chain.map((f: string) => json(f));
    const body = JSON.parse((await call(args)).text);
    assert.equal(body.chain_checked, 'chain' in entry);
    if (entry.expect === 'valid') assert.equal(body.verified, true, String(body.failures));
    else assert.ok(body.verified === false && body.failures.includes(entry.breaks), String(body.failures));
  });
}

test('the MCP tool: an empty chain is still a chain; an unrun one is named as unrun', async () => {
  const docs = flatDocs();
  const tip = json('valid-chain-of-three.json');
  const unrun = JSON.parse((await call({ receipt: tip, issuer_keys: docs.issuer, party_keys: docs.party })).text);
  assert.equal(unrun.chain_checked, false);
  const empty = JSON.parse((await call({ receipt: tip, issuer_keys: docs.issuer, party_keys: docs.party, chain: [] })).text);
  assert.equal(empty.chain_checked, true);
  assert.equal(empty.verified, false);
  assert.ok(empty.failures.some((f: string) => f.startsWith('chain.link[1 ')));
});

test('the MCP tool: party documents per party; a key_id two claim, or one in both roles, is refused; a malformed chain is a sentence', async () => {
  const vendor = json(join('key-documents', 'vendor.json'));
  const issuer = json(join('key-documents', 'issuer.json'));
  const receipt = json('valid-settled.json');
  const ok = JSON.parse((await call({ receipt, issuer_keys: issuer, party_keys: [vendor, json(join('key-documents', 'partner.json'))] })).text);
  assert.equal(ok.verified, true, String(ok.failures));
  const twice = await call({ receipt, issuer_keys: issuer, party_keys: [vendor, vendor] });
  assert.ok(twice.isError && /exactly one document/.test(twice.text));
  const both = await call({ receipt, issuer_keys: issuer, party_keys: issuer });
  assert.ok(both.isError && /one role/.test(both.text));
  for (const chain of ['receipts/', [1, 2], { receipt: {} }]) {
    const bad = await call({ receipt, issuer_keys: issuer, chain });
    assert.ok(bad.isError && /`chain` must be an array of Receipt objects/.test(bad.text), bad.text);
  }
});

// --- keyDocument writes the window -----------------------------------------------------------

test('keyDocument states not_before (now, or the Z form given) and an open not_after', async () => {
  const { publicKey } = await generateKey();
  const entry = (await keyDocument(publicKey, 'https://p.example/k.json')).keys[0];
  assert.equal(entry.not_after, null);
  assert.ok(Math.abs(Date.now() * 1000 - parseInstant(entry.not_before)) < 60_000_000);
  assert.equal((await keyDocument(publicKey, 'https://p.example/k.json', { notBefore: '2026-01-01T00:00:00Z' })).keys[0].not_before, '2026-01-01T00:00:00Z');
  await assert.rejects(keyDocument(publicKey, 'https://p.example/k.json', { notBefore: '2026-01-01' }));
  assert.deepEqual((await loadKeySet(await keyDocument(publicKey, 'https://p.example/k.json', { notBefore: '2026-01-01T00:00:00Z' }))).window('https://p.example/k.json'), {
    not_before: '2026-01-01T00:00:00Z',
    not_after: null,
  });
});
