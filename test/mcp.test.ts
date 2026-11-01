/**
 * The MCP server and the command: the protocol, malformed requests, each tool on a kit Receipt, and
 * the verify command's key-document roles.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { configure, handle, SERVER_VERSION } from '../src/mcp.js';
import { generateKey, privateKeyPem, strictParse } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));
const json = (f: string) => strictParse(readFileSync(join(KIT, f), 'utf8')) as any;
const DOCS = join(KIT, 'key-documents');
const doc = (f: string) => json(join('key-documents', f));
const VENDOR = 'https://vendor.example/.well-known/vsl-key.json';

const call = async (name: string, args: unknown) => {
  const r = (await handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })) as any;
  return { isError: Boolean(r.result?.isError), text: r.result?.content?.[0]?.text as string, error: r.error };
};

test('initialize negotiates; tools/list offers signing only when configured', async () => {
  configure({});
  const init = (await handle({ id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })) as any;
  assert.equal(init.result.protocolVersion, '2025-06-18');
  assert.equal(init.result.serverInfo.version, SERVER_VERSION);
  const old = (await handle({ id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } })) as any;
  assert.equal(old.result.protocolVersion, '2025-11-25');
  const list = (await handle({ id: 2, method: 'tools/list' })) as any;
  assert.deepEqual(list.result.tools.map((t: { name: string }) => t.name), ['verify_receipt']);
  assert.equal((await call('sign_trigger', { receipt: {} })).error.code, -32601);
});

test('malformed requests are answered, never fatal', async () => {
  for (const bad of [42, 'x', null, [], { id: {}, method: 'ping' }, { id: 1, method: 7 }, { id: 1, method: 'ping', params: [] }]) {
    assert.equal(((await handle(bad)) as any).error.code, -32600);
  }
  const notObject = await call('verify_receipt', 'nope');
  assert.ok(notObject.isError);
});

test('verify_receipt: the kit Receipt verifies with its key documents, and an unchecked trigger is named', async () => {
  configure({});
  const full = JSON.parse((await call('verify_receipt', { receipt: json('valid-settled.json'), issuer_keys: doc('issuer.json'), party_keys: doc('vendor.json') })).text);
  // Only the vendor's document: the partner's trigger has no key, which is a failure, not a skip.
  assert.equal(full.verified, false);
  assert.ok(full.failures.some((f: string) => f.startsWith('trigger[')));
  const noParty = JSON.parse((await call('verify_receipt', { receipt: { receipt: json('valid-settled.json') }, issuer_keys: doc('issuer.json') })).text);
  assert.equal(noParty.trigger_signatures_checked, false);
  assert.deepEqual(noParty.failures, ['settlement.complete']);
  const bad = await call('verify_receipt', { receipt: json('valid-settled.json'), issuer_keys: 'not a document' });
  assert.ok(bad.isError && bad.text.includes('`issuer_keys` must be a JSON object'));
});

test('sign_trigger signs as the configured identity only, and returns the trigger unsubmitted', async () => {
  const { privateKey } = await generateKey();
  configure({ signingKeyPem: await privateKeyPem(privateKey), signingKeyId: VENDOR });
  const receipt = json('valid-settled.json');
  receipt.settlement.triggers = [];
  const signed = JSON.parse((await call('sign_trigger', { receipt })).text);
  assert.equal(signed.submitted, false);
  assert.equal(signed.trigger.key_id, VENDOR);
  const other = await call('sign_trigger', { receipt, key_id: 'https://partner.example/.well-known/vsl-key.json' });
  assert.ok(other.isError && other.text.includes('not selectable per call'));
  configure({});
});

const cli = (...args: string[]) =>
  spawnSync(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), ...args], { encoding: 'utf8', input: '' });

test('the verify command: roles from the command line', () => {
  const ok = cli('verify', join(KIT, 'valid-settled.json'), '--issuer-keys', join(DOCS, 'issuer.json'), '--party-keys', join(DOCS, 'vendor.json'), '--party-keys', join(DOCS, 'partner.json'));
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /\nVERIFIED\n/);
  const both = cli('verify', join(KIT, 'valid-settled.json'), '--issuer-keys', join(DOCS, 'issuer.json'), '--party-keys', join(DOCS, 'issuer.json'));
  assert.equal(both.status, 2);
  assert.match(both.stderr, /both an issuer and a party document/);
  assert.equal(cli('verify', join(KIT, 'valid-settled.json')).status, 2);
});

test('the command answers over stdio', () => {
  const run = spawnSync(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), 'mcp'], {
    input: '{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"id":1,"id":2}\n',
    encoding: 'utf8',
  });
  const lines = run.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines[0], { jsonrpc: '2.0', id: 1, result: {} });
  assert.equal(lines[1].error.code, -32700, 'a duplicate key is refused, not read last-wins');
});
