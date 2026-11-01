/**
 * Settling, against a stand-in issuer on loopback: the envelope, a refused transition, a DENY,
 * the account errors, a redirect the token must not follow, and the checks made before any round
 * trip. The same through the MCP tool and the command.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkEndpoint, payloadCurrentState, settle, SettleError, SettleRejected, splitResponse, strictParse } from '../src/index.js';
import { configure, handle } from '../src/mcp.js';

const here = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));
const receipt = strictParse(readFileSync(join(KIT, 'valid-settled.json'), 'utf8')) as Record<string, any>;
const PAYLOAD = '<sdc4:dm-x xmlns:sdc4="https://semanticdatacharter.com/ns/sdc4/"><sdc4:current-state> ordered </sdc4:current-state></sdc4:dm-x>';
const PARTIES = ['https://vendor.example/k.json', 'https://buyer.example/k.json'];
const TOKEN = 'test-token-not-a-secret';

const seen: { path: string; auth?: string; body: any }[] = [];
const elsewhere: { auth?: string }[] = [];
let issuer: Server;
let other: Server;
let base = '';
let otherBase = '';

const readBody = (req: IncomingMessage) => new Promise<string>((ok) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => ok(b)); });
const listen = (s: Server) => new Promise<string>((ok) => s.listen(0, '127.0.0.1', () => ok(`http://127.0.0.1:${(s.address() as { port: number }).port}`)));

before(async () => {
  other = createServer((req, res) => {
    elsewhere.push({ auth: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ receipt }));
  });
  otherBase = await listen(other);
  issuer = createServer(async (req, res) => {
    const body = JSON.parse(await readBody(req));
    seen.push({ path: req.url!, auth: req.headers.authorization, body });
    const json = (status: number, value: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    switch (req.url) {
      case '/ok':
        return json(200, { receipt, governance: { decision: 'PERMIT', settleable: true }, wallet: { charged: '0.05' } });
      case '/deny':
        return json(200, { receipt: { ...receipt, governance: { ...receipt.governance, decision: 'DENY' } }, governance: { decision: 'DENY', allowed_transitions: ['shipped'] } });
      case '/reject':
        return json(422, { error: 'No transition from ordered to paid.', current_state: 'ordered', allowed_transitions: [{ target_state: 'shipped' }], workflow: [{ path: 'main', states: ['ordered', 'shipped', 'paid'] }], hint: 'Ship first.' });
      case '/401':
        return json(401, { error: 'bad token' });
      case '/402':
        return json(402, { error: 'balance 0.00' });
      case '/redirect':
        return res.writeHead(307, { location: `${otherBase}/ok` }).end();
      default:
        return res.writeHead(500).end('not json');
    }
  });
  base = await listen(issuer);
});

after(() => {
  issuer.close();
  other.close();
});

const opts = (path: string, extra: object = {}) => ({ endpoint: base + path, token: TOKEN, targetState: 'shipped', condition: { on: 'goods received' }, parties: PARTIES, ...extra });

test('a settled exchange: the request carries the token and the payload\'s state; the envelope splits', async () => {
  const answer = await settle(PAYLOAD, opts('/ok', { previousReceiptId: 'r-0' }));
  const last = seen.at(-1)!;
  assert.equal(last.auth, `Token ${TOKEN}`);
  assert.deepEqual(last.body, { payload: PAYLOAD, current_state: 'ordered', target_state: 'shipped', condition: { on: 'goods received' }, parties: PARTIES, previous_receipt_id: 'r-0' });
  const { receipt: r, meta } = splitResponse(answer);
  assert.equal(r.receipt_id, receipt.receipt_id);
  assert.deepEqual(Object.keys(meta).sort(), ['governance', 'wallet']);
});

test('a refused transition carries the states that would work', async () => {
  const e = await settle(PAYLOAD, opts('/reject')).catch((x) => x);
  assert.ok(e instanceof SettleRejected);
  assert.equal(e.currentState, 'ordered');
  assert.match(e.explain(), /From "ordered" you can go to: shipped/);
  assert.match(e.explain(), /main: ordered -> shipped -> paid/);
});

test('account and server errors are named, not status codes alone', async () => {
  await assert.rejects(settle(PAYLOAD, opts('/401')), /rejected the token/);
  await assert.rejects(settle(PAYLOAD, opts('/402')), /Insufficient balance .*balance 0.00/);
  await assert.rejects(settle(PAYLOAD, opts('/500')), /500 from .*not json/);
});

test('a redirect is refused, and the token goes nowhere else', async () => {
  const before = elsewhere.length;
  await assert.rejects(settle(PAYLOAD, opts('/redirect')), (e: Error) => e instanceof SettleError && /307 .*refusing to follow/.test(e.message));
  assert.equal(elsewhere.length, before, 'the redirect target was never contacted');
});

test('checked before any round trip: two distinct parties, a token, an https endpoint', async () => {
  const count = seen.length;
  await assert.rejects(settle(PAYLOAD, opts('/ok', { parties: [PARTIES[0], PARTIES[0]] })), /two distinct parties; got 1/);
  await assert.rejects(settle(PAYLOAD, opts('/ok', { token: '' })), /needs a token/);
  await assert.rejects(settle(PAYLOAD, opts('', { endpoint: 'http://issuer.example/settle' })), /must be an https:\/\/ URL/);
  assert.equal(seen.length, count);
  assert.equal(checkEndpoint('https://issuer.example/x'), 'https://issuer.example/x');
  assert.equal(checkEndpoint('http://[::1]:8000/x'), 'http://[::1]:8000/x');
  assert.throws(() => checkEndpoint('http://127.0.0.2/x'), SettleError);
  assert.throws(() => checkEndpoint('not a url'), SettleError);
});

test('payloadCurrentState', () => {
  assert.equal(payloadCurrentState(PAYLOAD), 'ordered');
  assert.equal(payloadCurrentState('<current-state>paid</current-state>'), 'paid');
  assert.equal(payloadCurrentState('<x/>'), '');
});

const call = async (name: string, args: unknown) => {
  const r = (await handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })) as any;
  return { isError: Boolean(r.result?.isError), body: r.result ? (r.result.isError ? r.result.content[0].text : JSON.parse(r.result.content[0].text)) : undefined, error: r.error };
};
const settleArgs = { payload: PAYLOAD, target_state: 'shipped', condition: { on: 'goods received' }, parties: PARTIES };

test('MCP settle: offered only with an issuer; posts only to it; a refusal is a result', async () => {
  configure({});
  assert.equal((await call('settle', settleArgs)).error.code, -32601);
  configure({ issuerEndpoint: `${base}/ok`, issuerToken: TOKEN });
  const tools = ((await handle({ id: 1, method: 'tools/list' })) as any).result.tools.map((t: { name: string }) => t.name);
  assert.deepEqual(tools, ['verify_receipt', 'settle']);
  const ok = await call('settle', { ...settleArgs, endpoint: 'https://attacker.example/settle' });
  assert.equal(ok.body.settled, true);
  assert.equal(ok.body.receipt.receipt_id, receipt.receipt_id, 'the bare Receipt, not the envelope');
  assert.equal(ok.body.decision, 'PERMIT');
  assert.equal(seen.at(-1)!.path, '/ok', 'an endpoint in the arguments is ignored');

  configure({ issuerEndpoint: `${base}/reject`, issuerToken: TOKEN });
  const rejected = await call('settle', settleArgs);
  assert.equal(rejected.isError, false);
  assert.equal(rejected.body.rejected, true);
  assert.deepEqual(rejected.body.allowed_transitions, [{ target_state: 'shipped' }]);

  configure({ issuerEndpoint: `${base}/deny`, issuerToken: TOKEN });
  const denied = await call('settle', settleArgs);
  assert.equal(denied.body.decision, 'DENY');
  assert.match(denied.body.hint, /accepts no triggers/);

  configure({ issuerEndpoint: `${base}/401`, issuerToken: TOKEN });
  const unauthorized = await call('settle', settleArgs);
  assert.ok(unauthorized.isError && /rejected the token/.test(unauthorized.body));
  assert.ok((await call('settle', { ...settleArgs, parties: 'x' })).isError);
  configure({});
});

const cli = (args: string[], env: Record<string, string> = {}) =>
  new Promise<{ status: number | null; stdout: string; stderr: string }>((ok) => {
    const child = spawn(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), ...args], { env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('close', (status) => ok({ status, stdout, stderr }));
  });

test('the settle command: writes the Receipt, explains a refusal, needs a token in the environment', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sdcreceipt-ts-'));
  const payloadFile = join(dir, 'payload.xml');
  (await import('node:fs')).writeFileSync(payloadFile, PAYLOAD);
  const args = (path: string) => ['settle', payloadFile, '--endpoint', base + path, '--target-state', 'shipped', '--condition', '{"on":"goods received"}', '--party', PARTIES[0], '--party', PARTIES[1]];

  const ok = await cli([...args('/ok'), '--out', join(dir, 'r.json')], { SDCRECEIPT_TOKEN: TOKEN });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(readFileSync(join(dir, 'r.json'), 'utf8')).receipt_id, receipt.receipt_id);

  const rejected = await cli(args('/reject'), { SDCRECEIPT_TOKEN: TOKEN });
  assert.equal(rejected.status, 1);
  assert.match(rejected.stderr, /you can go to: shipped/);

  const noToken = await cli(args('/ok'), { SDCRECEIPT_TOKEN: '' });
  assert.equal(noToken.status, 2);
  assert.match(noToken.stderr, /SDCRECEIPT_TOKEN/);
});
