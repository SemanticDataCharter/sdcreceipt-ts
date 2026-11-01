#!/usr/bin/env node
/**
 * The `sdcreceipt-ts` command.
 *
 *   sdcreceipt-ts verify RECEIPT --issuer-keys FILE [--party-keys FILE]... [--schema FILE]
 *                        [--governance FILE] [--payload FILE]
 *   sdcreceipt-ts settle PAYLOAD --target-state S --condition JSON --party URI --party URI
 *                        [--current-state S] [--previous ID] [--endpoint URL] [--out FILE]
 *   sdcreceipt-ts mcp [--key FILE --key-id URI] [--endpoint URL [--token T]]
 *
 * With no command, or with `mcp`, the MCP stdio server starts: an MCP registry client runs
 * `npx sdcreceipt-ts mcp`. Key documents are given in a role on the command line, never taken from
 * the Receipt, as sdcreceipt's own command does.
 */
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { strictParse } from './json.js';
import { assembleKeys, KeyError, type Role } from './keys.js';
import { configureFromOptions, runStdio, SERVER_VERSION } from './mcp.js';
import { DEFAULT_ENDPOINT, payloadCurrentState, settle, SettleError, SettleRejected, splitResponse } from './settle.js';
import { verify } from './verify.js';

const USAGE = `usage: sdcreceipt-ts [mcp | verify | --version | --help]

  verify RECEIPT --issuer-keys FILE [--party-keys FILE]... [--schema FILE] [--governance FILE] [--payload FILE]
      Run every check of the VSL verification procedure. Exit 0 VERIFIED, 1 NOT VERIFIED, 2 usage.
  settle PAYLOAD --target-state S --condition JSON --party URI --party URI [--current-state S] [--previous ID]
         [--endpoint URL] [--out FILE]
      Ask a VSL issuer to issue a Receipt. Needs a token in SDCRECEIPT_TOKEN. Writes the Receipt to --out or stdout.
  mcp [--key FILE --key-id URI] [--endpoint URL [--token T]]
      The MCP stdio server (JSON-RPC 2.0 on stdin). With a key and an identity it can sign triggers; with an
      issuer endpoint and a token (--token or SDCRECEIPT_TOKEN) it can settle.
`;

const readJson = (path: string, what: string) => {
  try {
    return strictParse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new UsageError(`${what} ${path}: ${(e as Error).message}`);
  }
};

class UsageError extends Error {}

async function cmdVerify(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      'issuer-keys': { type: 'string', multiple: true },
      'party-keys': { type: 'string', multiple: true },
      schema: { type: 'string' },
      governance: { type: 'string' },
      payload: { type: 'string' },
    },
  });
  if (positionals.length !== 1) throw new UsageError('verify takes one Receipt file');
  if (!values['issuer-keys']?.length) {
    throw new UsageError(
      "--issuer-keys FILE is required: the issuer's published key document " +
        '(https://sdcstudio.axius-sdc.com/.well-known/sdcstudio-signing-keys.json for SDCStudio). Never take a key from a location inside the Receipt.',
    );
  }
  const documents: { role: Role; document: unknown; source: string }[] = [];
  for (const [role, files] of [['issuer', values['issuer-keys']], ['party', values['party-keys'] ?? []]] as const) {
    for (const f of files) documents.push({ role, document: readJson(f, `${role} key document`), source: f });
  }
  let keys;
  try {
    keys = await assembleKeys(documents);
  } catch (e) {
    if (e instanceof KeyError) throw new UsageError(e.message);
    throw e;
  }
  // The issuer's settle and status answers carry the Receipt under `receipt`; that is what is verified.
  const { receipt, meta } = splitResponse(readJson(positionals[0], 'Receipt') as Record<string, unknown>);
  if (Object.keys(meta).length) process.stderr.write(`read the Receipt out of the issuer's response (${Object.keys(meta).sort().join(', ')})\n`);
  const result = await verify(receipt, {
    ...keys,
    schema: values.schema ? (readJson(values.schema, 'schema') as object) : undefined,
    governanceReceipt: values.governance ? (readJson(values.governance, 'governance Receipt') as Record<string, unknown>) : undefined,
    payload: values.payload ? new Uint8Array(readFileSync(values.payload)) : undefined,
  });
  process.stdout.write(`${result}\n`);
  if (result.ok) {
    process.stdout.write('\nVERIFIED\n');
    return 0;
  }
  process.stdout.write(`\nNOT VERIFIED - ${result.failures.length} check(s) failed\n`);
  return 1;
}

async function cmdSettle(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      'target-state': { type: 'string' },
      'current-state': { type: 'string' },
      condition: { type: 'string' },
      party: { type: 'string', multiple: true },
      previous: { type: 'string' },
      endpoint: { type: 'string' },
      out: { type: 'string' },
    },
  });
  if (positionals.length !== 1) throw new UsageError('settle takes one payload file (the SDC4 XML instance)');
  // Never a flag: a token on the command line lands in shell history and the process list.
  const token = process.env.SDCRECEIPT_TOKEN ?? '';
  if (!token) throw new UsageError('issuing needs a token in SDCRECEIPT_TOKEN. Everything else here does not.');
  if (!values['target-state']) throw new UsageError('--target-state is required');
  let condition: unknown;
  try {
    condition = strictParse(values.condition ?? '');
  } catch (e) {
    throw new UsageError(`--condition must be a JSON object: ${(e as Error).message}`);
  }
  if (typeof condition !== 'object' || condition === null || Array.isArray(condition)) throw new UsageError('--condition must be a JSON object');

  let payload: string;
  try {
    payload = readFileSync(positionals[0], 'utf8');
  } catch (e) {
    throw new UsageError(`no payload at ${positionals[0]}: ${(e as Error).message}`);
  }
  // The payload's own <current-state> is the default, because the issuer treats it as authoritative.
  const declared = payloadCurrentState(payload);
  const currentState = values['current-state'] || declared;
  if (values['current-state'] && declared && values['current-state'] !== declared) {
    process.stderr.write(
      `warning: --current-state ${JSON.stringify(values['current-state'])} differs from the payload's <current-state> ` +
        `${JSON.stringify(declared)}; the issuer treats the payload as authoritative.\n`,
    );
  }
  let answer: Record<string, unknown>;
  try {
    answer = await settle(payload, {
      endpoint: values.endpoint ?? DEFAULT_ENDPOINT,
      token,
      currentState,
      targetState: values['target-state'],
      condition: condition as Record<string, unknown>,
      parties: values.party ?? [],
      previousReceiptId: values.previous,
    });
  } catch (e) {
    if (e instanceof SettleRejected) {
      process.stderr.write(`${e.explain()}\n`);
      return 1;
    }
    if (e instanceof SettleError) throw new UsageError(e.message);
    throw e;
  }
  const { receipt, meta } = splitResponse(answer);
  const decision = (meta.governance as { decision?: string } | undefined)?.decision ?? (receipt.governance as { decision?: string } | undefined)?.decision;
  const text = JSON.stringify(receipt, null, 2) + '\n';
  if (values.out) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(values.out, text);
    process.stderr.write(`Receipt ${String(receipt.receipt_id ?? '')} written to ${values.out}\n`);
  } else process.stdout.write(text);
  if (decision === 'DENY') {
    process.stderr.write('The issuer refused this transition (DENY). The Receipt records the refusal and accepts no triggers.\n');
    return 1;
  }
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === undefined || command === 'mcp') {
    const { values } = parseArgs({
      args: rest,
      options: { key: { type: 'string' }, 'key-id': { type: 'string' }, endpoint: { type: 'string' }, token: { type: 'string' } },
    });
    await configureFromOptions({ key: values.key, keyId: values['key-id'], endpoint: values.endpoint, token: values.token });
    if (command === undefined && process.stdin.isTTY) {
      process.stderr.write('sdcreceipt-ts: MCP server reading JSON-RPC 2.0 on stdin (--help for options, Ctrl-D to stop)\n');
    }
    await runStdio();
    return 0;
  }
  if (command === 'verify') return cmdVerify(rest);
  if (command === 'settle') return cmdSettle(rest);
  if (command === '--version' || command === '-v') {
    process.stdout.write(`${SERVER_VERSION}\n`);
    return 0;
  }
  process.stdout.write(USAGE);
  return command === '--help' || command === '-h' ? 0 : 2;
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (e) {
  process.stderr.write(`error: ${(e as Error).message}\n`);
  process.exitCode = 2;
}
