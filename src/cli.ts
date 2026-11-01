#!/usr/bin/env node
/**
 * The `sdcreceipt-ts` command.
 *
 *   sdcreceipt-ts verify RECEIPT --issuer-keys FILE [--party-keys FILE]... [--schema FILE]
 *                        [--governance FILE] [--payload FILE]
 *   sdcreceipt-ts mcp [--key FILE --key-id URI]
 *
 * With no command, or with `mcp`, the MCP stdio server starts: an MCP registry client runs
 * `npx sdcreceipt-ts mcp`. Key documents are given in a role on the command line, never taken from
 * the Receipt, as sdcreceipt's own command does.
 */
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { strictParse } from './json.js';
import { assembleKeys, KeyError, type Role } from './keys.js';
import { configureFromFiles, runStdio, SERVER_VERSION } from './mcp.js';
import { verify } from './verify.js';

const USAGE = `usage: sdcreceipt-ts [mcp | verify | --version | --help]

  verify RECEIPT --issuer-keys FILE [--party-keys FILE]... [--schema FILE] [--governance FILE] [--payload FILE]
      Run every check of the VSL verification procedure. Exit 0 VERIFIED, 1 NOT VERIFIED, 2 usage.
  mcp [--key FILE --key-id URI]
      The MCP stdio server (JSON-RPC 2.0 on stdin). With a key and an identity, it can sign triggers.
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
  const result = await verify(readJson(positionals[0], 'Receipt'), {
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

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === undefined || command === 'mcp') {
    const { values } = parseArgs({ args: rest, options: { key: { type: 'string' }, 'key-id': { type: 'string' } } });
    await configureFromFiles(values.key, values['key-id']);
    if (command === undefined && process.stdin.isTTY) {
      process.stderr.write('sdcreceipt-ts: MCP server reading JSON-RPC 2.0 on stdin (--help for options, Ctrl-D to stop)\n');
    }
    await runStdio();
    return 0;
  }
  if (command === 'verify') return cmdVerify(rest);
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
