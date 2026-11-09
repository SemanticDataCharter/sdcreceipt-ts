/**
 * MCP stdio server for sdcreceipt-ts (sdcreceipt `mcp_server`, Node only: it reads the signing key).
 *
 * A raw JSON-RPC 2.0 stdio server, one JSON object per line, with no MCP SDK dependency, as
 * sdcreceipt's own server is built. Three tools:
 * - verify_receipt: every check, no network, no account; the caller supplies the key documents;
 * - sign_trigger: offered only when the server was started with a key and an identity;
 * - settle: offered only when the server was started with an issuer endpoint and a token.
 *
 * Its rules are sdcreceipt's:
 * - No tool takes a URL as an argument. `settle` reaches the network, and its endpoint is fixed at
 *   start-up exactly like the key, so it can only reach the issuer an operator chose.
 * - The signing key and the identity it signs as are bound at start-up, never passed per call, so
 *   the key stays out of the conversation and a caller cannot choose who this server signs as.
 * - A signed trigger is returned, never submitted. Posting it is for whoever owns submission.
 */
import { readFileSync } from 'node:fs';
import { strictParse } from './json.js';
import { KeyError, loadKeySet } from './keys.js';
import { loadPrivateKey, PartyError, signTrigger } from './party.js';
import { checkEndpoint, settle, SettleError, SettleRejected, splitResponse } from './settle.js';
import { verify } from './verify.js';

export const SERVER_NAME = 'sdcreceipt-ts';
export const SERVER_VERSION = '4.0.1';
/** Newest revision implemented; `initialize` negotiates rather than asserting. */
export const MCP_PROTOCOL_VERSION = '2025-11-25';
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-11-25'];

export interface ServerConfig {
  /** PKCS#8 PEM text of the party key to sign triggers with. */
  signingKeyPem?: string;
  /** The party key_id this server signs as. */
  signingKeyId?: string;
  /** The VSL issuer's settle URL. */
  issuerEndpoint?: string;
  /** The API token for that issuer. */
  issuerToken?: string;
}

let config: ServerConfig = {};

/** Bind the signing identity. Called once, at start-up; never from a tool argument. */
export function configure(c: ServerConfig): void {
  config = { ...c };
}

class ToolError extends Error {}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export const TOOLS = [
  {
    name: 'verify_receipt',
    description:
      'Verify a VSL Settlement Receipt. Runs every check and reports all of them, including the ones that passed, rather than ' +
      'stopping at the first failure. Requires no network and no account: the issuer key document is supplied by the caller. ' +
      'Use this to decide whether a Receipt you were sent is trustworthy before acting on it.',
    inputSchema: {
      type: 'object',
      properties: {
        receipt: { type: 'object', description: 'The Settlement Receipt document to verify.' },
        issuer_keys: {
          type: 'object',
          description: "The issuer's published key document, as JSON. Either the key-set shape with a `keys` array, or a did:web DID document.",
        },
        party_keys: {
          type: 'object',
          description:
            'Optional. Party key document, to verify triggers. Omitting it skips the trigger check, which is honest when the keys are not held; the result says so.',
        },
        governance_receipt: { type: 'object', description: 'Optional. The governance Receipt, if held.' },
      },
      required: ['receipt', 'issuer_keys'],
    },
  },
  {
    name: 'sign_trigger',
    description:
      'Sign a trigger for a settlement, as the single identity this server was started with. Signs {condition_hash, receipt_id}, ' +
      'which is fixed before either party signs, so parties can sign alone and in any order while the signature cannot be replayed ' +
      'into another settlement. The identity is not selectable per call: it is whichever --key-id the operator configured, and it ' +
      'must be one of the Receipt\'s listed parties. Returns the signed trigger WITHOUT submitting it: submission is not exposed here.',
    inputSchema: {
      type: 'object',
      properties: { receipt: { type: 'object', description: 'The Receipt whose settlement is being triggered.' } },
      required: ['receipt'],
      additionalProperties: false,
    },
  },
  {
    name: 'settle',
    description:
      'Ask the configured VSL issuer to validate, govern, attest and sign one exchange, returning a Settlement Receipt. This is ' +
      'the one tool here that needs an account, and it posts only to the endpoint this server was started with. If the ' +
      "transition is refused, the result carries the transitions that would have been accepted and the model's full workflow, " +
      'so a second attempt can be informed rather than guessed.',
    inputSchema: {
      type: 'object',
      properties: {
        payload: { type: 'string', description: 'The SDC4 XML instance to settle, as text.' },
        current_state: { type: 'string', description: "The workflow state the payload is in. Defaults to the payload's own <current-state>." },
        target_state: { type: 'string', description: 'The state being transitioned to.' },
        condition: {
          type: 'object',
          description: 'The release condition. The issuer hashes it and never stores it, so it may hold terms neither party wants published.',
        },
        parties: {
          type: 'array',
          items: { type: 'string' },
          minItems: 2,
          description:
            'At least two key_id URIs, each controlled by its party (https://... or did:web:...). That control is what lets a ' +
            'verifier check a signature without asking the issuer.',
        },
        previous_receipt_id: { type: 'string', description: 'Optional. Chain onto an earlier settlement.' },
      },
      required: ['payload', 'target_state', 'condition', 'parties'],
    },
  },
];

/** A tool argument that must be a JSON object, checked before anything runs (Lee, F-03). */
function requireObject(args: Record<string, unknown>, name: string, optional = false): Record<string, unknown> | undefined {
  const v = args[name];
  if ((v === undefined || v === null) && optional) return undefined;
  if (!isObject(v)) throw new ToolError(`\`${name}\` must be a JSON object.`);
  return v;
}

/** A bare Receipt, or the issuer's envelope around one. */
const receiptOf = (value: Record<string, unknown>) => splitResponse(value).receipt;

async function keys(document: Record<string, unknown>) {
  try {
    return await loadKeySet(document);
  } catch (e) {
    if (e instanceof KeyError) throw new ToolError(e.message);
    throw e;
  }
}

export const HANDLERS: Record<string, (args: Record<string, unknown>) => Promise<unknown>> = {
  async verify_receipt(args) {
    const receipt = receiptOf(requireObject(args, 'receipt')!);
    const issuerKeys = await keys(requireObject(args, 'issuer_keys')!);
    const partyKeys = args.party_keys ? await keys(requireObject(args, 'party_keys')!) : undefined;
    const result = await verify(receipt, { issuerKeys, partyKeys, governanceReceipt: requireObject(args, 'governance_receipt', true) });
    return {
      verified: result.ok,
      checks: result.checks.map((c) => ({ name: c.name, passed: c.passed, detail: c.detail })),
      failures: result.failures.map((c) => c.name),
      // Named so a reader cannot mistake an unrun check for a passed one.
      trigger_signatures_checked: partyKeys !== undefined,
    };
  },

  async sign_trigger(args) {
    if (!config.signingKeyPem || !config.signingKeyId) {
      throw new ToolError('This server was started without a signing key, so it can verify but not sign. Restart it with --key <path> --key-id <uri>.');
    }
    // Refused rather than ignored: the identity is the operator's decision, made once at start-up.
    if (args.key_id !== undefined && args.key_id !== config.signingKeyId) {
      throw new ToolError(
        `This server signs as ${config.signingKeyId} and the identity is not selectable per call, so it will not sign as ${String(args.key_id)}. ` +
          'Start a second server with --key-id if you hold that party\'s key.',
      );
    }
    let key: CryptoKey;
    try {
      key = await loadPrivateKey(config.signingKeyPem);
    } catch {
      // Without the path or the key: an error message is part of the conversation (Lee, F-11).
      throw new ToolError('The signing key this server was started with can no longer be read. The operator should check the server\'s --key.');
    }
    try {
      const trigger = await signTrigger(key, requireObject(args, 'receipt')!, config.signingKeyId);
      return {
        trigger,
        submitted: false,
        next_step: 'Not submitted. This server does not reach the network by design. POST this to the VSL trigger endpoint yourself, or hand it to whatever owns submission.',
      };
    } catch (e) {
      if (e instanceof PartyError) throw new ToolError(e.message);
      throw e;
    }
  },

  async settle(args) {
    if (!config.issuerEndpoint || !config.issuerToken) {
      throw new ToolError('This server was started without an issuer, so it can verify and sign but not settle. Restart it with --endpoint <url> and a token.');
    }
    if (typeof args.payload !== 'string') throw new ToolError('`payload` must be the SDC4 XML instance as a string.');
    if (typeof args.target_state !== 'string') throw new ToolError('`target_state` must be a string.');
    if (args.current_state !== undefined && typeof args.current_state !== 'string') throw new ToolError('`current_state` must be a string.');
    if (!isObject(args.condition)) throw new ToolError('`condition` must be a JSON object.');
    if (!Array.isArray(args.parties) || !args.parties.every((p) => typeof p === 'string')) {
      throw new ToolError('`parties` must be an array of key_id strings.');
    }
    if (args.previous_receipt_id !== undefined && typeof args.previous_receipt_id !== 'string') {
      throw new ToolError('`previous_receipt_id` must be a string.');
    }
    let answer: Record<string, unknown>;
    try {
      answer = await settle(args.payload, {
        endpoint: config.issuerEndpoint,
        token: config.issuerToken,
        currentState: args.current_state as string | undefined,
        targetState: args.target_state,
        condition: args.condition,
        parties: args.parties as string[],
        previousReceiptId: args.previous_receipt_id as string | undefined,
      });
    } catch (e) {
      // A refused transition is the recoverable failure: returned as a result, so the calling model
      // sees the states that would work, not only a sentence.
      if (e instanceof SettleRejected) {
        return {
          settled: false,
          rejected: true,
          error: e.message,
          current_state: e.currentState,
          allowed_transitions: e.allowed,
          workflow: e.workflow,
          model_defines_workflow_states: e.definesStates,
          hint: e.hint,
        };
      }
      if (e instanceof SettleError) throw new ToolError(e.message);
      throw e;
    }
    // The signed Receipt is what verify_receipt and sign_trigger take. A DENY is issued and signed
    // but accepts no triggers, so the decision is surfaced beside it.
    const { receipt, meta } = splitResponse(answer);
    const governance = (isObject(meta.governance) ? meta.governance : {}) as Record<string, unknown>;
    const inReceipt = (isObject(receipt.governance) ? receipt.governance : {}) as Record<string, unknown>;
    const result: Record<string, unknown> = {
      settled: true,
      receipt,
      decision: governance.decision ?? inReceipt.decision ?? null,
      settleable: governance.settleable ?? null,
    };
    if (meta.wallet) result.wallet = meta.wallet;
    if (result.decision === 'DENY') {
      result.hint = governance.hint ?? 'The issuer refused this transition. The Receipt records the refusal and accepts no triggers.';
      result.allowed_transitions = governance.allowed_transitions ?? [];
      result.workflow = governance.workflow ?? [];
    }
    return result;
  },
};

const response = (id: unknown, result: unknown) => ({ jsonrpc: '2.0', id, result });
const failure = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });
const toolResult = (text: string, isError = false) => (isError ? { content: [{ type: 'text', text }], isError: true } : { content: [{ type: 'text', text }] });

/** Answer one JSON-RPC request; null for a notification. A malformed shape gets -32600, never a crash. */
export async function handle(request: unknown): Promise<object | null> {
  if (!isObject(request)) return failure(null, -32600, 'Invalid Request: a JSON-RPC request is an object');
  const { id = null, method = '', params = {} } = request as { id?: unknown; method?: unknown; params?: unknown };
  if (!(typeof id === 'string' || typeof id === 'number' || id === null)) return failure(null, -32600, 'Invalid Request: id must be a string, a number or null');
  if (typeof method !== 'string') return failure(id, -32600, 'Invalid Request: method must be a string');
  const p = params ?? {};
  if (!isObject(p)) return failure(id, -32600, 'Invalid Request: params must be an object');
  const canSign = Boolean(config.signingKeyPem && config.signingKeyId);
  const canSettle = Boolean(config.issuerEndpoint && config.issuerToken);
  const offered = (tool: string) => tool === 'verify_receipt' || (tool === 'sign_trigger' && canSign) || (tool === 'settle' && canSettle);

  switch (method) {
    case 'initialize': {
      const requested = p.protocolVersion;
      return response(id, {
        protocolVersion: SUPPORTED_PROTOCOL_VERSIONS.includes(requested as string) ? requested : MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        instructions:
          'Verify VSL Settlement Receipts and sign settlement triggers, conforming to sdcreceipt. `verify_receipt` needs no network ' +
          'and no account. `sign_trigger` signs with the key this server was started with and returns the trigger unsubmitted. ' +
          '`settle`, when configured, posts only to the issuer this server was started with. No tool takes a URL. ' +
          (canSign ? `Signing is available as ${config.signingKeyId}. ` : 'No signing key was configured, so signing is unavailable. ') +
          (canSettle ? 'Settling is available.' : 'No issuer was configured, so settling is unavailable.'),
      });
    }
    case 'notifications/initialized':
      return null;
    case 'ping':
      return response(id, {});
    case 'tools/list':
      // Advertise only what this server can do.
      return response(id, { tools: TOOLS.filter((t) => offered(t.name)) });
    case 'tools/call': {
      const { name, arguments: a = {} } = p as { name?: unknown; arguments?: unknown };
      const args = a ?? {};
      if (typeof name !== 'string') return failure(id, -32602, 'Invalid params: name must be a string');
      const handler = HANDLERS[name];
      if (!handler || !offered(name)) return failure(id, -32601, `Unknown tool: ${name}`);
      if (!isObject(args)) return response(id, toolResult('Tool execution error: arguments must be a JSON object.', true));
      try {
        return response(id, toolResult(JSON.stringify(await handler(args))));
      } catch (e) {
        // SEP-1303: input and execution failures are tool errors the calling model can read.
        if (e instanceof ToolError) return response(id, toolResult(`Tool execution error: ${e.message}`, true));
        // Anything else is a defect here, reported without internals.
        return response(
          id,
          toolResult(
            `Tool execution error: the server could not process this input (${(e as Error)?.name ?? 'Error'}). ` +
              'This is a defect worth reporting at https://github.com/SemanticDataCharter/sdcreceipt-ts/issues',
            true,
          ),
        );
      }
    }
    default:
      return id === null ? null : failure(id, -32601, `Method not found: ${method}`);
  }
}

/** Run the server on stdio until stdin closes. Requests are read strictly (duplicate keys refused). */
export async function runStdio(): Promise<void> {
  const { createInterface } = await import('node:readline');
  for await (const raw of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
    const line = raw.trim();
    if (!line) continue;
    let request: unknown;
    try {
      request = strictParse(line);
    } catch (e) {
      process.stdout.write(JSON.stringify(failure(null, -32700, `Parse error: ${(e as Error).message}`)) + '\n');
      continue;
    }
    const out = await handle(request);
    if (out) process.stdout.write(JSON.stringify(out) + '\n');
  }
}

/**
 * Check the start-up options and bind them, so an operator sees a bad key or endpoint at launch,
 * not an agent mid-task. The token comes from `--token` or SDCRECEIPT_TOKEN.
 */
export async function configureFromOptions(o: { key?: string; keyId?: string; endpoint?: string; token?: string }): Promise<void> {
  if (o.key && !o.keyId) throw new Error('--key needs --key-id: a signature is only meaningful with the URI it is attributed to.');
  if (o.keyId && !o.key) throw new Error('--key-id without --key cannot sign anything.');
  const c: ServerConfig = {};
  if (o.key) {
    const pem = readFileSync(o.key, 'utf8');
    await loadPrivateKey(pem);
    c.signingKeyPem = pem;
    c.signingKeyId = o.keyId;
  }
  if (o.endpoint) {
    checkEndpoint(o.endpoint);
    const token = o.token || process.env.SDCRECEIPT_TOKEN || '';
    if (!token) throw new Error('--endpoint needs a token: pass --token or set SDCRECEIPT_TOKEN. Issuing is the one thing here that needs an account.');
    c.issuerEndpoint = o.endpoint;
    c.issuerToken = token;
  } else if (o.token) {
    throw new Error('--token without --endpoint has nothing to authenticate to.');
  }
  configure(c);
}
