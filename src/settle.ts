/**
 * Issuing a Receipt: the one thing here that needs an account (sdcreceipt `issue`).
 *
 * Every other function in this package works with nothing from the issuer; `verify` needs no
 * network at all. This one posts to a VSL issuer, which means an endpoint, a token and a balance.
 * It carries an API token, so it belongs on a server or in an agent's process, not in a web page.
 *
 * The rejection path matters as much as the happy one. A VSL issuer answers a bad transition with
 * the states that would have worked, and SettleRejected carries that through instead of flattening
 * it to a status code.
 */

export const DEFAULT_ENDPOINT = 'https://sdcstudio.axius-sdc.com/api/v1/vsl/settle';

export class SettleError extends Error {
  override name = 'SettleError';
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** The issuer refused the transition, and said what it would have accepted. */
export class SettleRejected extends SettleError {
  override name = 'SettleRejected';
  readonly currentState: string;
  readonly allowed: unknown[];
  readonly workflow: { path?: string; states?: string[] }[];
  readonly hint: string;
  /** False when the model constrains no states, so the refusal came from another governance dimension. */
  readonly definesStates: boolean;

  constructor(readonly body: Json) {
    super(typeof body.error === 'string' ? body.error : 'The issuer rejected the transition.');
    this.currentState = typeof body.current_state === 'string' ? body.current_state : '';
    this.allowed = Array.isArray(body.allowed_transitions) ? body.allowed_transitions : [];
    this.workflow = Array.isArray(body.workflow) ? body.workflow : [];
    this.hint = typeof body.hint === 'string' ? body.hint : '';
    this.definesStates = body.model_defines_workflow_states !== false;
  }

  /** The rejection as a person should read it. */
  explain(): string {
    const lines = [this.message];
    if (this.hint) lines.push('', this.hint);
    if (this.allowed.length) {
      const targets = this.allowed.map((t) => (isObject(t) && typeof t.target_state === 'string' ? t.target_state : String(t))).join(', ');
      lines.push('', `From ${JSON.stringify(this.currentState)} you can go to: ${targets}`);
    }
    if (this.workflow.length) {
      lines.push('', "This model's workflow:");
      for (const path of this.workflow) lines.push(`  ${path.path ?? '(unnamed)'}: ${(path.states ?? []).join(' -> ')}`);
    }
    return lines.join('\n');
  }
}

/**
 * Separate the Receipt from the rest of an issuer's response.
 *
 * The issuer answers settle with an envelope (the signed Receipt under `receipt`, beside
 * `governance`, `verification` and `wallet`) and its status endpoint with another. Only the Receipt
 * is the artifact a party verifies, triggers and passes on. A bare Receipt passes through.
 */
export function splitResponse(response: Json): { receipt: Json; meta: Json } {
  if (isObject(response.receipt)) {
    const { receipt, ...meta } = response;
    return { receipt: receipt as Json, meta };
  }
  return { receipt: response, meta: {} };
}

/**
 * The value of the payload's `<current-state>` element, or "" if it has none. The issuer treats it
 * as authoritative, so it is the right default for `currentState`. Read with a pattern, not a
 * parser: a convenience default should not add a parser's attack surface.
 */
export function payloadCurrentState(payload: string): string {
  const m = /<(?:[A-Za-z_][\w.-]*:)?current-state\s*>\s*([^<]*?)\s*<\/(?:[A-Za-z_][\w.-]*:)?current-state\s*>/.exec(payload);
  return m ? m[1] : '';
}

/**
 * Refuse to send a token, or a signature, anywhere but over HTTPS. `http://` would put the token
 * on the wire in clear (Lee, F-07); loopback is the one exception, for a local issuer.
 */
export function checkEndpoint(url: string, what = 'endpoint'): string {
  let parts: URL | undefined;
  try {
    parts = new URL(url);
  } catch {
    parts = undefined;
  }
  const host = parts?.hostname.toLowerCase().replace(/^\[|\]$/g, '') ?? '';
  if (parts?.protocol === 'https:' && host) return url;
  if (parts?.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(host)) return url;
  throw new SettleError(
    `Refusing ${what} ${JSON.stringify(url)}: it must be an https:// URL (or http:// on localhost for a local issuer). ` +
      'Anything sent to it carries a token or a signature, and a plaintext hop discloses it.',
  );
}

/**
 * POST without following a redirect. checkEndpoint vets the URL a person gave; a followed redirect
 * would carry the Authorization header to a host nobody checked (Lee, 4.3.3 review, F-14). An
 * issuer has no reason to redirect a POST, so a redirect is an error that names where it pointed.
 */
export async function postWithoutRedirects(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    throw new SettleError(`Could not reach ${url}: ${(e as Error).message}`);
  }
  // A browser hides a manual redirect as an opaque response with status 0.
  if (response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400)) {
    const location = response.headers.get('location') ?? '(not disclosed)';
    throw new SettleError(
      `${url} answered ${response.status || 'a redirect'} to ${JSON.stringify(location)}; refusing to follow it, because the request ` +
        'carries a token or a signature and the new host was never checked. If that is the right address, use it directly.',
    );
  }
  return response;
}

export interface SettleOptions {
  /** The issuer's settle URL. */
  endpoint?: string;
  /** An API token for that issuer. */
  token: string;
  /** The workflow state the payload is in. Defaults to the payload's own `<current-state>`. */
  currentState?: string;
  /** The state being transitioned to. */
  targetState: string;
  /** The release condition. Hashed by the issuer and never stored, so it may hold private terms. */
  condition: Json;
  /** At least two key_id URIs, each controlled by its party. */
  parties: string[];
  /** Chain this settlement onto an earlier one. */
  previousReceiptId?: string;
  timeoutMs?: number;
}

/**
 * Ask a VSL issuer to validate, govern, attest and sign one exchange. Returns the issuer's
 * response; `splitResponse` takes the Receipt out of it.
 *
 * @throws SettleRejected The transition was refused, with what would work.
 * @throws SettleError Anything else, including transport failures.
 */
export async function settle(payload: string, options: SettleOptions): Promise<Json> {
  const { token, targetState, condition, parties, previousReceiptId = '', timeoutMs = 60_000 } = options;
  const distinct = new Set(parties).size;
  if (distinct < 2) {
    // Caught before a round trip: a settlement with one party is a signature.
    throw new SettleError(
      `A settlement needs at least two distinct parties; got ${distinct}. Each is a key_id URI that party controls, which is ` +
        'what lets a verifier check their signature without asking the issuer.',
    );
  }
  if (!token) throw new SettleError('Issuing needs a token. Everything else here does not.');
  if (!isObject(condition)) throw new SettleError('The condition must be a JSON object.');
  const endpoint = checkEndpoint(options.endpoint ?? DEFAULT_ENDPOINT);

  const body: Json = {
    payload,
    current_state: options.currentState || payloadCurrentState(payload),
    target_state: targetState,
    condition,
    parties,
  };
  if (previousReceiptId) body.previous_receipt_id = previousReceiptId;

  const response = await postWithoutRedirects(
    endpoint,
    { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Token ${token}` }, body: JSON.stringify(body) },
    timeoutMs,
  );
  const raw = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SettleError(`${response.status} from ${endpoint}: ${raw.slice(0, 400)}`);
  }
  if (response.ok) {
    if (!isObject(parsed)) throw new SettleError(`${endpoint} answered with something other than a JSON object.`);
    return parsed;
  }
  const error = isObject(parsed) && typeof parsed.error === 'string' ? parsed.error : raw.slice(0, 400);
  if (response.status === 422 && isObject(parsed) && 'allowed_transitions' in parsed) throw new SettleRejected(parsed);
  if (response.status === 401) {
    throw new SettleError(`${endpoint} rejected the token. Issuing is the one function here that needs an account; everything else works without one.`);
  }
  if (response.status === 402) throw new SettleError(`Insufficient balance at ${endpoint}: ${error.slice(0, 200)}`);
  throw new SettleError(`${response.status} from ${endpoint}: ${error}`);
}
