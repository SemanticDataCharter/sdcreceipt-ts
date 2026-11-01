/**
 * The parts of sdcgovernance a Settlement Receipt relies on.
 *
 * - Decision tables (sdcgovernance `decision`, `tables`): parse, hash (`table_hash`, the policy a
 *   governance Receipt names), evaluate with the FIRST, UNIQUE and COLLECT hit policies, and keep
 *   versions in a registry.
 * - Governance Receipts (sdcgovernance `receipts`): recompute a governance Receipt's own
 *   `receipt_hash`. A Settlement Receipt's `verify` compares `governance.receipt_hash` with the held
 *   governance Receipt; this checks that the held one is itself untampered.
 *
 * The rules are Python's, because sdcgovernance is the reference and two implementations that
 * decide differently on the same table are worse than either alone. Where JavaScript would read a
 * value differently, this follows Python: booleans are integers (`true == 1`), `in` is a substring
 * test on strings and a key test on objects, strings order by code point, lists compare element by
 * element, and an order across types is false. sdcgovernance publishes vectors for each.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalize } from './jcs.js';

export type Decision = 'PERMIT' | 'DENY' | 'INDETERMINATE' | 'NOT_APPLICABLE';
export type HitPolicy = 'FIRST' | 'UNIQUE' | 'COLLECT';
export type Op = '==' | '!=' | '<' | '<=' | '>' | '>=' | 'in' | 'not_in';

const DECISIONS: readonly Decision[] = ['PERMIT', 'DENY', 'INDETERMINATE', 'NOT_APPLICABLE'];
const POLICIES: readonly HitPolicy[] = ['FIRST', 'UNIQUE', 'COLLECT'];
const OPS: readonly Op[] = ['==', '!=', '<', '<=', '>', '>=', 'in', 'not_in'];

export interface Condition {
  field: string;
  op: Op;
  value: unknown;
}
export interface Rule {
  conditions: Condition[];
  outcome: Decision;
  description: string;
}
export interface DecisionTable {
  name: string;
  hitPolicy: HitPolicy;
  rules: Rule[];
  description: string;
}

export class DecisionTableError extends Error {
  override name = 'DecisionTableError';
}

/** Raised where Python raises TypeError: the reference does not decide, so neither does this. */
export class EvaluationError extends Error {
  override name = 'EvaluationError';
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const has = (o: Json, k: string) => Object.hasOwn(o, k);
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// --- Python's reading of JSON values -----------------------------------------------------------

/** A bool is an int in Python, so both are numbers here. */
const isNumeric = (v: unknown): v is number | boolean => typeof v === 'number' || typeof v === 'boolean';

/** Python `==` on JSON values. */
export function pyEquals(a: unknown, b: unknown): boolean {
  if (isNumeric(a) && isNumeric(b)) return Number(a) === Number(b);
  if (typeof a === 'string' || typeof b === 'string') return a === b;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => pyEquals(x, b[i]));
  if (isObject(a) && isObject(b)) {
    const ka = Object.keys(a);
    return ka.length === Object.keys(b).length && ka.every((k) => has(b, k) && pyEquals(a[k], b[k]));
  }
  return false;
}

class Unordered extends Error {}

/** Strings by code point, as Python compares them, not by UTF-16 code unit. */
function compareCodePoints(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d) return d < 0 ? -1 : 1;
  }
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
}

/** Python's ordering: numbers, strings and lists; anything else is a TypeError (`Unordered`). */
function pyCompare(a: unknown, b: unknown): number {
  if (isNumeric(a) && isNumeric(b)) return Number(a) < Number(b) ? -1 : Number(a) > Number(b) ? 1 : 0;
  if (typeof a === 'string' && typeof b === 'string') return compareCodePoints(a, b);
  if (Array.isArray(a) && Array.isArray(b)) {
    // The first elements that differ decide; otherwise the shorter list is smaller.
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (!pyEquals(a[i], b[i])) return pyCompare(a[i], b[i]);
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
  }
  throw new Unordered();
}

/** Python `left in right`. A right side that is not a container raises, as in Python. */
function pyContains(left: unknown, right: unknown): boolean {
  if (typeof right === 'string') {
    if (typeof left !== 'string') throw new EvaluationError(`'in <string>' requires a string on the left, not ${pyType(left)}`);
    return right.includes(left);
  }
  if (Array.isArray(right)) return right.some((x) => pyEquals(left, x));
  if (isObject(right)) {
    // JSON object keys are strings, so only a string can be one; a list or object is unhashable.
    if (Array.isArray(left) || isObject(left)) throw new EvaluationError(`unhashable type: '${pyType(left)}'`);
    return typeof left === 'string' && has(right, left);
  }
  throw new EvaluationError(`argument of type '${pyType(right)}' is not iterable`);
}

function pyType(v: unknown): string {
  if (v === null || v === undefined) return 'NoneType';
  if (typeof v === 'boolean') return 'bool';
  if (typeof v === 'number') return Number.isInteger(v) ? 'int' : 'float';
  if (typeof v === 'string') return 'str';
  return Array.isArray(v) ? 'list' : 'dict';
}

function compare(op: Op, left: unknown, right: unknown): boolean {
  switch (op) {
    case '==':
      return pyEquals(left, right);
    case '!=':
      return !pyEquals(left, right);
    case 'in':
      return pyContains(left, right);
    case 'not_in':
      return !pyContains(left, right);
    default:
      try {
        const c = pyCompare(left, right);
        return op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : c >= 0;
      } catch (e) {
        if (e instanceof Unordered) return false; // sdcgovernance catches TypeError for these operators
        throw e;
      }
  }
}

/**
 * Python `str()` of a name, field or description. A string is itself; an integer, a bool and null
 * read as Python writes them. A fractional number is refused: whether the JSON said `1.5` or
 * `1.50` cannot be known here, and the hash depends on the text Python would produce.
 */
function pyStr(v: unknown, what: string): string {
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v ? 'True' : 'False';
  if (v === null) return 'None';
  if (typeof v === 'number' && Number.isSafeInteger(v)) return String(v);
  throw new DecisionTableError(`${what} must be a string; ${JSON.stringify(v)} has no single Python str() here`);
}

/** Python truthiness, for `x or ""`. */
const pyFalsy = (v: unknown) =>
  v === undefined || v === null || v === false || v === 0 || v === '' || (Array.isArray(v) && !v.length) || (isObject(v) && !Object.keys(v).length);

const strOrEmpty = (v: unknown, what: string) => (pyFalsy(v) ? '' : pyStr(v, what));

// --- Decision tables ---------------------------------------------------------------------------

/**
 * Build a DecisionTable from its JSON form (sdcgovernance `parse_decision_table`).
 *
 *     {"name", "hit_policy": "FIRST|UNIQUE|COLLECT", "description",
 *      "rules": [{"conditions": [{"field", "op", "value"}], "outcome", "description"}]}
 *
 * Unknown operators, outcomes and hit policies are errors rather than defaults: a policy that
 * silently evaluates differently from how it was written is worse than one that refuses to load.
 */
export function parseDecisionTable(data: unknown): DecisionTable {
  if (!isObject(data)) throw new DecisionTableError('A decision table is a JSON object.');
  const policy = has(data, 'hit_policy') ? data.hit_policy : 'FIRST';
  if (!POLICIES.includes(policy as HitPolicy)) {
    throw new DecisionTableError(`Unknown hit_policy ${JSON.stringify(policy)}; expected one of ${[...POLICIES].sort().join(', ')}.`);
  }
  const rulesData = has(data, 'rules') ? data.rules : [];
  if (!Array.isArray(rulesData)) throw new DecisionTableError('`rules` must be a list.');
  const rules = rulesData.map((ruleData, index): Rule => {
    if (!isObject(ruleData)) throw new DecisionTableError(`Rule ${index} must be an object.`);
    const outcome = ruleData.outcome;
    if (!DECISIONS.includes(outcome as Decision)) {
      throw new DecisionTableError(`Rule ${index}: unknown outcome ${JSON.stringify(outcome)}; expected one of ${[...DECISIONS].sort().join(', ')}.`);
    }
    const raw = pyFalsy(ruleData.conditions) ? [] : ruleData.conditions;
    if (!Array.isArray(raw)) throw new DecisionTableError(`Rule ${index}: a condition needs \`field\`, \`op\` and \`value\`.`);
    const conditions = raw.map((c): Condition => {
      if (!isObject(c) || !has(c, 'field') || !has(c, 'op') || !has(c, 'value')) {
        throw new DecisionTableError(`Rule ${index}: a condition needs \`field\`, \`op\` and \`value\`.`);
      }
      if (!OPS.includes(c.op as Op)) throw new DecisionTableError(`Rule ${index}: unknown op ${JSON.stringify(c.op)}; expected one of ${[...OPS].sort().join(', ')}.`);
      return { field: pyStr(c.field, `Rule ${index}: a condition's field`), op: c.op as Op, value: c.value };
    });
    return { conditions, outcome: outcome as Decision, description: strOrEmpty(ruleData.description, `Rule ${index}: description`) };
  });
  return {
    name: strOrEmpty(data.name, 'name'),
    hitPolicy: policy as HitPolicy,
    rules,
    description: strOrEmpty(data.description, 'description'),
  };
}

/** The table's JSON form: the content `table_hash` names (sdcgovernance `decision_table_to_dict`). */
export function decisionTableToJson(table: DecisionTable) {
  return {
    name: table.name,
    hit_policy: table.hitPolicy,
    description: table.description,
    rules: table.rules.map((r) => ({
      conditions: r.conditions.map((c) => ({ field: c.field, op: c.op, value: c.value })),
      outcome: r.outcome,
      description: r.description,
    })),
  };
}

const asTable = (t: DecisionTable | unknown) =>
  isObject(t) && 'hitPolicy' in t ? (t as unknown as DecisionTable) : parseDecisionTable(t);

/** SHA-256 of the table's RFC 8785 canonical JSON: a governance Receipt's `table_hash`. */
export function decisionTableHash(table: DecisionTable | unknown): string {
  return toHex(sha256(new TextEncoder().encode(canonicalize(decisionTableToJson(asTable(table))))));
}

export interface DecisionResult {
  decision: Decision;
  matchedRules: number[];
  reasoning: string;
  errors: string[];
}

/**
 * Evaluate a decision table against a context (sdcgovernance `evaluate_decision_table`).
 *
 * A condition on a field the context lacks, or holds as null, does not match. FIRST takes the first
 * matching rule; UNIQUE is INDETERMINATE when more than one matches; COLLECT takes the most
 * restrictive outcome (DENY, then INDETERMINATE, then PERMIT). No match is NOT_APPLICABLE.
 *
 * @throws EvaluationError where sdcgovernance raises, as for `in` against a number.
 */
export function evaluateDecisionTable(table: DecisionTable | unknown, context: Json): DecisionResult {
  const t = asTable(table);
  const matched: [number, Rule][] = [];
  t.rules.forEach((rule, i) => {
    const hit = rule.conditions.every((c) => {
      const actual = has(context, c.field) ? context[c.field] : undefined;
      return actual !== undefined && actual !== null && compare(c.op, actual, c.value);
    });
    if (hit) matched.push([i, rule]);
  });

  if (!matched.length) return { decision: 'NOT_APPLICABLE', matchedRules: [], reasoning: `No rules matched in decision table '${t.name}'`, errors: [] };

  const [first, rule] = matched[0];
  if (t.hitPolicy === 'FIRST') {
    return { decision: rule.outcome, matchedRules: [first], reasoning: `First matching rule (#${first})${rule.description ? `: ${rule.description}` : ''}`, errors: [] };
  }
  if (t.hitPolicy === 'UNIQUE') {
    if (matched.length > 1) {
      const indices = matched.map(([i]) => i);
      return {
        decision: 'INDETERMINATE',
        matchedRules: indices,
        reasoning: `UNIQUE hit policy violated: ${matched.length} rules matched`,
        errors: [`UNIQUE hit policy requires exactly 1 match, but ${matched.length} rules matched: [${indices.join(', ')}]`],
      };
    }
    return { decision: rule.outcome, matchedRules: [first], reasoning: `Unique matching rule (#${first})${rule.description ? `: ${rule.description}` : ''}`, errors: [] };
  }
  const outcomes = matched.map(([, r]) => r.outcome);
  const final: Decision = outcomes.includes('DENY') ? 'DENY' : outcomes.includes('INDETERMINATE') ? 'INDETERMINATE' : 'PERMIT';
  const descriptions = matched.filter(([, r]) => r.description).map(([i, r]) => `Rule #${i}: ${r.description}`);
  return {
    decision: final,
    matchedRules: matched.map(([i]) => i),
    reasoning: `COLLECT: ${matched.length} rules matched, most restrictive outcome: ${final}. ${descriptions.join('; ')}`,
    errors: [],
  };
}

// --- The table registry ------------------------------------------------------------------------

/** A table id or version: letters, digits, dot, underscore, hyphen; it becomes a file name. */
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export interface RegisteredTable {
  tableId: string;
  version: string;
  table: DecisionTable;
  tableHash: string;
  domain: string;
  policy: string;
  registeredAt: string;
}

export class TableNotFound extends Error {
  override name = 'TableNotFound';
}
export class TableConflict extends Error {
  override name = 'TableConflict';
}

/** Order `1.10` after `1.9`; any version not wholly numeric sorts after every numeric one, by text. */
function compareVersions(a: string, b: string): number {
  const numeric = (v: string) => v.split('.').every((p) => /^[0-9]+$/.test(p));
  const na = numeric(a);
  const nb = numeric(b);
  if (na !== nb) return na ? -1 : 1;
  if (!na) return compareCodePoints(a, b);
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  return pa.length - pb.length;
}

/**
 * Decision tables by stable id and immutable version (sdcgovernance `TableRegistry`), in memory.
 *
 * `register` is idempotent for identical content and refuses different content under an existing
 * id and version: a version, once registered, means one thing. `get` without a version returns the
 * highest version. `loadRecords` takes the records sdcgovernance saves, one per table version,
 * and refuses one whose table no longer matches its recorded hash.
 */
export class TableRegistry {
  private readonly tables = new Map<string, RegisteredTable>();
  private static key = (id: string, version: string) => JSON.stringify([id, version]);

  register(tableId: string, version: string, table: DecisionTable | unknown, options: { domain?: string; policy?: string } = {}): RegisteredTable {
    for (const [label, value] of [['table_id', tableId], ['version', version]] as const) {
      if (typeof value !== 'string' || !TOKEN.test(value)) {
        throw new DecisionTableError(
          `\`${label}\` must be 1-128 characters of letters, digits, '.', '_' or '-', starting with a letter or digit; got ${JSON.stringify(value)}.`,
        );
      }
    }
    const parsed = asTable(table);
    const tableHash = decisionTableHash(parsed);
    const existing = this.tables.get(TableRegistry.key(tableId, version));
    if (existing) {
      if (existing.tableHash !== tableHash) {
        throw new TableConflict(`${tableId} version ${version} is already registered with hash ${existing.tableHash}; register the changed table under a new version.`);
      }
      return existing;
    }
    const entry: RegisteredTable = {
      tableId,
      version,
      table: parsed,
      tableHash,
      domain: options.domain || '',
      policy: options.policy || '',
      registeredAt: new Date().toISOString(),
    };
    this.tables.set(TableRegistry.key(tableId, version), entry);
    return entry;
  }

  get(tableId: string, version?: string): RegisteredTable {
    if (version !== undefined) {
      const entry = this.tables.get(TableRegistry.key(tableId, version));
      if (!entry) throw new TableNotFound(`No decision table ${JSON.stringify(tableId)} version ${JSON.stringify(version)} is registered.`);
      return entry;
    }
    const versions = this.versions(tableId);
    if (!versions.length) throw new TableNotFound(`No decision table ${JSON.stringify(tableId)} is registered.`);
    return this.get(tableId, versions[versions.length - 1]);
  }

  /** Registered versions of a table, lowest first. */
  versions(tableId: string): string[] {
    return [...this.tables.values()].filter((e) => e.tableId === tableId).map((e) => e.version).sort(compareVersions);
  }

  list(filter: { tableId?: string; domain?: string } = {}): RegisteredTable[] {
    return [...this.tables.values()]
      .filter((e) => (filter.tableId === undefined || e.tableId === filter.tableId) && (filter.domain === undefined || e.domain === filter.domain))
      .sort((a, b) => compareCodePoints(a.tableId, b.tableId) || compareVersions(a.version, b.version));
  }

  /** Every registration whose content has that hash (a governance Receipt's `table_hash`). */
  findByHash(tableHash: string): RegisteredTable[] {
    return this.list().filter((e) => e.tableHash === tableHash);
  }

  get size(): number {
    return this.tables.size;
  }

  /** The records sdcgovernance's `TableRegistry.save` writes: `{table_id, version, table, table_hash?, domain?, policy?}`. */
  loadRecords(records: unknown): RegisteredTable[] {
    const list = Array.isArray(records) ? records : [records];
    return list.map((record) => {
      if (!isObject(record) || !has(record, 'table_id') || !has(record, 'version') || !has(record, 'table')) {
        throw new DecisionTableError('each record needs `table_id`, `version` and `table`.');
      }
      const entry = this.register(record.table_id as string, record.version as string, record.table, {
        domain: (record.domain as string) ?? '',
        policy: (record.policy as string) ?? '',
      });
      if (record.table_hash && record.table_hash !== entry.tableHash) {
        throw new DecisionTableError(
          `table content hashes to ${entry.tableHash} but the record says ${String(record.table_hash)}; the table was changed after it was registered.`,
        );
      }
      return entry;
    });
  }
}

// --- Governance Receipts -----------------------------------------------------------------------

/** The `canonicalization` a governance Receipt hashed before RFC 8785 is read as (none on the wire). */
export const LEGACY_CANONICALIZATION = 'legacy-json-dumps';

export class GovernanceReceiptError extends Error {
  override name = 'GovernanceReceiptError';
}

/** Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`, without numbers. */
function legacyJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    return (
      '"' +
      value.replace(/[\u0000-\u001f"\\]/g, (c) =>
        ({ '"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f' } as Record<string, string>)[c] ??
          '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
      ) +
      '"'
    );
  }
  if (typeof value === 'number') {
    // Python wrote 1.0 where JSON reading here gives 1, so a number cannot be reproduced.
    throw new GovernanceReceiptError(
      'a governance Receipt hashed before RFC 8785 carries a number, and the legacy rendering of numbers (Python json.dumps) cannot be reproduced from parsed JSON',
    );
  }
  if (Array.isArray(value)) return '[' + value.map(legacyJson).join(',') + ']';
  if (isObject(value)) {
    return '{' + Object.keys(value).sort(compareCodePoints).map((k) => `${legacyJson(k)}:${legacyJson(value[k])}`).join(',') + '}';
  }
  throw new GovernanceReceiptError(`a ${typeof value} has no JSON representation`);
}

const OBLIGATION_FIELDS = ['obligation_id', 'description', 'is_obligation', 'attributes'];

/**
 * The content a governance Receipt's `receipt_hash` commits to (sdcgovernance
 * `Receipt._compute_hash`), and how it is rendered.
 *
 * The optional parts are inside the hash only when present (source lineage, obligations, the
 * policy), so Receipts issued before each was added still verify. A Receipt with no
 * `canonicalization` field was hashed with the legacy rendering.
 */
export function governanceReceiptBytes(receipt: unknown): Uint8Array {
  if (!isObject(receipt)) throw new GovernanceReceiptError('A governance Receipt is a JSON object.');
  const r = receipt;
  const field = <T>(k: string, d: T) => (has(r, k) ? r[k] : d);
  if (!DECISIONS.includes(r.decision as Decision)) throw new GovernanceReceiptError(`unknown decision ${JSON.stringify(r.decision)}`);
  if (!has(r, 'timestamp')) throw new GovernanceReceiptError('a governance Receipt needs its `timestamp`');

  const content: Json = {
    decision: r.decision,
    reasoning: field('reasoning', ''),
    status_code: field('status_code', 'urn:oasis:names:tc:xacml:1.0:status:ok'),
    instance_id: field('instance_id', ''),
    instance_version: field('instance_version', ''),
    timestamp: r.timestamp,
    previous_hash: field('previous_hash', null),
    dimensions_checked: field('dimensions_checked', []),
    errors: field('errors', []),
    context_hash: field('context_hash', ''),
  };
  for (const k of ['source_instance_id', 'source_version_id']) if (!pyFalsy(r[k])) content[k] = r[k];
  const obligations = field('obligations', []);
  if (!Array.isArray(obligations)) throw new GovernanceReceiptError('`obligations` must be a list');
  if (obligations.length) {
    content.obligations = obligations.map((o, i) => {
      if (!isObject(o)) throw new GovernanceReceiptError(`obligations[${i}] must be an object`);
      const extra = Object.keys(o).filter((k) => !OBLIGATION_FIELDS.includes(k));
      if (extra.length) throw new GovernanceReceiptError(`obligations[${i}] has unknown field ${JSON.stringify(extra[0])}`);
      return {
        obligation_id: has(o, 'obligation_id') ? o.obligation_id : '',
        description: has(o, 'description') ? o.description : '',
        is_obligation: has(o, 'is_obligation') ? o.is_obligation : true,
        attributes: has(o, 'attributes') ? o.attributes : {},
      };
    });
  }
  for (const k of ['table_hash', 'table_id', 'table_version']) if (!pyFalsy(r[k])) content[k] = r[k];

  if (!has(r, 'canonicalization')) return new TextEncoder().encode(legacyJson(content));
  if (r.canonicalization !== 'rfc8785') throw new GovernanceReceiptError(`unknown canonicalization ${JSON.stringify(r.canonicalization)}`);
  content.canonicalization = r.canonicalization;
  return new TextEncoder().encode(canonicalize(content));
}

/** Recompute a governance Receipt's `receipt_hash` from its content. */
export function governanceReceiptHash(receipt: unknown): string {
  return toHex(sha256(governanceReceiptBytes(receipt)));
}

/**
 * Whether a governance Receipt is untampered: its recorded `receipt_hash` is the hash of its
 * content. A Receipt this cannot read, or a legacy one carrying a number, is reported with the
 * reason, never as verified.
 */
export function verifyGovernanceReceipt(receipt: unknown): { ok: boolean; recorded: unknown; recomputed?: string; detail: string } {
  const recorded = isObject(receipt) ? receipt.receipt_hash : undefined;
  let recomputed: string;
  try {
    recomputed = governanceReceiptHash(receipt);
  } catch (e) {
    return { ok: false, recorded, detail: `cannot check: ${(e as Error).message}` };
  }
  const ok = recomputed === recorded;
  return { ok, recorded, recomputed, detail: ok ? 'matches its content' : `recorded ${String(recorded)} but its content hashes to ${recomputed}` };
}
