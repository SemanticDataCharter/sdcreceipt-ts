/**
 * The governance pieces against sdcgovernance's published vectors (test-vectors/decision-tables.json
 * and governance-receipts.json): a sibling sdcgovernance checkout, or GOVERNANCE_VECTORS (the
 * test-vectors directory). Every expected value is what the Python reference computes.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  decisionTableHash, DecisionTableError, evaluateDecisionTable, EvaluationError, governanceReceiptHash, parseDecisionTable,
  strictParse, TableConflict, TableRegistry, verifyGovernanceReceipt,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const DIR = resolve(process.env.GOVERNANCE_VECTORS ?? join(here, '..', '..', 'sdcgovernance', 'test-vectors'));
const read = (f: string) => strictParse(readFileSync(join(DIR, f), 'utf8')) as any;
const tables = read('decision-tables.json');
const receipts = read('governance-receipts.json');
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));

test('every table hashes as the reference does', () => {
  for (const c of tables.cases) assert.equal(decisionTableHash(c.table), c.table_hash, c.name);
});

test('every evaluation decides as the reference does: decision, matched rules, reasoning, errors', () => {
  const problems: string[] = [];
  for (const c of tables.cases) {
    for (const e of c.evaluations) {
      const r = evaluateDecisionTable(c.table, e.context);
      const got = { decision: r.decision, matched_rules: r.matchedRules, reasoning: r.reasoning, errors: r.errors };
      const want = { decision: e.decision, matched_rules: e.matched_rules, reasoning: e.reasoning, errors: e.errors };
      try {
        assert.deepEqual(got, want);
      } catch {
        problems.push(`${c.name} ${JSON.stringify(e.context)}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
      }
    }
  }
  assert.deepEqual(problems, []);
});

test('spellings hash alike, or differently, as the reference says', () => {
  for (const s of tables.spellings) {
    assert.deepEqual(s.tables.map(decisionTableHash), s.hashes, s.description);
  }
});

test('the tables the reference refuses are refused', () => {
  for (const r of tables.refused) assert.throws(() => parseDecisionTable(r.table), DecisionTableError, r.description);
});

test('where the reference raises, this does not decide', () => {
  for (const r of tables.raises) assert.throws(() => evaluateDecisionTable(r.table, r.context), EvaluationError, r.description);
});

test('the registry orders versions, picks the latest and refuses a conflict as the reference does', () => {
  const v = tables.registry;
  const registry = new TableRegistry();
  const table = tables.cases[0].table;
  for (const version of v.registered_in_order) registry.register('risk', version, table);
  assert.deepEqual(registry.versions('risk'), v.versions);
  assert.equal(registry.get('risk').version, v.latest);
  assert.equal(registry.register('risk', '2', table).version, '2');
  assert.throws(() => registry.register('risk', '2', { ...table, name: 'changed' }), TableConflict);
  for (const token of v.invalid_tokens) assert.throws(() => new TableRegistry().register(token, '1', table), DecisionTableError);
  assert.deepEqual(registry.findByHash(tables.cases[0].table_hash).length, v.versions.length);
  const loaded = new TableRegistry().loadRecords({ table_id: 'risk', version: '1', table, table_hash: tables.cases[0].table_hash });
  assert.equal(loaded[0].tableHash, tables.cases[0].table_hash);
  assert.throws(() => new TableRegistry().loadRecords({ table_id: 'risk', version: '1', table, table_hash: 'ab' }), /changed after it was registered/);
});

test('every governance Receipt verifies, or fails to, as the reference says', () => {
  for (const v of receipts.vectors) {
    const result = verifyGovernanceReceipt(v.receipt);
    assert.equal(result.ok, v.verifies, `${v.description}: ${result.detail}`);
  }
});

test('the kit\'s governance Receipt is untampered', () => {
  const g = strictParse(readFileSync(join(KIT, 'governance-receipt.json'), 'utf8'));
  assert.ok(verifyGovernanceReceipt(g).ok);
});

test('a legacy governance Receipt carrying a number is reported, never verified', () => {
  const legacy = structuredClone(receipts.vectors.find((v: any) => !('canonicalization' in v.receipt)).receipt);
  legacy.obligations = [{ obligation_id: 'x', attributes: { n: 1 } }];
  const r = verifyGovernanceReceipt(legacy);
  assert.equal(r.ok, false);
  assert.match(r.detail, /cannot check: .*legacy rendering of numbers/);
  assert.throws(() => governanceReceiptHash({ ...legacy, canonicalization: 'other' }), /unknown canonicalization/);
});
