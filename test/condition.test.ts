/**
 * The Settlement Condition projection, held to the VSL conformance kit 1.3 condition cases (the
 * kit is sdcreceipt's `tests/conformance/`: a sibling sdcreceipt checkout, or SDCRECEIPT_KIT), as
 * sdcreceipt's own `tests/test_conformance.py` holds `sdcreceipt condition` to them.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalizeBytes, ConditionError, conditionHash, projectCondition, strictParse } from '../src/index.js';
import { handle } from '../src/mcp.js';

const here = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(process.env.SDCRECEIPT_KIT ?? join(here, '..', '..', 'sdcreceipt', 'tests', 'conformance'));
const read = (f: string) => readFileSync(join(KIT, f), 'utf8');
const manifest = strictParse(read('manifest.json')) as any;
const cases: any[] = manifest.conditions ?? [];

test('the kit carries the condition cases (1.3)', () => {
  assert.equal(manifest.version, '1.3');
  assert.equal(cases.length, 10);
});

for (const c of cases) {
  test(`condition case ${c.name} (${c.expect})`, () => {
    const record = new Uint8Array(readFileSync(join(KIT, c.file)));
    if (c.expect === 'refused') {
      assert.throws(() => projectCondition(record, c.cluster), ConditionError);
      return;
    }
    assert.deepEqual(projectCondition(record, c.cluster), strictParse(read(c.projection)));
    assert.equal(conditionHash(record, c.cluster)[0], c.condition_hash);
  });
}

test('the same/differs relations hold', () => {
  const by = Object.fromEntries(cases.map((c) => [c.name, c.condition_hash]));
  for (const c of cases) {
    if (c.same_as) assert.equal(by[c.name], by[c.same_as], c.name);
    if (c.differs_from) assert.notEqual(by[c.name], by[c.differs_from], c.name);
  }
});

const base = read('conditions/settlement-condition-ledger-account.xml');
const CLUSTER = 'eid1kx2nx04u3okbo18vqrks';
const ESCROW = 'j2bn2htdkisk9lluiehmihfv';
const TARGET = 'gel80vtu8pcs59cl7liqfemz';

test('a string and its UTF-8 bytes project alike; the canonical bytes are RFC 8785 of the projection', () => {
  const [a, canon] = conditionHash(base, CLUSTER);
  assert.equal(conditionHash(new TextEncoder().encode(base), CLUSTER)[0], a);
  assert.deepEqual(canon, canonicalizeBytes(projectCondition(base, CLUSTER)));
});

test('character references, CDATA and comments read as ElementTree reads them', () => {
  const swap = (v: string) => base.replace('<xdstring-value>42</xdstring-value>', `<xdstring-value>${v}</xdstring-value>`);
  const value = (xml: string) => (projectCondition(xml, CLUSTER).terms[TARGET] as any)[ESCROW];
  assert.equal(value(swap('&#52;2')), '42');
  assert.equal(value(swap('<![CDATA[4]]>2')), '42');
  assert.equal(value(swap('4<!-- c -->2')), '42');
  assert.equal(value(swap('4<?pi x?>2')), '42');
  assert.equal(value(swap('A &amp; B')), 'A & B');
  assert.equal(value(swap(' 42 ')), ' 42 ', 'values are lexical: no trimming');
});

test('malformed or undeclared-entity records are refused', () => {
  for (const bad of [base.replace('</sdc4:dm-', '</sdc4:dmx-'), base.replace('>42<', '>&nbsp;42<'), base.replace('xmlns:sdc4=', 'xmlns:other=')]) {
    assert.throws(() => projectCondition(bad, CLUSTER), ConditionError);
  }
  assert.throws(() => projectCondition(base.replace("encoding='UTF-8'", "encoding='ISO-8859-1'"), CLUSTER), ConditionError);
  assert.throws(() => projectCondition(new Uint8Array([0x3c, 0xff, 0xfe]), CLUSTER), ConditionError);
});

const cli = (...args: string[]) =>
  spawnSync(process.execPath, ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), ...args], { encoding: 'utf8', input: '' });

test('the condition command prints the hash, writes the projection, and exits 2 on a refusal', () => {
  const c = cases[0];
  const out = join(mkdtempSync(join(tmpdir(), 'cond-')), 'projection.json');
  const ok = cli('condition', join(KIT, c.file), '--cluster', c.cluster, '--out', out);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout.trim(), c.condition_hash);
  assert.deepEqual(strictParse(readFileSync(out, 'utf8')), strictParse(read(c.projection)));
  const refused = cli('condition', join(KIT, c.file), '--cluster', 'z'.repeat(24));
  assert.equal(refused.status, 2);
  assert.equal(refused.stdout, '');
});

test('the MCP tool is offered without configuration and returns the same hash', async () => {
  const list = (await handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' })) as any;
  assert.ok(list.result.tools.some((t: any) => t.name === 'condition_hash'));
  const c = cases[0];
  const call = async (args: object) => ((await handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'condition_hash', arguments: args } })) as any).result;
  const r = await call({ record: read(c.file), cluster: c.cluster });
  assert.equal(JSON.parse(r.content[0].text).condition_hash, c.condition_hash);
  assert.equal((await call({ record: read(c.file), cluster: 'z'.repeat(24) })).isError, true);
  assert.equal((await call({ record: 1, cluster: c.cluster })).isError, true);
});
