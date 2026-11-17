/**
 * The Settlement Condition projection (sdcreceipt `condition`): from a governed record to the JSON
 * whose hash is `condition_hash`.
 *
 * A VSL Receipt commits to its release condition by hash, and every party's trigger signs that hash.
 * When the condition is a Settlement Condition record (the Business Documents library), each party,
 * the issuer and the holder must derive the *same* JSON from the record, or the hashes differ and the
 * holder refuses a valid settlement. This is a port of sdcreceipt 4.5.0 `condition.py`, held to the
 * VSL conformance kit 1.3 condition cases; the rules are the kit README's.
 *
 * The projection, `sdc-settlement-condition/1`:
 *
 * 1. The input is a Governed Data Record as XML, root `sdc4:dm-<model>`. A DOCTYPE or entity
 *    declaration is refused.
 * 2. The projected element is `sdc4:ms-<condition>`, anywhere in the record; exactly one.
 * 3. A cluster projects to an object keyed by ct_id (the part after `ms-`). An adapter (no child
 *    outside the SDC4 namespace, exactly one member) stands for its leaf; a member holding members is
 *    a cluster; a member holding none is a leaf, and a leaf with neither a value nor an Exceptional
 *    Value is refused.
 * 4. A leaf's value is the text of its value element exactly as written. A quantity is
 *    `{value, units}`. An Exceptional Value in place of the value is `{ev}`; beside it, `{ev, value}`.
 * 5. `{projection, model, condition, terms}`, RFC 8785, SHA-256, lowercase hex.
 *
 * It does not validate the record: validate against the published model first.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { SaxesParser } from 'saxes';
import { canonicalizeBytes } from './jcs.js';

export const PROJECTION = 'sdc-settlement-condition/1';
export const SDC4 = 'https://semanticdatacharter.com/ns/sdc4/';
const VALUE = ['xdstring-value', 'xdtoken-value', 'xdcount-value', 'xdquantity-value', 'xdfloat-value', 'xddouble-value', 'xdboolean-true', 'xdboolean-false'];
const CT = /^[a-z0-9]{20,32}$/;

export class ConditionError extends Error {
  override name = 'ConditionError';
}

export type Terms = { [ctId: string]: TermValue };
export type TermValue = string | Terms | { value: string; units: string } | { ev: string; value?: string | { value: string; units: string } };
export interface Projection {
  projection: typeof PROJECTION;
  model: string;
  condition: string;
  terms: Terms;
}

/** An element as ElementTree sees it: `text` is the character data before the first child element. */
interface El {
  ns: string;
  local: string;
  children: El[];
  text: string;
}

const sdc = (el: El) => el.ns === SDC4;
const isMember = (el: El) => sdc(el) && el.local.startsWith('ms-');
/** ElementTree's `find(name)`: the first child with that tag and no namespace. */
const find = (el: El, local: string) => el.children.find((c) => c.ns === '' && c.local === local);

function memberId(el: El): string {
  if (!el.local.startsWith('ms-') || !CT.test(el.local.slice(3))) throw new ConditionError(`not a member element: ${el.local}`);
  return el.local.slice(3);
}

function ev(el: El): El | undefined {
  return el.children.find((c) => sdc(c) && !isMember(c) && find(c, 'ev-name') !== undefined);
}

function value(el: El): string | { value: string; units: string } | undefined {
  const plain = new Map<string, El>();
  for (const c of el.children) if (!sdc(c)) plain.set(c.local, c); // last wins, as a Python dict does
  const q = plain.get('xdquantity-value');
  if (q) {
    const units = plain.get('xdquantity-units');
    const u = units ? find(units, 'xdstring-value') : undefined;
    return { value: q.text, units: u ? u.text : '' };
  }
  for (const name of VALUE) {
    const v = plain.get(name);
    if (v) return v.text;
  }
  const temporal = [...plain.keys()].filter((n) => n.startsWith('xdtemporal-'));
  return temporal.length === 1 ? plain.get(temporal[0])!.text : undefined;
}

/** Both an Exceptional Value and the value beside it are hashed, so the value is never dropped. */
function leafValue(el: El): TermValue | undefined {
  const e = ev(el);
  const v = value(el);
  if (!e) return v;
  const out: { ev: string; value?: string | { value: string; units: string } } = { ev: find(e, 'ev-name')!.text };
  if (v !== undefined) out.value = v;
  return out;
}

function projectCluster(cluster: El): Terms {
  const out: Terms = {};
  for (let child of cluster.children) {
    if (!isMember(child)) continue;
    let members = child.children.filter(isMember);
    const plain = child.children.filter((c) => !sdc(c));
    if (plain.length === 0 && members.length === 1) {
      // an adapter: it stands for its leaf
      child = members[0];
      members = child.children.filter(isMember);
    }
    const key = memberId(child);
    let v: TermValue | undefined;
    if (members.length) v = projectCluster(child);
    else {
      v = leafValue(child);
      if (v === undefined) throw new ConditionError(`ms-${key} has no members, no value and no Exceptional Value`);
    }
    if (Object.prototype.hasOwnProperty.call(out, key)) throw new ConditionError(`member ${key} appears twice`);
    out[key] = v;
  }
  return out;
}

/** Parse strictly (saxes: well-formedness and namespaces enforced) into the shape ElementTree gives. */
export function parse(xml: string | Uint8Array): El {
  let text: string;
  if (typeof xml === 'string') text = xml;
  else {
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(xml);
    } catch {
      throw new ConditionError('not UTF-8');
    }
  }
  if (text.includes('<!DOCTYPE') || text.includes('<!ENTITY')) throw new ConditionError('a DOCTYPE or entity declaration is refused');
  const decl = /^﻿?<\?xml[^?]*encoding\s*=\s*["']([^"']+)["']/.exec(text);
  if (decl && !/^utf-?8$/i.test(decl[1])) throw new ConditionError(`encoding ${decl[1]} is refused: give the record as UTF-8`);

  const parser = new SaxesParser({ xmlns: true });
  const stack: El[] = [];
  let root: El | undefined;
  const data = (t: string) => {
    const top = stack[stack.length - 1];
    if (top && top.children.length === 0) top.text += t;
  };
  parser.on('opentag', (node) => {
    const el: El = { ns: node.uri ?? '', local: node.local ?? node.name, children: [], text: '' };
    if (stack.length) stack[stack.length - 1].children.push(el);
    else root = el;
    stack.push(el);
  });
  parser.on('closetag', () => {
    stack.pop();
  });
  parser.on('text', data);
  parser.on('cdata', data);
  parser.on('error', (e) => {
    throw new ConditionError(`not well-formed XML: ${e.message}`);
  });
  parser.write(text).close();
  if (!root) throw new ConditionError('not well-formed XML: no root element');
  return root;
}

function* iter(el: El): Generator<El> {
  yield el;
  for (const c of el.children) yield* iter(c);
}

/** The projection of the Settlement Condition cluster `ms-<condition>` in a governed record. */
export function project(xml: string | Uint8Array, condition: string): Projection {
  if (!CT.test(condition)) throw new ConditionError(`not a ct_id: ${condition}`);
  const root = parse(xml);
  if (root.ns !== SDC4 || !root.local.startsWith('dm-')) throw new ConditionError('the root is not an SDC4 data model element (sdc4:dm-<ct_id>)');
  const found = [...iter(root)].filter((el) => sdc(el) && el.local === `ms-${condition}`);
  if (found.length !== 1) throw new ConditionError(`expected one ms-${condition}, found ${found.length}`);
  return { projection: PROJECTION, model: root.local.slice(3), condition, terms: projectCluster(found[0]) };
}

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** `[condition_hash, canonical bytes]`: SHA-256 hex over RFC 8785 of the projection. */
export function conditionHash(xml: string | Uint8Array, condition: string): [string, Uint8Array] {
  const canon = canonicalizeBytes(project(xml, condition));
  return [toHex(sha256(canon)), canon];
}
