# sdcreceipt-ts

Verify VSL Settlement Receipts, sign settlement triggers and request Receipts from an issuer in
TypeScript, with the same results as
[sdcreceipt](https://github.com/SemanticDataCharter/sdcreceipt), the reference implementation.

**Conforms to:**
- the [VSL conformance kit](https://github.com/SemanticDataCharter/sdcreceipt/tree/main/tests/conformance)
  1.2: all 27 Receipt vectors, each invalid one failing on the check the manifest names (the six
  chain and four key-window vectors through the library, the command line and the MCP tool), and
  all 5 key-document cases;
- [sdcgovernance's vectors](https://github.com/SemanticDataCharter/sdcgovernance/tree/main/test-vectors):
  all 21 RFC 8785 vectors, and the decision-table and governance-Receipt vectors (every table hash,
  all 37 evaluations, all 9 governance Receipts).

CI runs both, pinned to a fixed commit and release.

It runs in Node (20 or later), Deno and browsers. Verifying and signing need no network and no
account. You supply the keys, so a Receipt can never nominate the key it is judged by. Only `settle`
reaches an issuer.

```ts
import { assembleKeys, verify } from 'sdcreceipt-ts';

// Key documents, each in the role YOU assign. Never from a location inside the Receipt.
const keys = await assembleKeys([
  { role: 'issuer', document: issuerKeyDocument },  // https://sdcstudio.axius-sdc.com/.well-known/sdcstudio-signing-keys.json
  { role: 'party', document: vendorKeyDocument },
  { role: 'party', document: buyerKeyDocument },
]);

const result = await verify(receipt, { ...keys, governanceReceipt, payload });
result.ok;        // true only if every check passed
result.checks;    // every check that ran, passed or not: receipt_hash, signature[...], trigger[...], ...
```

**What `verify` checks:**
- **`receipt_hash`:** recomputed over the RFC 8785 canonical content.
- **Signatures:** every issuer signature over the 32-byte digest. That's `ES256` for Receipt 1.0, and both `ES256` and `ML-DSA-65` (FIPS 204) for Receipt 1.1.
- **Triggers:** each party's trigger over `{condition_hash, receipt_id}`, with the check that no party triggered twice.
- **Governance binding and payload hash:** checked when you hold the governance Receipt and the payload.
- **Key windows:** an issuer signature must fall inside its key's published window,
  `not_before <= timestamp < not_after`, compared with the Receipt's own signed `timestamp`. A
  `retired` key inside its window still verifies; a `revoked` key fails whatever its window says. A
  party key whose `not_after` is at or before the Receipt's `timestamp` fails its trigger. A bound
  not written as RFC 3339 UTC ending in `Z` refuses the key document. Always on.

**Chains.** `verifyChain(receipt, { ...keys, held })` follows `previous_hash` back to the head
through the earlier Receipts you hold, running every check on each. Held Receipts are found by the
hash computed here, never the one a document records, and are never fetched. Checks on earlier
Receipts are prefixed `chain.link[<n> <first 8 of previous_hash>…]`, and the walk ends with
`chain.head`. A link not held, two different documents with one hash, or an earlier Receipt never
fully triggered means not verified. The names are the conformance kit 1.2's.

It reports every check, never only the first failure. A settled Receipt checked without party keys
does not verify: `settlement.complete` is recorded as unestablished, never decided by comparing
`key_id` strings.

**What `assembleKeys` refuses:**
- a key_id that two documents publish;
- a key_id listed twice in one document;
- one key in both roles.

A key marked `revoked` fails any signature it made.

### Signing a trigger (the party side)

```ts
import { generateKey, keyDocument, signTrigger } from 'sdcreceipt-ts';

const { privateKey, publicKey } = await generateKey();          // ECDSA P-256 (ES256)
const published = await keyDocument(publicKey, myKeyId);         // publish this at your key_id
const trigger = await signTrigger(privateKey, receipt, myKeyId); // returned, never submitted
```

Keys exchange as PKCS#8 and SPKI PEM (`privateKeyPem`, `loadPrivateKey`), the files sdcreceipt reads
and writes. Triggers move both ways: sdcreceipt verifies a trigger signed here, and this library
verifies one sdcreceipt signed.

### Requesting a Receipt (`settle`)

```ts
import { settle, splitResponse, SettleRejected } from 'sdcreceipt-ts';

try {
  const answer = await settle(payloadXml, {
    token: process.env.SDCRECEIPT_TOKEN!,   // an SDCStudio API token; the endpoint defaults to SDCStudio's
    targetState: 'shipped',                 // currentState defaults to the payload's own <current-state>
    condition: { on: 'goods received' },    // hashed by the issuer, never stored
    parties: [vendorKeyId, buyerKeyId],     // at least two, each a key_id its party controls
  });
  const { receipt } = splitResponse(answer); // the signed Receipt, out of the issuer's envelope
} catch (e) {
  if (e instanceof SettleRejected) console.log(e.explain()); // the transitions that would have worked
}
```

This is the one function that needs an account: a token and a balance at the issuer. It carries the
token, so run it on a server or in an agent's process, not in a web page.

Its guards are sdcreceipt's:
- **The endpoint** must be `https://`, or `http://` on loopback for a local issuer.
- **A redirect** is refused rather than followed, so the token never reaches a host nobody checked.
- **Two distinct parties** are required before anything is sent.

### A Settlement Condition as the release condition

When the release condition is a Settlement Condition record (the Business Documents library), every
party must hash the same thing. `conditionHash` projects the record to `sdc-settlement-condition/1`
(the terms inside the named cluster, keyed by ct_id, values exactly as written) and hashes RFC 8785
of it. Settle with the projection as the condition and the issuer derives the same `condition_hash`.

```ts
import { conditionHash, projectCondition } from 'sdcreceipt-ts';

const projection = projectCondition(recordXml, 'eid1kx2nx04u3okbo18vqrks');  // the condition to settle with
const [hash] = conditionHash(recordXml, 'eid1kx2nx04u3okbo18vqrks');         // what the holder pins
```

It does not validate the record: validate it against its published model first (an XSD 1.1
validator, such as `sdcvalidate`), because the model is what enforces the per-kind rules. A DOCTYPE,
a cluster absent or present twice, and a term with neither a value nor an Exceptional Value are
refused. A port of sdcreceipt 4.5.0 `condition`, held to the conformance kit 1.3 condition cases.

### Decision tables and governance Receipts

The parts of sdcgovernance a Receipt relies on.

```ts
import { evaluateDecisionTable, decisionTableHash, TableRegistry, verifyGovernanceReceipt } from 'sdcreceipt-ts';

const result = evaluateDecisionTable(table, { risk_score: 5, attestation_level: 'senior' });
// { decision: 'PERMIT', matchedRules: [1], reasoning: 'First matching rule (#1): ...', errors: [] }

decisionTableHash(table);           // the table_hash a governance Receipt names
new TableRegistry().register('shipment-risk', '1.2', table);  // immutable versions, as sdcgovernance keeps them

verifyGovernanceReceipt(governanceReceipt);  // { ok, recorded, recomputed, detail }: is the held one untampered?
```

**Tables:**
- Hit policies FIRST, UNIQUE and COLLECT, where COLLECT takes the most restrictive outcome.
- Operators `==`, `!=`, `<`, `<=`, `>`, `>=`, `in` and `not_in`.
- An unknown operator, outcome or hit policy refuses to load rather than defaulting.

**Python's rules, deliberately.** sdcgovernance is the reference, and two implementations that decide
differently on one table are worse than either alone. So:
- `true == 1`;
- `in` is a substring test on a string and a key test on an object;
- strings order by code point;
- an order across types is false;
- `in` against a number raises `EvaluationError` rather than deciding.

**Governance Receipts.** `verify` checks that a Settlement Receipt names the governance Receipt you
hold. `verifyGovernanceReceipt` checks that the held one is itself untampered, by recomputing its
`receipt_hash`. It also reads one hashed before RFC 8785, unless that Receipt carries a number,
whose legacy rendering cannot be reproduced; then it says so.

## Command line and MCP server

```bash
npx sdcreceipt-ts verify receipt.json --issuer-keys issuer.json --party-keys vendor.json --party-keys buyer.json
npx sdcreceipt-ts verify receipt.json --issuer-keys issuer.json --party-keys vendor.json --party-keys buyer.json --chain receipts/
```

```bash
SDCRECEIPT_TOKEN=... npx sdcreceipt-ts settle payload.xml --target-state shipped --condition '{"on":"goods received"}' --party https://vendor.example/k.json --party https://buyer.example/k.json --out receipt.json
```

```bash
npx sdcreceipt-ts condition record.xml --cluster eid1kx2nx04u3okbo18vqrks --out projection.json
```

`verify` also reads a Receipt out of the issuer's settle or status response. `settle` takes the token
only from `SDCRECEIPT_TOKEN`, never from a flag, so it stays out of shell history.

```bash
npx sdcreceipt-ts mcp
```

The MCP server speaks JSON-RPC 2.0 over stdio, as sdcreceipt's own server does.

| Tool | What it does |
|---|---|
| `verify_receipt` | Every check, with each result; no network, no account. `party_keys` takes one document or one per party, `chain` the earlier Receipts you hold; `trigger_signatures_checked` and `chain_checked` name what did not run |
| `sign_trigger` | Signs as the identity the server was started with (`mcp --key FILE --key-id URI`); offered only then; returns the trigger unsubmitted |
| `settle` | Asks the issuer the server was started with (`mcp --endpoint URL`, token in `--token` or `SDCRECEIPT_TOKEN`) to issue a Receipt; offered only then. A refused transition comes back as a result, with the states that would work |
| `condition_hash` | A Settlement Condition record's projection, its RFC 8785 text and `condition_hash`; local, always offered |

No tool takes a URL. The signing key, the identity and the issuer endpoint are fixed at start-up,
never passed per call. It is registered in the MCP registry as
`io.github.SemanticDataCharter/sdcreceipt-ts`.

Also listed on [mcprush](https://mcprush.com/semanticdatacharter/sdcreceipt-ts-mcp).

## Development

```bash
npm install
npm run typecheck
npm test     # needs the kit and the vectors: sibling sdcreceipt and sdcgovernance checkouts, or SDCRECEIPT_KIT, JCS_VECTORS and GOVERNANCE_VECTORS
npm run build
```

Dependencies are pinned exactly:
- `@noble/post-quantum` 0.7.1 (ML-DSA-65);
- `canonicalize` 5.1.0 (RFC 8785, by one of its authors), so canonicalization is not written twice;
- `ajv` 8.20.0 (the Receipt schemas, JSON Schema 2020-12);
- `@noble/hashes` 2.4.0 (SHA-256 for table and governance Receipt hashes).

ES256 uses the runtime's own WebCrypto.

## License

Apache-2.0.
