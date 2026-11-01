# sdcreceipt-ts

Verify VSL Settlement Receipts, sign settlement triggers and request Receipts from an issuer in
TypeScript, with the same results as
[sdcreceipt](https://github.com/SemanticDataCharter/sdcreceipt), the reference implementation.

**Conforms to:**
- the [VSL conformance kit](https://github.com/SemanticDataCharter/sdcreceipt/tree/main/tests/conformance)
  1.1: all 17 Receipt vectors, each invalid one failing on the check the manifest names, and all 5
  key-document cases;
- [sdcgovernance's RFC 8785 vectors](https://github.com/SemanticDataCharter/sdcgovernance/tree/main/test-vectors):
  all 21.

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

## Command line and MCP server

```bash
npx sdcreceipt-ts verify receipt.json --issuer-keys issuer.json --party-keys vendor.json --party-keys buyer.json
```

```bash
SDCRECEIPT_TOKEN=... npx sdcreceipt-ts settle payload.xml --target-state shipped --condition '{"on":"goods received"}' --party https://vendor.example/k.json --party https://buyer.example/k.json --out receipt.json
```

`verify` also reads a Receipt out of the issuer's settle or status response. `settle` takes the token
only from `SDCRECEIPT_TOKEN`, never from a flag, so it stays out of shell history.

```bash
npx sdcreceipt-ts mcp
```

The MCP server speaks JSON-RPC 2.0 over stdio, as sdcreceipt's own server does.

| Tool | What it does |
|---|---|
| `verify_receipt` | Every check, with each result; no network, no account |
| `sign_trigger` | Signs as the identity the server was started with (`mcp --key FILE --key-id URI`); offered only then; returns the trigger unsubmitted |
| `settle` | Asks the issuer the server was started with (`mcp --endpoint URL`, token in `--token` or `SDCRECEIPT_TOKEN`) to issue a Receipt; offered only then. A refused transition comes back as a result, with the states that would work |

No tool takes a URL. The signing key, the identity and the issuer endpoint are fixed at start-up,
never passed per call. It is registered in the MCP registry as
`io.github.SemanticDataCharter/sdcreceipt-ts`.

## Development

```bash
npm install
npm run typecheck
npm test     # needs the kit and the vectors: sibling sdcreceipt and sdcgovernance checkouts, or SDCRECEIPT_KIT and JCS_VECTORS
npm run build
```

Dependencies are pinned exactly:
- `@noble/post-quantum` 0.7.1 (ML-DSA-65);
- `canonicalize` 5.1.0 (RFC 8785, by one of its authors), so canonicalization is not written twice;
- `ajv` 8.20.0 (the Receipt schemas, JSON Schema 2020-12).

ES256 uses the runtime's own WebCrypto.

## License

Apache-2.0.
