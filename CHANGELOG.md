# Changelog

## [Unreleased]

### Added

- **`verify`**: the VSL verification procedure over a Settlement Receipt, as sdcreceipt implements
  it. It covers `receipt_hash` over RFC 8785 content, issuer signatures (`ES256`, and `ML-DSA-65`
  for Receipt 1.1), party triggers over `{condition_hash, receipt_id}`, trigger uniqueness,
  settlement completeness, the governance binding and the payload hash. Every check is reported,
  and the check names are sdcreceipt's.
- **Conforms to the VSL conformance kit 1.1:** all 17 vectors, each invalid one failing on the
  check the manifest names, and all 5 key-document cases. Also passes sdcgovernance's 21 RFC 8785
  vectors. CI pins the kit to sdcreceipt commit `50590c0`.
- **Key documents:**
  - `loadKeySet` reads the issuer key-set shape and did:web DID documents, admitting P-256 and
    ML-DSA-65 keys only and keeping `revoked`.
  - `assembleKeys` takes documents in caller-given roles. It refuses a key_id two documents claim,
    one listed twice, and one key in both roles.
- **The party side:** `generateKey`, `keyDocument`, `publicationPath` and `signTrigger`, with keys as
  PKCS#8 and SPKI PEM. Checked both ways against sdcreceipt 4.3.4: each verifies the other's
  triggers.
- **Strict JSON reading** (`strictParse`): it refuses duplicate object keys, integers beyond
  2^53 - 1 and excessive nesting. Canonicalization refuses values with no JSON form.
- **A command and an MCP server:**
  - `npx sdcreceipt-ts verify` takes key documents in roles.
  - `npx sdcreceipt-ts mcp` serves `verify_receipt`, `sign_trigger` when started with `--key`
    and `--key-id`, and `settle` when started with `--endpoint`. No tool takes a URL. Registered as
    `io.github.SemanticDataCharter/sdcreceipt-ts`.
- **`settle`**: asks a VSL issuer to issue a Receipt, as sdcreceipt's client does. It refuses an
  endpoint that is not `https://` (or loopback `http://`), refuses to follow a redirect, and
  requires two distinct parties before any round trip. A refused transition raises
  `SettleRejected` with the states that would have worked. `splitResponse` takes the Receipt out of
  the issuer's envelope.
  - The `settle` command takes the token only from `SDCRECEIPT_TOKEN`, never a flag.
  - The MCP `settle` tool is offered only when the server is started with `--endpoint`, and posts
    only there.
  - Tested against a stand-in issuer on loopback, not against a live one.
- **Decision tables and governance Receipts**, the parts of sdcgovernance a Receipt relies on:
  - `parseDecisionTable`, `decisionTableHash` (a governance Receipt's `table_hash`),
    `evaluateDecisionTable` (FIRST, UNIQUE, COLLECT) and an in-memory `TableRegistry` that loads
    sdcgovernance's saved records.
  - `verifyGovernanceReceipt` recomputes a governance Receipt's own `receipt_hash`, including one
    hashed before RFC 8785. It refuses, rather than guesses, a legacy Receipt carrying a number.
  - Python's semantics are kept where JavaScript differs.
  - Conforms to sdcgovernance's decision-table and governance-Receipt vectors: every table hash,
    37 evaluations, 9 governance Receipts. CI pins them to sdcgovernance commit `396c2bf`.
- **Runs in Node, Deno and browsers.** Checked 2026-11-01 on Node 24.4 (CI runs Node 20, 22 and
  24), Deno 2.5.6 (all 17 kit vectors) and Chromium 152 (the 1.1 vector with its schema).

### Changed

- A release skips the npm publish for a version already on npm. 4.0.0 was published by hand to
  create the package for trusted publishing, so its tag registers it with the MCP registry only.
