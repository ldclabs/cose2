# Security Review: cose2

## Scope

Standard repository-wide security scan of cose2, a Rust COSE/CWT library. The deterministic inventory selected all 21 runtime source-like files for deep review.

- Scan mode: repository
- Target kind: git_worktree
- Target ID: target_sha256_abdeef65af2465cb9f058ce7570b8c6ee7a4295c045a0c66c4f50aad196bd53f
- Revision: 4e643d819c2b39b8a080d2cb9b389434408f2cd4
- Snapshot digest: codex-security-snapshot/v1:sha256:af637baa0821172ac115eaee661c2d3388dff23dd4d27e220776aca6d2bb77cf
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Runtime or test status: Source review plus targeted local test evidence from discovery workers; no code changes were made by the scan.
- Artifacts reviewed: AGENTS.md repository instructions, Cargo.toml, 21 source-like files from deterministic rank_input.jsonl, targeted README, docs, tests, and examples as supporting evidence
- Scan context: The scan used a generated repository threat model and a 100% deep-review worklist over deterministic source-like runtime files. Discovery, validation, and attack-path receipts were saved under artifacts/.

Limitations and exclusions:
- Docs, examples, and tests were not treated as deployed runtime surfaces; selected files were read as supporting evidence.
- No remediation was applied because no reportable findings survived validation and attack-path analysis.
- Excluded tests/\*\*: Test code was not treated as a deployed runtime surface; targeted tests were read as supporting evidence for reviewed controls.
- Excluded examples/\*\*: Examples were not treated as deployed runtime surfaces; selected examples were read as API guidance evidence.
- Excluded docs/\*\*: Documentation was not treated as runtime code; selected docs were read to validate public API contract and policy boundaries.

### Scan Summary

| Field | Value |
| --- | --- |
| Reportable findings | 0 |
| Severity mix | none |
| Confidence mix | none |
| Coverage | complete |
| Validation mode | Static source review with targeted existing-test evidence and candidate-level validation/attack-path analysis. |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

`cose2` is a Rust library for COSE and CWT wire structures. Its primary trust boundary is untrusted CBOR/COSE/CWT data entering parsing, validation, signing, verification, MAC, encryption, decryption, and optional `crypto-ring` provider construction APIs. The main risks are protocol-soundness failures around protected bytes, AAD, detached data, nonces, headers, claims, key material, and algorithm selection.

### Assets

- COSE message authenticity, integrity, and confidentiality
- CWT claim validity and custom claim preservation
- Canonical protected header/key encoding for newly built messages
- Raw decoded protected-header bytes used for verification/decryption structures
- Optional `crypto-ring` algorithm and key-material correctness

### Trust Boundaries

- Untrusted encoded COSE/CWT/CBOR bytes versus the library APIs that decode and construct authenticated structures.
- Application/operator-controlled key material and key-use policy versus this crate's structural key/provider validation.
- Caller-controlled external AAD and detached bytes versus message creation and verification/decryption helpers.
- Feature-gated optional `ring` crypto backend versus the crypto-free default build.

### Attacker Capabilities

- Supply untrusted COSE/CWT/CBOR bytes, including unusual encodings, headers, payloads, ciphertexts, signatures, tags, recipients, and claims.
- Supply mismatched detached payloads, detached ciphertexts, or external AAD through an embedding application.
- Attempt algorithm confusion, malformed `crit`, duplicate labels, unsupported algorithms, invalid key parameters, or nonce misuse patterns.

### Security Objectives

- Authenticate exactly the protected-header bytes and AAD required by RFC 9052 structures.
- Fail closed on malformed message, header, key, recipient, CWT, map, label, and optional crypto provider inputs.
- Keep the default build crypto-free and gate `ring` behind `crypto-ring`.
- Expose explicit APIs for detached payload/ciphertext and nonce construction so callers do not silently skip security-critical bytes.

### Assumptions

- The crate does not decide whether a key is trusted for a business identity; key trust and key-use policy are application-owned.
- The crate does not generate randomness or nonces; AEAD nonce uniqueness is an embedding application's responsibility.
- Applications processing untrusted messages must enforce private critical-header understanding with `Header::ensure_crit_understood`.
- Optional crypto providers must reject unsupported algorithm/key combinations rather than silently falling back.

## Findings

### No findings

No reportable findings survived the canonical discovery, validation, and reportability gates.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Signature messages and headers | COSE signature integrity, protected header bytes, detached payloads, AAD, and algorithm selection | No issue found | Reviewed `Sign1Message`, `SignMessage`, `Header`, and shared structure helpers. Protected-header raw bytes are preserved for verification, detached payload APIs are explicit, `crit` is structurally validated, and `alg` selection uses protected headers. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/03_coverage/repository_coverage_ledger.md |
| MAC messages and recipients | MAC authenticity, external AAD, and recipient structure | No issue found | Reviewed `Mac0Message`, `MacMessage`, `Recipient`, and `KdfContext`. MAC structures bind expected fields, recipients are structurally validated, and recipient cryptography is application-owned. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/03_coverage/repository_coverage_ledger.md |
| Encryption messages and nonce handling | AEAD AAD, IV/Partial IV, detached ciphertext, and empty plaintext | No issue found | Reviewed `Encrypt0Message`, `EncryptMessage`, `Encryptor`, tag helpers, and nonce helpers. AAD is bound, decoded protected bytes are reused, IV/PIV conflicts and malformed sizes fail closed, and detached ciphertext APIs are explicit. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/03_coverage/repository_coverage_ledger.md |
| Optional `crypto-ring` providers and keys | Feature gating, algorithm mapping, key material parsing, AEAD nonce size, and key-use metadata | Rejected | Reviewed feature gating, algorithm mapping, key parsing, AEAD nonce length, and `key_ops`. One candidate around `key_ops` enforcement was validated and rejected because key-use policy is application-owned under the current crate contract. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/02_discovery/raw_candidates.jsonl, artifacts/04_reconciliation/deduped_candidates.jsonl, artifacts/05_findings/cose2-crypto-key-ops-not-enforced/candidate_ledger.jsonl, artifacts/05_findings/cose2-crypto-key-ops-not-enforced/validation_report.md, artifacts/05_findings/cose2-crypto-key-ops-not-enforced/attack_path_analysis_report.md, artifacts/03_coverage/repository_coverage_ledger.md |
| CWT claims and validation | Custom claims, temporal validation, issuer, and audience | No issue found | Reviewed `Claims`, `ClaimsMap`, and `Validator`. Custom claims are preserved and expiration, not-before, issued-at, issuer, and audience checks fail closed under the documented validator semantics. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/03_coverage/repository_coverage_ledger.md |
| Core maps, labels, tags, and public exports | Duplicate labels, label type confusion, unsafe/default-safety guarantees, and public API guidance | No issue found | Reviewed `CoseMap`, `Label`, `Error`, `lib.rs`, tag helpers, and public guidance. Duplicate labels and label type confusion fail closed; unsafe is forbidden and default features are crypto-free. Evidence: artifacts/02_discovery/work_ledger.jsonl, artifacts/03_coverage/repository_coverage_ledger.md |
