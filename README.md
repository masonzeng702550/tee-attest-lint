# TEE-Attest-Lint

A linter and security grader for confidential-computing **remote-attestation
verifiers**. It finds the classic mistakes that *silently* void an attestation's
security guarantee — the verifier still "passes", the TLS session still
establishes, business logic still runs, but the TEE guarantee is already gone.

Targets the verifier side of AMD SEV-SNP, Intel TDX and Intel SGX. The MVP ships
SEV-SNP; TDX/SGX are scaffolded behind the same rule catalog and report schema.

> Not a replacement for vendor verification libraries (DCAP/QVL, sev-guest). It
> audits *how you call them* — the part that fails silently.

## Why

Attestation verification is a long, multi-step chain: signature, certificate
chain to the vendor root, TCB floor, revocation, measurement pinning,
nonce/freshness, and channel binding. Miss any one and the attack surface
collapses back to "no TEE" — with **no error and no signal**. This tool turns
those silent gaps into explicit findings.

## Three modes, one rule catalog

| Mode | Command | What it does |
|------|---------|--------------|
| Static scan | `attest-lint scan <path>` | Lint verifier source for missing/incorrect checks (no code executed). |
| Policy lint | `attest-lint lint-policy <policy.yaml>` | Validate the policy schema and flag over-loose settings. |
| Runtime grade | `attest-lint grade <report.bin> --policy <policy.yaml>` | Run a real report through the policy and produce a 0–100 security score plus a "which checks are missing" list. |

All three emit the same JSON shape keyed by rule ID, so static findings, policy
defects and runtime gaps line up.

## Install

```bash
pip install -e .
# optional: real signature/chain verification in `grade`
pip install -e ".[dev]" cryptography
```

Requires Python 3.10+.

## Usage

```bash
# CI gate: non-zero exit when a verifier is missing checks
attest-lint scan ./verifier --tee sev-snp --format json

# audit a policy for silently-weak settings
attest-lint lint-policy policy.yaml

# grade a real report against a policy
attest-lint grade report.bin --policy policy.yaml \
    --nonce 0011223344556677 --tls-pubkey channel.pub \
    --vcek vcek.pem --trust-root amd-ark.pem --crl vcek.crl

attest-lint rules --tee sev-snp     # list the rule catalog
```

**Exit codes:** `0` clean · `1` findings at/above threshold or grade weak/insecure
· `2` execution error (parse failure, missing collateral).

## Rule catalog

| ID | Severity | Modes | What it catches |
|----|----------|-------|-----------------|
| R-SIG-001 | critical | S/R | report/quote signature not verified |
| R-CHAIN-001 | critical | S/R | cert chain not anchored to the vendor root |
| R-DEBUG-001 | critical | S/P/R | DEBUG / UNVALIDATED state accepted |
| R-MEAS-001 | critical | S/P/R | measurement not pinned / compared |
| R-BIND-001 | critical | S/R | report_data not bound to the TLS channel key |
| R-FRESH-001 | high | S/P/R | missing nonce / freshness (replay) |
| R-TCB-001 | high | S/P/R | TCB below minimum accepted |
| R-REVOKE-001 | high | S/R | collateral / CRL revocation not handled |
| R-RESULT-001 | high | S/R | structured verification result ignored |
| R-BOOT-001 | high | S/P | unlocked kernel cmdline / mutable boot params |
| R-ALG-001 | medium | S | weak / arbitrary algorithm accepted |

See [`docs/rules/`](docs/rules) for the rationale and fix of each rule.

## Grading

The grader runs the verification steps in order and weights them (Critical steps
weigh most, sum 100). A **safety cap** forces the score to ≤ 40 / `insecure` when
any Critical step is missing or fails — so leaving out one key check can never
yield a high score. Bands: `strong` ≥ 90, `adequate` 70–89, `weak` 40–69,
`insecure` < 40. Same report + same policy is deterministic.

Cryptographic steps (signature/chain/revocation) bind to vendor collateral. When
collateral is not supplied the step degrades to `missing` ("could not verify")
rather than passing silently — which, being Critical, trips the safety cap.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" pyyaml cryptography
pytest -q
```

Tests assert detection rate on known-bad fixtures and zero false positives on
known-good fixtures (`tests/fixtures/`).

## License

Apache-2.0.
