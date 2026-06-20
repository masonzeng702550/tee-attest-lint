# R-FRESH-001 — missing nonce / freshness

- **Severity:** high
- **Modes:** static, policy, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

Without a challenge nonce an attacker can replay an old but valid report and bypass liveness.

## How to fix

Bind a caller-supplied nonce into report_data and compare it on every verification.
