# R-DEBUG-001 — DEBUG / UNVALIDATED state accepted

- **Severity:** critical
- **Modes:** static, policy, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

A DEBUG TEE can be inspected and injected; UNVALIDATED means the TCB was never checked. Accepting either destroys isolation.

## How to fix

Reject reports whose policy/flags indicate DEBUG or that are not VALIDATED.
