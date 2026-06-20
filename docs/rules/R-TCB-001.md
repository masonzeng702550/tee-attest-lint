# R-TCB-001 — TCB below minimum accepted

- **Severity:** high
- **Modes:** static, policy, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

Old TCB contains known vulnerabilities; no lower bound means accepting exploitable firmware/microcode.

## How to fix

Require reported TCB >= policy min_tcb for every component.
