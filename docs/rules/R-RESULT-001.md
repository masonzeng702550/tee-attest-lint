# R-RESULT-001 — structured verification result ignored

- **Severity:** high
- **Modes:** static, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

DCAP/QVL return a structure (TCB status, advisory IDs), not a bool. Checking only 'did it throw' lets OUT_OF_DATE / SW_HARDENING_NEEDED through.

## How to fix

Inspect the returned status/advisory fields and treat any non-OK status as a defect.
