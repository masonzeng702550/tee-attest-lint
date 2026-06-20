# R-ALG-001 — weak / arbitrary signature or measurement algorithm accepted

- **Severity:** medium
- **Modes:** static
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

Accepting a downgraded algorithm weakens the cryptographic guarantee.

## How to fix

Pin the expected algorithm; never accept a caller-specified algorithm.
