# R-REVOKE-001 — collateral / CRL revocation not handled

- **Severity:** high
- **Modes:** static, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

Skipping revocation means revoked VCEK/PCK certs are still accepted; the revocation mechanism becomes a no-op.

## How to fix

Fetch and apply CRL/collateral; fail when a cert is revoked.
