# R-SIG-001 — report/quote signature not verified

- **Severity:** critical
- **Modes:** static, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

Skipping signature verification means anyone can forge a report; attestation fails completely and silently.

## How to fix

Verify the report signature with the VCEK/VLEK (SEV-SNP) or PCK (TDX/SGX) public key and check the result.
