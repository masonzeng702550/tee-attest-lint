# R-CHAIN-001 — certificate chain not anchored to the vendor root

- **Severity:** critical
- **Modes:** static, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

If VCEK/VLEK or PCK does not chain to AMD ARK/ASK or the Intel PCS root, you are trusting an unknown issuer.

## How to fix

Build and verify the certificate chain to a built-in vendor root (ARK/ASK or PCS); never trust a hard-coded or caller-supplied root.
