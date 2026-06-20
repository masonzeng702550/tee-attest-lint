# R-BIND-001 — report_data not bound to the TLS channel public key

- **Severity:** critical
- **Modes:** static, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

If attestation is decoupled from the secure channel, a MITM can relay a legitimate report onto its own channel.

## How to fix

Set the expected report_data to a hash of the local TLS public key (channel binding) and compare it.
