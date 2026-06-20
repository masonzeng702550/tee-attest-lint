# R-MEAS-001 — measurement not pinned / compared

- **Severity:** critical
- **Modes:** static, policy, runtime
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

Without comparing MRENCLAVE / MRTD / launch measurement you accept any image — an attacker can swap in a malicious workload.

## How to fix

Compare the reported measurement byte-for-byte against the expected value(s) from policy; never use a wildcard.
