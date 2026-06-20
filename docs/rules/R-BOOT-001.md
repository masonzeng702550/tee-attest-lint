# R-BOOT-001 — policy allows mutable boot parameters / unlocked kernel cmdline

- **Severity:** high
- **Modes:** static, policy
- **Platforms:** sev-snp, tdx, sgx

## Why it is dangerous

An unlocked cmdline lets an attacker inject init=, disable dm-verity, etc. — the boot chain is tampered while the measurement still 'passes'.

## How to fix

Lock the kernel cmdline and enumerate allowed cmdline hashes in policy.
