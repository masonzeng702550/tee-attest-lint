"""Helpers for constructing raw SEV-SNP report bytes in tests."""

from __future__ import annotations

import hashlib
import struct

from tee_attest_lint.platforms import sev_snp

# Measurement that matches tests/fixtures/policy/strict.yaml
GOOD_MEASUREMENT = bytes.fromhex("ab" * 48)


def _tcb_u64(bootloader: int, tee: int, snp: int, microcode: int) -> int:
    b = bytearray(8)
    b[0] = bootloader
    b[1] = tee
    b[6] = snp
    b[7] = microcode
    return int.from_bytes(bytes(b), "little")


def build_report(
    *,
    version: int = 2,
    debug: bool = False,
    measurement: bytes = GOOD_MEASUREMENT,
    report_data: bytes = b"\x00" * 64,
    tcb=(3, 0, 8, 209),
    signature: bytes | None = None,
) -> bytes:
    """Return raw report bytes (>= 1184) with the given fields."""
    buf = bytearray(sev_snp.REPORT_MIN_LEN)
    struct.pack_into("<I", buf, 0x000, version)
    policy = 0
    if debug:
        policy |= sev_snp.POLICY_DEBUG_BIT
    struct.pack_into("<Q", buf, 0x008, policy)
    struct.pack_into("<I", buf, 0x034, 1)  # signature_algo
    assert len(report_data) == 64
    buf[0x050:0x050 + 64] = report_data
    assert len(measurement) == 48
    buf[0x090:0x090 + 48] = measurement
    struct.pack_into("<Q", buf, 0x180, _tcb_u64(*tcb))
    if signature is None:
        signature = b"\x01" * 96  # non-zero placeholder => "has signature"
    buf[0x2A0:0x2A0 + len(signature)] = signature
    return bytes(buf)


def report_data_for(tls_pubkey: bytes | None, nonce: bytes | None) -> bytes:
    h = hashlib.sha512()
    if tls_pubkey is not None:
        h.update(tls_pubkey)
    if nonce is not None:
        h.update(nonce)
    return h.digest()
