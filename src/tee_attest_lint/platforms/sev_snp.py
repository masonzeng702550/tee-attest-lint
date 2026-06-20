"""Minimal AMD SEV-SNP attestation-report parser.

Decodes the fields the grader needs from the raw ATTESTATION_REPORT structure
(AMD SEV-SNP ABI). We parse the locally-checkable fields — version, guest
policy (DEBUG bit), measurement, report_data, reported TCB, signature presence —
without depending on hardware. Cryptographic verification of the signature
against the VCEK requires collateral (KDS) and is handled by the grader as a
degradable step (SPEC §10: offline degrade).

Reference layout (offsets, little-endian):
    0x000 version            u32
    0x008 policy             u64   (guest policy; bit 19 = DEBUG)
    0x030 vmpl               u32
    0x034 signature_algo     u32
    0x050 report_data        64 bytes
    0x090 measurement        48 bytes
    0x0C0 host_data          32 bytes
    0x180 reported_tcb       u64
    0x2A0 signature          512 bytes (to end)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

REPORT_MIN_LEN = 0x4A0  # 1184 bytes for v2 reports

POLICY_DEBUG_BIT = 1 << 19

_OFF_VERSION = 0x000
_OFF_POLICY = 0x008
_OFF_SIG_ALGO = 0x034
_OFF_REPORT_DATA = 0x050
_OFF_MEASUREMENT = 0x090
_OFF_REPORTED_TCB = 0x180
_OFF_SIGNATURE = 0x2A0


class ReportParseError(Exception):
    pass


@dataclass
class TcbVersion:
    """SEV-SNP TCB_VERSION unpacked from its u64 little-endian encoding."""

    bootloader: int
    tee: int
    snp: int
    microcode: int

    @classmethod
    def from_u64(cls, raw: int) -> "TcbVersion":
        b = raw.to_bytes(8, "little")
        return cls(bootloader=b[0], tee=b[1], snp=b[6], microcode=b[7])

    def as_dict(self) -> dict[str, int]:
        return {
            "bootloader": self.bootloader,
            "tee": self.tee,
            "snp": self.snp,
            "microcode": self.microcode,
        }


@dataclass
class SevSnpReport:
    version: int
    policy: int
    signature_algo: int
    report_data: bytes      # 64 bytes
    measurement: bytes      # 48 bytes
    reported_tcb: TcbVersion
    signature: bytes        # raw signature bytes

    @property
    def is_debug(self) -> bool:
        return bool(self.policy & POLICY_DEBUG_BIT)

    @property
    def has_signature(self) -> bool:
        return any(self.signature)


def parse(data: bytes) -> SevSnpReport:
    if len(data) < REPORT_MIN_LEN:
        raise ReportParseError(
            f"report too short: {len(data)} bytes (< {REPORT_MIN_LEN})"
        )

    (version,) = struct.unpack_from("<I", data, _OFF_VERSION)
    (policy,) = struct.unpack_from("<Q", data, _OFF_POLICY)
    (sig_algo,) = struct.unpack_from("<I", data, _OFF_SIG_ALGO)
    report_data = data[_OFF_REPORT_DATA:_OFF_REPORT_DATA + 64]
    measurement = data[_OFF_MEASUREMENT:_OFF_MEASUREMENT + 48]
    (reported_tcb_raw,) = struct.unpack_from("<Q", data, _OFF_REPORTED_TCB)
    signature = data[_OFF_SIGNATURE:]

    if version == 0:
        raise ReportParseError("report version is 0 — not a SEV-SNP report")

    return SevSnpReport(
        version=version,
        policy=policy,
        signature_algo=sig_algo,
        report_data=report_data,
        measurement=measurement,
        reported_tcb=TcbVersion.from_u64(reported_tcb_raw),
        signature=signature,
    )


def parse_file(path: str) -> SevSnpReport:
    try:
        with open(path, "rb") as fh:
            return parse(fh.read())
    except FileNotFoundError as exc:
        raise ReportParseError(f"report file not found: {path}") from exc
