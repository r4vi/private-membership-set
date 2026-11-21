"""Executable formal verification test suite covering Z3 SMT, TLA+ TLC, and Lean 4."""

from __future__ import annotations

import pytest

import pmset
from pmset.verification import LeanVerifier, TLAVerifier, Z3Verifier

ALL_PROTOCOLS = pmset.all_protocols()


@pytest.mark.parametrize("protocol", ALL_PROTOCOLS, ids=lambda p: p.name)
def test_z3_formal_verification(protocol):
    verifier = Z3Verifier()
    assert verifier.is_available(), "z3-solver must be installed in dev/verify env"
    report = verifier.verify(protocol)
    assert report.all_passed, "\n".join(f"{p.name}: {p.detail}" for p in report.properties)


@pytest.mark.parametrize(
    "spec_name",
    [
        "PMSetGeneric.tla",
        "OPRFPIR.tla",
        "CuckooOPRFPIR.tla",
        "FNPPaillier.tla",
        "ElGamalEquality.tla",
        "OPRFFilter.tla",
        "OTGarbledBloom.tla",
        "TwoServerDPFPIR.tla",
        "ShamirMultiServerPIR.tla",
    ],
)
def test_tla_model_checking(spec_name: str):
    verifier = TLAVerifier()
    assert verifier.is_available(), "Java + tla2tools.jar must be available"
    res = verifier.run_spec(spec_name)
    assert res.passed, res.detail


def test_tla_spec_mapped_for_every_protocol():
    for proto in ALL_PROTOCOLS:
        assert proto.metadata.tla_spec is not None


def test_lean4_formal_verification_all_protocols():
    verifier = LeanVerifier()
    assert verifier.is_available(), "Lean 4 (lake) toolchain must be available"
    for proto in ALL_PROTOCOLS:
        report = verifier.verify(proto)
        assert report.all_passed, "\n".join(f"{p.name}: {p.detail}" for p in report.properties)
