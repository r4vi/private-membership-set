"""Uniform conformance test suite running ALL 12 concrete PMSet protocols through the generic interface."""

from __future__ import annotations

import pytest

import pmset
from pmset.core.interfaces import MultiServerPMSetServer
from pmset.core.types import PublicParams

ALL_PROTOCOL_NAMES = pmset.list_protocols()


def test_all_twelve_protocols_registered():
    assert len(ALL_PROTOCOL_NAMES) == 12
    expected = {
        "cuckoo_oprf_pir",
        "dh_oprf_paillier_pir",
        "ecdh_oprf_filter",
        "ecdh_oprf_paillier_2d_pir",
        "ecdh_oprf_paillier_pir",
        "elgamal_equality",
        "fnp_paillier",
        "oprf_rlwe_pir",
        "ot_garbled_bloom",
        "rsa_oprf_paillier_pir",
        "shamir_multiserver_pir",
        "two_server_dpf_pir",
    }
    assert set(ALL_PROTOCOL_NAMES) == expected


@pytest.mark.parametrize("protocol_name", ALL_PROTOCOL_NAMES)
def test_protocol_membership_wire_roundtrip(protocol_name: str):
    """Every protocol must accurately decide membership over serialized wire frames."""
    proto = pmset.get_protocol(protocol_name)
    items = ["alice@example.com", "bob@example.com", "charlie@example.com", "dave@example.com"]
    server = proto.create_server(items)
    assert server.item_count == 4

    # Verify PublicParams survive full binary serialization round-trip
    raw_params = server.public_params().to_bytes()
    params = PublicParams.from_bytes(raw_params)
    client = proto.create_client(params)

    for member in ("alice@example.com", "dave@example.com"):
        res = client.query_detailed(server, member, verify_wire_roundtrip=True)
        assert res.is_member is True
        assert res.stats is not None
        assert res.stats.rounds == proto.metadata.capabilities.rounds
        assert res.stats.bytes_sent > 0
        assert res.stats.bytes_received > 0

    for absent in ("eve@example.com", "malory@example.com"):
        res = client.query_detailed(server, absent, verify_wire_roundtrip=True)
        assert res.is_member is False


@pytest.mark.parametrize("protocol_name", ALL_PROTOCOL_NAMES)
def test_protocol_empty_and_single_item_sets(protocol_name: str):
    """Every protocol must handle empty sets and singleton sets cleanly."""
    proto = pmset.get_protocol(protocol_name)

    empty_server = proto.create_server([])
    empty_client = proto.create_client(empty_server.public_params())
    assert empty_client.query(empty_server, "anyone@example.com") is False

    single_server = proto.create_server([b"\x00binary-key-\xff"])
    single_client = proto.create_client(single_server.public_params())
    assert single_client.query(single_server, b"\x00binary-key-\xff") is True
    assert single_client.query(single_server, b"\x00binary-key-\xfe") is False


@pytest.mark.parametrize("protocol_name", ALL_PROTOCOL_NAMES)
def test_protocol_stateless_interleaved_sessions(protocol_name: str):
    """Server must be stateless: interleaving two sessions step-by-step must succeed."""
    proto = pmset.get_protocol(protocol_name)
    server = proto.create_server(["alpha", "beta", "gamma"])
    client1 = proto.create_client(server.public_params())
    client2 = proto.create_client(server.public_params())

    s1 = client1.start_query("alpha")
    s2 = client2.start_query("omega")

    while not (s1.is_complete and s2.is_complete):
        if not s1.is_complete:
            r1 = s1.next_request()
        else:
            r1 = None
        if not s2.is_complete:
            r2 = s2.next_request()
        else:
            r2 = None
        # Process in reverse order (s2 before s1) to expose any accidental server state
        if r2 is not None:
            s2.process_response(server.handle_request(r2))
        if r1 is not None:
            s1.process_response(server.handle_request(r1))

    assert s1.result().is_member is True
    assert s2.result().is_member is False


@pytest.mark.parametrize("protocol_name", ALL_PROTOCOL_NAMES)
def test_protocol_payload_retrieval_and_batch(protocol_name: str):
    """Protocols advertising payload support must return exact AEAD-decrypted payloads."""
    proto = pmset.get_protocol(protocol_name)
    dataset = {
        "alice@example.com": b"role=admin;quota=100",
        "bob@example.com": b"role=user;quota=10",
    }
    server = proto.create_server(dataset)
    client = proto.create_client(server.public_params())

    batch = client.query_batch(
        server,
        ["alice@example.com", "eve@example.com", "bob@example.com"],
        verify_wire_roundtrip=True,
    )
    assert batch.memberships == [True, False, True]
    if proto.metadata.capabilities.supports_payloads:
        assert batch.results[0].payload == b"role=admin;quota=100"
        assert batch.results[1].payload is None
        assert batch.results[2].payload == b"role=user;quota=10"


@pytest.mark.parametrize("protocol_name", ["two_server_dpf_pir", "shamir_multiserver_pir"])
def test_multi_server_strict_replica_isolation(protocol_name: str):
    """Verify multi-server replicas can be invoked completely independently."""
    proto = pmset.get_protocol(protocol_name)
    server = proto.create_server({"alice": b"v1", "bob": b"v2"})
    assert isinstance(server, MultiServerPMSetServer)
    assert len(server.replicas) >= 2

    client = proto.create_client(server.public_params())
    session = client.start_query("alice")
    while not session.is_complete:
        req = session.next_request()
        assert req.replica_payloads is not None
        # Deliver each replica's isolated payload ONLY to that replica
        resp_map = {}
        for replica in server.replicas:
            if replica.replica_id in req.replica_payloads:
                resp_map[replica.replica_id] = replica.handle_replica_request(
                    req.phase, req.replica_payloads[replica.replica_id]
                )
        from pmset.core.types import ProtocolMessage

        session.process_response(
            ProtocolMessage(
                protocol=req.protocol,
                phase=f"{req.phase}_response",
                round_num=req.round_num,
                replica_payloads=resp_map,
            )
        )
    res = session.result()
    assert res.is_member is True
    assert res.payload == b"v1"


def test_ecdh_oprf_filter_bloom_mode():
    proto = pmset.get_protocol("ecdh_oprf_filter")
    server = proto.create_server(
        [f"item-{i}" for i in range(25)],
        filter_mode="bloom",
        false_positive_rate=1e-6,
    )
    client = proto.create_client(server.public_params())
    assert client.query(server, "item-0") is True
    assert client.query(server, "item-24") is True
    assert client.query(server, "non-member-xyz") is False


def test_protocol_mismatch_raises():
    p1 = pmset.get_protocol("oprf_rlwe_pir")
    p2 = pmset.get_protocol("fnp_paillier")
    s1 = p1.create_server(["a", "b"])
    s2 = p2.create_server(["a", "b"])
    c1 = p1.create_client(s1.public_params())
    with pytest.raises(ValueError):
        c1.query(s2, "a")
    with pytest.raises(ValueError):
        p2.create_client(s1.public_params())
