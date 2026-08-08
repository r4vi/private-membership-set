import random

import pytest
from private_membership import PSMServer, PSMClient, DHOPRF, Paillier, is_prime, OPRF_PRIME

def test_oprf_flow():
    """Test that the OPRF unblinding results in the same hash as direct computation."""
    oprf = DHOPRF()
    server_k = 123456789
    item = "test_item"
    
    # Client side
    blinded, r = oprf.client_blind(item)
    
    # Server side
    signed = oprf.server_sign(blinded, server_k)
    
    # Client side
    unblinded = oprf.client_unblind(signed, r)
    
    # Direct computation
    direct = oprf.server_compute_hash(item, server_k)
    
    assert unblinded == direct

def test_paillier_encryption():
    """Test Paillier homomorphic properties."""
    p = Paillier(bits=512)
    m1 = 10
    m2 = 20
    
    c1 = p.encrypt(m1)
    c2 = p.encrypt(m2)
    
    # Test decryption
    assert p.decrypt(c1) == m1
    
    # Test addition: E(m1 + m2) = E(m1) * E(m2) mod n^2
    c_sum = (c1 * c2) % p.n_sq
    assert p.decrypt(c_sum) == m1 + m2
    
    # Test scalar multiplication: E(m1 * k) = E(m1)^k mod n^2
    k = 5
    c_mul = pow(c1, k, p.n_sq)
    assert p.decrypt(c_mul) == m1 * k

def test_psm_membership():
    """Test full PSM flow for membership and non-membership."""
    items = ["alice@gmail.com", "bob@gmail.com", "charlie@gmail.com"]
    bucket_count = 4
    server = PSMServer(items, bucket_count=bucket_count)
    client = PSMClient(bucket_count=bucket_count)
    
    # Test existing items
    assert client.query(server, "alice@gmail.com") is True
    assert client.query(server, "bob@gmail.com") is True
    
    # Test non-existing items
    assert client.query(server, "eve@gmail.com") is False
    assert client.query(server, "malory@gmail.com") is False

def test_psm_empty_server():
    """Test PSM flow with an empty server set."""
    server = PSMServer([], bucket_count=4)
    client = PSMClient(bucket_count=4)
    
    assert client.query(server, "anyone@gmail.com") is False

def test_bucket_count_mismatch_raises():
    """Client and server must agree on bucket_count.

    A mismatch previously caused either silent wrong answers (client with more
    buckets than the server) or an unhandled IndexError (client with fewer).
    Both must now raise a clear ValueError instead.
    """
    items = ["alice@gmail.com", "bob@gmail.com"]
    server = PSMServer(items, bucket_count=4)

    # Client with MORE buckets than the server -> previously silent false negatives
    client_more = PSMClient(bucket_count=8)
    with pytest.raises(ValueError):
        client_more.query(server, "alice@gmail.com")

    # Client with FEWER buckets than the server -> previously IndexError inside PIR
    client_less = PSMClient(bucket_count=2)
    with pytest.raises(ValueError):
        client_less.query(server, "alice@gmail.com")


def test_oprf_rejects_composite_prime():
    """The DH OPRF is only correct for a prime modulus.

    A composite p silently breaks the unblinding math (Fermat's little theorem
    is required), so it must be rejected at construction.
    """
    with pytest.raises(ValueError):
        DHOPRF(p=561)  # Carmichael number: passes the Fermat test for many bases
    with pytest.raises(ValueError):
        DHOPRF(p=15)
    with pytest.raises(ValueError):
        DHOPRF(p=2)  # even: group math breaks

    # Default prime 2^256 - 189 is prime and must be accepted
    oprf = DHOPRF()
    assert oprf.p == OPRF_PRIME


def test_is_prime_rejects_carmichael_numbers():
    """is_prime must not accept Carmichael numbers (Fermat pseudoprimes).

    The previous implementation was Fermat's test, which accepts Carmichael
    numbers whenever all random bases are coprime to n. The RNG is seeded so
    this is deterministic: with seed 30 the old Fermat test wrongly reported
    561, 1729 and 6601 as prime.
    """
    state = random.getstate()
    try:
        random.seed(30)
        for n in (561, 1105, 1729, 2465, 2821, 6601, 8911):
            assert is_prime(n) is False, f"{n} is a Carmichael number, must be composite"
    finally:
        random.setstate(state)


def test_is_prime_accepts_primes():
    """Primes (including the defaults used by the protocol) must be accepted."""
    state = random.getstate()
    try:
        random.seed(30)
        for n in (2, 3, 97, 101, 2 ** 61 - 1, OPRF_PRIME):
            assert is_prime(n) is True, f"{n} is prime, must be accepted"
    finally:
        random.setstate(state)


def test_server_holds_no_client_state():
    """The client's Paillier modulus is passed per PIR request, never stored on
    the server.

    Previously the client mutated server.n_for_pir as a side channel, which
    broke interleaved clients and relied on an assert that disappears under
    python -O.
    """
    server = PSMServer(["alice@gmail.com", "bob@gmail.com"], bucket_count=4)
    client = PSMClient(bucket_count=4)

    assert not hasattr(server, "n_for_pir")
    assert client.query(server, "alice@gmail.com") is True
    assert client.query(server, "eve@gmail.com") is False


def test_bucket_padding():
    """Test that all buckets are padded to the same size."""
    items = ["a", "b", "c"]
    bucket_count = 10 # More buckets than items, ensuring some are empty/small
    server = PSMServer(items, bucket_count=bucket_count)
    
    sizes = [len(b) for b in server.buckets]
    assert len(set(sizes)) == 1 # All sizes should be equal
    assert sizes[0] >= 1
