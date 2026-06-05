import pytest
from private_membership import PSMServer, PSMClient, DHOPRF, Paillier

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

def test_bucket_padding():
    """Test that all buckets are padded to the same size."""
    items = ["a", "b", "c"]
    bucket_count = 10 # More buckets than items, ensuring some are empty/small
    server = PSMServer(items, bucket_count=bucket_count)
    
    sizes = [len(b) for b in server.buckets]
    assert len(set(sizes)) == 1 # All sizes should be equal
    assert sizes[0] >= 1
