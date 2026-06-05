import hashlib
import random
import math
from typing import Optional

"""
Pure Python Implementation of Private Set Membership (PSM).
Inspired by https://github.com/google/private-membership.

Goal: Readability and learning.
Performance: Not optimized (uses pure Python and Paillier HE).

The protocol follows these main phases:
1. OPRF (Oblivious Pseudo-Random Function):
   Client gets a hash of their element signed by the server's key,
   without the server seeing the element and without the client seeing the key.
2. Bucketization:
   The server's set is divided into buckets based on the prefix of the OPRF hash.
3. PIR (Private Information Retrieval):
   The client fetches the target bucket without the server knowing which bucket was fetched.
"""

# --- Constants ---
# Using a fixed 256-bit prime for the OPRF group.
# In production, use a large safe prime (e.g. from RFC 3526).
OPRF_PRIME = 2**256 - 189

# --- Math Utilities ---

def is_prime(n, k=5):
    """Miller-Rabin primality test (simplified)."""
    if n <= 1: return False
    if n <= 3: return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def get_prime(bits):
    """Generate a random prime with the specified number of bits."""
    while True:
        p = random.getrandbits(bits)
        if p % 2 != 0 and is_prime(p):
            return p

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

# --- OPRF (Oblivious Pseudo-Random Function) ---
# Implements a Diffie-Hellman based OPRF.
# This corresponds to the commutative cipher part of Google's PSM.

class DHOPRF:
    def __init__(self, p=OPRF_PRIME):
        self.p = p

    def hash_to_group(self, x):
        """Map a string x to an element in the multiplicative group Zp*."""
        h = hashlib.sha256(x.encode()).digest()
        # Ensure it's not 0 by adding 1 if necessary
        return (int.from_bytes(h, 'big') % (self.p - 1)) + 1

    def client_blind(self, x):
        """Step 1: Client blinds the element with a random factor r."""
        while True:
            r = random.randint(2, self.p - 2)
            if math.gcd(r, self.p - 1) == 1:
                break
        h_x = self.hash_to_group(x)
        blinded = pow(h_x, r, self.p)
        return blinded, r

    def server_sign(self, blinded_x, k):
        """Step 2: Server signs the blinded element with its secret key k."""
        return pow(blinded_x, k, self.p)

    def client_unblind(self, signed_blinded_x, r):
        """Step 3: Client removes the blinding factor to get H(x)^k."""
        r_inv = pow(r, -1, self.p - 1)
        return pow(signed_blinded_x, r_inv, self.p)

    def server_compute_hash(self, x, k):
        """Server-side direct computation for its own set of items."""
        h_x = self.hash_to_group(x)
        return pow(h_x, k, self.p)

# --- PIR (Private Information Retrieval) ---
# Implements a Linear PIR using Paillier Homomorphic Encryption.
# Google's library uses Ring-LWE (RLWE) based PIR for better efficiency.
# Paillier is used here for educational clarity as it is simpler to understand.

class Paillier:
    def __init__(self, bits=1024):
        p = get_prime(bits // 2)
        q = get_prime(bits // 2)
        self.n = p * q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.phi = (p - 1) * (q - 1)
        self.l = lcm(p - 1, q - 1)
        # mu = (L(g^l mod n^2))^-1 mod n
        self.mu = pow((pow(self.g, self.l, self.n_sq) - 1) // self.n, -1, self.n)

    def encrypt(self, m):
        """Encrypt message m: c = g^m * r^n mod n^2."""
        r = random.randint(2, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(2, self.n - 1)
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return c

    def decrypt(self, c):
        """Decrypt ciphertext c: m = L(c^l mod n^2) * mu mod n."""
        return (((pow(c, self.l, self.n_sq) - 1) // self.n) * self.mu) % self.n

# --- Private Set Membership (PSM) Logic ---

class PSMServer:
    def __init__(self, items, bucket_count=16):
        self.oprf = DHOPRF()
        self.k = random.randint(2, self.oprf.p - 1)
        self.bucket_count = bucket_count
        self.buckets = [[] for _ in range(bucket_count)]
        self.n_for_pir: Optional[int] = None # To be provided by client
        self._setup(items)

    def _setup(self, items):
        """Preprocess items by OPRF-hashing them and placing them into buckets."""
        for item in items:
            h_k = self.oprf.server_compute_hash(item, self.k)
            # Use lower bits as bucket index (corresponds to prefix-based bucketization)
            bucket_idx = h_k % self.bucket_count
            self.buckets[bucket_idx].append(h_k)

        # Pad all buckets to the same size to prevent size-based leakage
        max_size = max(len(b) for b in self.buckets)
        for b in self.buckets:
            while len(b) < max_size:
                b.append(random.randint(2, self.oprf.p - 1))

    def handle_oprf_request(self, blinded_element):
        return self.oprf.server_sign(blinded_element, self.k)

    def handle_pir_request(self, encrypted_query_vector):
        """
        Linear PIR: Compute dot product of query vector and buckets homomorphically.
        Result is an encrypted list containing the hashes of the target bucket.
        """
        bucket_size = len(self.buckets[0])
        assert self.n_for_pir is not None, "Client must provide n for PIR before making requests."
        n_sq: int = self.n_for_pir**2
        response = []

        for j in range(bucket_size):
            # Homomorphic dot product: Product(E(q_i)^hash_i) = E(Sum(q_i * hash_i))
            encrypted_sum = 1 # E(0) with r=1
            for i in range(self.bucket_count):
                term = pow(encrypted_query_vector[i], self.buckets[i][j], n_sq)
                encrypted_sum = (encrypted_sum * term) % n_sq
            response.append(encrypted_sum)
        return response

class PSMClient:
    def __init__(self, bucket_count=16):
        self.oprf = DHOPRF()
        self.bucket_count = bucket_count
        self.pir = Paillier(bits=1024)

    def query(self, server, element):
        print(f"[*] Querying for element: '{element}'")

        # --- Phase 1: OPRF ---
        # Get the 'hardened' hash of the element without revealing the element.
        blinded_element, r = self.oprf.client_blind(element)
        signed_blinded = server.handle_oprf_request(blinded_element)
        target_h_k = self.oprf.client_unblind(signed_blinded, r)

        # Determine which bucket the hash *should* be in.
        bucket_idx = target_h_k % self.bucket_count

        # --- Phase 2: PIR ---
        # Fetch the entire bucket without the server knowing which one.
        server.n_for_pir = self.pir.n
        query_vector = []
        for i in range(self.bucket_count):
            val = 1 if i == bucket_idx else 0
            query_vector.append(self.pir.encrypt(val))

        encrypted_response = server.handle_pir_request(query_vector)

        # Decrypt the hashes in the bucket.
        retrieved_bucket = [self.pir.decrypt(c) for c in encrypted_response]
        print(f"[-] Retrieved bucket {bucket_idx} with {len(retrieved_bucket)} items via PIR.")

        # --- Phase 3: Membership Check ---
        # Since we have the bucket, we check if our hash is present.
        if target_h_k in retrieved_bucket:
            return True
        return False

# --- Main Demonstration ---

if __name__ == "__main__":
    # Server's secret set
    server_items = ["alice@example.com", "bob@example.com", "charlie@example.com", "dave@example.com"]
    bucket_count = 4

    server = PSMServer(server_items, bucket_count=bucket_count)
    client = PSMClient(bucket_count=bucket_count)

    print(f"Server initialized with {len(server_items)} items.\n")

    test_queries = ["alice@example.com", "eve@example.com", "bob@example.com", "malory@example.com"]

    for q in test_queries:
        is_member = client.query(server, q)
        result = "MEMBER" if is_member else "NOT A MEMBER"
        print(f"[Result] '{q}' is {result}\n")
