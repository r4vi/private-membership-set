# Pure Python Private Set Membership (PSM)

[![License](https://img.shields.io/badge/license-WTFPL-brightgreen.svg)](LICENSE)

This is a educational, pure-Python implementation of the [Private Set Membership (PSM)](https://github.com/google/private-membership) protocol.

## Overview

Private Set Membership allows a **Client** to query whether an item exists in a **Server's** set without:
1. The Server learning what the Client is looking for.
2. The Server learning if the search was successful.
3. The Client learning anything about the Server's set other than the membership of that specific item.

## Protocol Phases

### 1. OPRF (Oblivious Pseudo-Random Function)
The Client and Server interact so the Client obtains $H(x)^k \pmod p$, where $x$ is the Client's item and $k$ is the Server's secret key.
- The Client **blinds** the item before sending.
- The Server **signs** the blinded item.
- The Client **unblinds** the result.

### 2. Bucketization
The Server's set is pre-processed into buckets. The bucket index is derived from `OPRF_hash % bucket_count`. This reduces the amount of data the PIR phase needs to process.

### 3. PIR (Private Information Retrieval)
The Client retrieves the specific bucket that would contain their hash. This implementation uses **Paillier Homomorphic Encryption** to perform a linear PIR:
- The Client sends an encrypted vector $[E(0), E(0), E(1), E(0)]$ where $E(1)$ is at the target bucket index.
- The Server computes a homomorphic dot product to extract the bucket content without knowing which index was $1$.

## Requirements
- Python 3.11+
- `pytest` (for running tests)

## Usage

```python
from private_membership import PSMServer, PSMClient

# Initialize Server
items = ["user123", "user456"]
server = PSMServer(items, bucket_count=4)

# Initialize Client
client = PSMClient(bucket_count=4)

# Query
is_member = client.query(server, "user123")
print(f"Is member: {is_member}")
```

## Running Tests
```bash
pytest test_psm.py
```

## Disclaimers
This implementation is for **educational purposes only**.
- It is not constant-time and is vulnerable to side-channel attacks.
- It uses a simplified prime generation logic.
- It is significantly slower than the original C++ implementation which uses RLWE-based homomorphic encryption.

## Differences from the C++ Original

This implementation is an educational simplification of [google/private-membership](https://github.com/google/private-membership). Key differences:

### 1. OPRF (Oblivious Pseudo-Random Function)

| Aspect | C++ Original | Python Implementation |
|---|---|---|
| **Group** | EC P-256 (prime-order subgroup) | Z_p* with a 256-bit prime |
| **Hash-to-group** | SSWU-RO hash-to-curve or SHA256 | `SHA256(x) mod (p-1) + 1` |
| **Protocol** | `Encrypt(client_key)` → `ReEncrypt(server_key)` → `Decrypt(client_layer)` | `Blind(r)` → `Sign(k)` → `Unblind(r)` |
| **Key derivation** | HKDF from OPRF output | Direct OPRF output |

The DH blinding/unblinding protocol `H(x)^(k·r) mod p` mathematically works, but the composite-order Z_p* group is weaker than the prime-order EC group used in production. The DDH assumption required for OPRF security only holds in prime-order subgroups. Production use would require a safe prime or elliptic curve group.

### 2. Bucketization

| Aspect | C++ Original | Python Implementation |
|---|---|---|
| **Method** | **Prefix-based**: top N bits of hash | **Modulo-based**: `hash % bucket_count` |
| **Levels** | Two-level (hashed + encrypted buckets) | Single-level |

The original takes the **top** N bits of the hash as the bucket ID; this implementation uses `hash % bucket_count` (bottom bits). These produce different bucket assignments. The protocol also omits the second-level encrypted bucket scheme.

### 3. PIR (Private Information Retrieval)

| Aspect | C++ Original | Python Implementation |
|---|---|---|
| **Algorithm** | RLWE-based FHE (Shell library) with multi-level recursion | Paillier HE, linear (single-level) PIR |
| **Complexity** | O(D^(1/L)) for L recursion levels | O(D) where D = database size |
| **Max scale** | Millions of items | Hundreds of items |

Paillier linear PIR is correct — `Πᵢ E(qᵢ)^(bucket[i][j]) = E(bucket[target][j])` — but scales linearly. The original RLWE-based approach uses multi-level recursion to achieve sublinear complexity.

### 4. Missing Features

| Feature | Notes |
|---|---|
| AEAD value encryption (AES-SIV/GCM-256) | Bucket contents are raw hashes, not encrypted |
| Two-level bucket scheme (hashed + encrypted) | Single-level only |
| Non-sensitive + sensitive ID separation | All items treated uniformly |
| Batch queries | One item per query |
| Protocol Buffers for serialization | Python objects used directly |
| Cryptographically secure RNG | Uses Python's `random` module, not `secrets` |
| Constant-time guarantees | Vulnerable to timing side-channels |

## Why?
Because I wanted to understand the implementation without all the google / bazel bullshit
