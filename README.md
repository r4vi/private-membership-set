# `pmset` — Canonical Python Private Set Membership Library

[![License](https://img.shields.io/badge/license-WTFPL-brightgreen.svg)](LICENSE)

`pmset` is a modular, cryptographically sound, transport-agnostic Python library for **Private Set Membership (PSM / PMSet)** — enabling a client to check whether an element belongs to a server's private set (and optionally retrieve an AEAD-encrypted associated payload) without:

1. The server learning what item the client queried (**Client Query Privacy**).
2. The server learning whether the query was a member (**Result Privacy**).
3. The client learning anything about non-queried items in the server's set (**Server Privacy**).

Every concrete implementation adheres to a single generic protocol interface and ships with **machine-checked formal verification** across **Z3 (SMT)**, **TLA+ (TLC model checker)**, and **Lean 4 (kernel-checked proofs with 0 `sorry` and 0 custom axioms)**.

---

## Architecture

### 1. Generic Protocol Interface (`pmset.core`)

Every PMSet scheme — whether 1-round homomorphic polynomial evaluation, 2-round OPRF + PIR, OT + Garbled Bloom Filter, Post-Quantum RLWE Lattice PIR, or $k$-server non-colluding PIR — implements the exact same transport-agnostic state machine:

```python
import pmset

proto = pmset.get_protocol("oprf_rlwe_pir")  # or any of the 12 registered protocols
server = proto.create_server({
    "alice@example.com": b"tier=gold",
    "bob@example.com": b"tier=silver",
})

# PublicParams serialize deterministically to canonical binary wire frames (no pickle)
params = pmset.PublicParams.from_bytes(server.public_params().to_bytes())
client = proto.create_client(params)

# High-level convenience API
result = client.query_detailed(server, "alice@example.com", verify_wire_roundtrip=True)
assert result.is_member is True
assert result.payload == b"tier=gold"

# Or transport-agnostic step-by-step session (HTTP / gRPC / sockets)
session = client.start_query("eve@example.com")
while not session.is_complete:
    req_bytes = session.next_request().to_bytes()
    resp_bytes = server.handle_request(pmset.ProtocolMessage.from_bytes(req_bytes)).to_bytes()
    session.process_response(pmset.ProtocolMessage.from_bytes(resp_bytes))
assert session.result().is_member is False
```

Core contracts enforced across all protocols:
- **Stateless Server**: `PMSetServer.handle_request` never stores per-client state; interleaved or concurrent client sessions never interfere.
- **Canonical Wire Serialization**: Every `PublicParams` and `ProtocolMessage` serializes deterministically via a pickle-free tagged binary codec (`pmset.core.serialization`).
- **Strict Multi-Server Isolation**: Multi-server protocols expose independent `PMSetServerReplica` objects via `MultiServerPMSetServer.replicas`, with isolated per-replica wire payloads.
- **Pluggable Registry**: Implement `PMSetProtocol`, `PMSetServer`, `PMSetClient`, `PMSetSession` and call `pmset.register_protocol(...)` to plug in custom techniques.

### 2. Composable Cryptographic Primitives (`pmset.primitives`)

| Primitive Family | Generic ABC | Concrete Implementations |
|---|---|---|
| **OPRF** | `OPRF` | `ECDHOPRF` (NIST P-256, RFC 9497 style), `DHOPRF` (safe-prime prime-order subgroup $G_q$), `RSAOPRF` (Chaum blind-RSA) |
| **Single-Server PIR** | `SingleServerPIR` | `PaillierLinearPIR` (1D), `Paillier2DPIR` ($O(\sqrt{B})$ upload), `RLWEPIR` (Ring-LWE over $R_q = \mathbb{Z}_q[X]/(X^N+1)$) |
| **Multi-Server PIR** | `MultiServerPIR` | `TwoServerDPFPIR` (Boyle-Gilboa-Ishai BGI15 PRG-tree FSS, $O(\log B)$ upload), `ShamirMultiServerPIR` (CGKS $t$-private $k$-server IT-PIR) |
| **Additive HE** | `AdditiveHE` | `PaillierHE` (CSPRNG + fast $(n+1)^m$ encryption), `ExponentialElGamalHE` (NIST P-256 zero-testing) |
| **Lattice HE** | — | `RLWEContext` / `RLWEParams` (negacyclic convolution, CBD noise, exact noise-budget analyzer) |
| **Oblivious Transfer** | `ObliviousTransfer` | `ChouOrlandiOT` (1-round reusable-setup 1-out-of-2 ECDH OT on P-256) |
| **Indexing & AEAD** | `Bucketizer` | `PrefixBucketizer` (Google PSM top-$N$-bits + AES-256-GCM AEAD), `ModuloBucketizer`, `CuckooTable` (PSZ14 2-hash + stash), `BloomFilter`, `GarbledBloomFilter` (DCW13) |

---

## Concrete PMSet Implementations (12 Protocols)

| Protocol Name | Technique / Family | Rounds | Payloads | Servers | Key Assumptions |
|---|---|---:|:---:|---:|---|
| `oprf_rlwe_pir` | P-256 ECDH-OPRF + Prefix Buckets + **RLWE Lattice PIR** (Google PSM-RLWE) | 2 | Yes | 1 | DDH (P-256), Ring-LWE (PQ PIR), RO |
| `ecdh_oprf_paillier_pir` | P-256 ECDH-OPRF + Prefix Buckets + Paillier 1D PIR + AEAD | 2 | Yes | 1 | DDH (P-256), DCR (Paillier), RO |
| `ecdh_oprf_paillier_2d_pir` | P-256 ECDH-OPRF + Prefix Buckets + **Paillier 2D $\sqrt{B}$ PIR** + AEAD | 2 | Yes | 1 | DDH (P-256), DCR (Paillier), RO |
| `dh_oprf_paillier_pir` | Safe-Prime Subgroup DH-OPRF + Paillier 1D PIR + AEAD | 2 | Yes | 1 | DDH ($G_q$), DCR (Paillier), RO |
| `rsa_oprf_paillier_pir` | **Chaum Blind-RSA OPRF** + Prefix Buckets + Paillier PIR + AEAD | 2 | Yes | 1 | RSA One-More Inv., DCR, RO |
| `cuckoo_oprf_pir` | **Cuckoo Hashing (PSZ14)** + P-256 ECDH-OPRF + 2-Slot RLWE PIR | 2 | Yes | 1 | DDH (P-256), Ring-LWE, RO |
| `fnp_paillier` | **FNP04 Oblivious Polynomial Evaluation** (Paillier HE) | 1 | No | 1 | DCR (Paillier), CRHF |
| `elgamal_equality` | **Exponential ElGamal Shuffled Zero-Test** (P-256) | 1 | No | 1 | DDH (P-256), CRHF |
| `ecdh_oprf_filter` | **Amortized $O(1)$ ECDH-OPRF + Compact Encrypted Set / Bloom Filter** | 1 | Yes | 1 | One-More DDH (P-256), RO |
| `ot_garbled_bloom` | **DCW13 Garbled Bloom Filter + Chou-Orlandi 1-out-of-2 OT** (no HE) | 1 | No | 1 | CDH (P-256), RO |
| `two_server_dpf_pir` | **2-Server BGI15 DPF/FSS PRG-Tree PIR** + P-256 ECDH-OPRF ($O(\log B)$ upload) | 2 | Yes | 2 | 2 Non-Colluding Servers, PRG, DDH |
| `shamir_multiserver_pir` | **$k$-Server $t$-Private Shamir IT-PIR (CGKS)** + P-256 ECDH-OPRF | 2 | Yes | $k \ge 2$ | $\le t$ Colluding Servers (IT PIR), DDH |

---

## Formal Verification (Z3, TLA+, and Lean 4)

Every concrete protocol in `pmset` is formally verified by three complementary verification engines through the unified `pmset.verification` API and CLI:

1. **Z3 SMT Solver (`pmset.verification.Z3Verifier`)**:
   - Proves algebraic completeness, soundness, blinding/query indistinguishability, server-set privacy (non-member uniform masking), Chou-Orlandi OT key agreement & IT choice privacy, 128-bit GBF XOR secret-sharing recovery, 2-server DPF XOR reconstruction & single-replica secrecy, Shamir Lagrange recovery & $t$-privacy, and **exact RLWE decryption rounding + noise-budget safety** via refutation (`z3.unsat`).
2. **TLA+ / TLC Model Checker (`verification/tla/*.tla`, `pmset.verification.TLAVerifier`)**:
   - Exhaustively model-checks 9 formal specifications (`PMSetGeneric`, `OPRFPIR`, `CuckooOPRFPIR`, `FNPPaillier`, `ElGamalEquality`, `OPRFFilter`, `OTGarbledBloom`, `TwoServerDPFPIR`, `ShamirMultiServerPIR`) for `TypeOK`, `StatelessServer`, `MembershipCorrectness`, `BlindingPrivacy`, `OTChoicePrivacy`, `SingleReplicaPrivacy`, and `SingleServerITPrivacy` with **0 errors**.
3. **Lean 4 Kernel-Checked Proofs (`verification/lean/PMSet/`, `pmset.verification.LeanVerifier`)**:
   - Machine-checked theorems in pure Lean 4 (`PMSet/Basic.lean`, `PMSet/OPRF.lean`, `PMSet/PIR.lean`, `PMSet/Protocols.lean`) covering all 12 protocols, including `rlwe_rounding_exact`, `dpf_two_server_pir_correct`, `shamir_pir_correct`, `fnp_paillier_correct`, `cuckoo_oprf_pir_correct`, `chou_orlandi_ot_correct`, and `chou_orlandi_ot_receiver_private`, verified by `lake build` with **0 `sorry`s and 0 custom axioms**.

### Running Formal Verification

```bash
# Programmatic API
python -c "import pmset; print(pmset.verify_protocol('oprf_rlwe_pir')['z3'].summary())"

# CLI — verify a single protocol or all 12 across Z3, TLA+, and Lean 4
pmset verify --backend z3
pmset verify --backend tla
pmset verify --backend lean
pmset verify --backend all
```

---

## Installation & Usage

```bash
# Install package with cryptographic acceleration (AES-GCM) and Z3 verifier
uv pip install -e ".[dev]"

# Explore protocols, run live demos, and benchmark all 12 implementations
pmset list
pmset demo -p oprf_rlwe_pir
pmset benchmark --size 16

# Run the full test & formal verification suite
pytest
```

### Backward Compatibility

The legacy `private_membership.py` module (`PSMServer`, `PSMClient`, `DHOPRF`, `Paillier`, `is_prime`, `OPRF_PRIME`) is preserved as a thin facade backed by `pmset`'s CSPRNG primitives so existing scripts and tests continue working unchanged.

---

## Security Disclaimer

While `pmset` upgrades every cryptographic primitive from the original educational toy (using `secrets` CSPRNG, NIST P-256 prime-order groups, safe-prime prime-order subgroups, AES-256-GCM AEAD, Ring-LWE noise-budget enforcement, and formal verification), Python's arbitrary-precision integer arithmetic is **not constant-time** and therefore cannot defend against local timing side-channel attacks. For production deployment with strict side-channel resistance, pair the protocol interfaces with constant-time native backends.

## References

- Google Private Membership (PSM-RLWE): https://github.com/google/private-membership
- Freedman, Nissim, Pinkas — *Efficient Private Matching and Set Intersection* (EUROCRYPT 2004)
- Dong, Chen, Wen — *When Private Set Intersection Meets Big Data* (ACM CCS 2013)
- Pinkas, Schneider, Zohner — *Faster Private Set Intersection Based on OT Extension* (USENIX Security 2014)
- Chou, Orlandi — *The Simplest Protocol for Oblivious Transfer* (LATINCRYPT 2015)
- Boyle, Gilboa, Ishai — *Function Secret Sharing* (EUROCRYPT 2015 / CCS 2016)
- Chor, Goldreich, Kushilevitz, Sudan — *Private Information Retrieval* (FOCS 1995)
- RFC 9497 — *Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups*
- RFC 9474 — *RSA Blind Signatures*
