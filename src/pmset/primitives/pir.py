"""Private Information Retrieval (PIR) primitives: Single-Server & Multi-Server.

Implements five genuinely distinct PIR algorithms over fixed-size byte buckets:
  1. :class:`PaillierLinearPIR`: 1D Paillier additive HE scan, O(B) upload.
  2. :class:`Paillier2DPIR`: 2D sqrt(B)xsqrt(B) Paillier PIR, O(sqrt(B)) upload.
  3. :class:`RLWEPIR`: Post-quantum Ring-LWE lattice PIR over R_q = Z_q[X]/(X^N+1).
  4. :class:`TwoServerDPFPIR`: 2-server Boyle-Gilboa-Ishai (BGI15) Distributed
     Point Function (FSS) PRG-tree PIR, O(log B) upload!
  5. :class:`ShamirMultiServerPIR`: k-server t-private Information-Theoretic
     Chor-Goldreich-Kushilevitz-Sudan (CGKS) Shamir secret-sharing PIR!
"""

from __future__ import annotations

import math
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Sequence

from pmset.primitives.he import PaillierHE, PaillierPublicKey
from pmset.primitives.math_utils import (
    lagrange_coefficients_at_zero,
    prg_expand,
    shamir_share,
)
from pmset.primitives.rlwe import RLWECiphertext, RLWEContext, RLWEParams


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _chunk_bytes_to_ints(data: bytes, chunk_size: int) -> list[int]:
    if not data:
        return [0]
    return [
        int.from_bytes(data[i : i + chunk_size], "big")
        for i in range(0, len(data), chunk_size)
    ]


def _ints_to_bytes(values: Sequence[int], chunk_size: int, total_len: int) -> bytes:
    if total_len == 0:
        return b""
    out = bytearray()
    remaining = total_len
    for val in values:
        take = min(chunk_size, remaining)
        out.extend(val.to_bytes(take, "big"))
        remaining -= take
        if remaining == 0:
            break
    return bytes(out)


class SingleServerPIR(ABC):
    """Generic interface for single-server computational PIR over uniform-length buckets."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical PIR scheme name."""

    @abstractmethod
    def public_params(self) -> dict[str, Any]:
        """Public PIR parameters shared by server and client."""

    @abstractmethod
    def client_generate_query(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[str, Any], Any]:
        """Generate a wire query and secret client state for ``target_index``."""

    @abstractmethod
    def server_answer(
        self, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        """Evaluate the PIR query against ``buckets`` (all equal byte length)."""

    @abstractmethod
    def client_extract(
        self, response: dict[str, Any], client_state: Any, bucket_byte_len: int
    ) -> bytes:
        """Decrypt/extract the target bucket bytes from ``response``."""


class PaillierLinearPIR(SingleServerPIR):
    """1D Linear PIR using Paillier additive homomorphic encryption."""

    def __init__(self, key_bits: int = 512) -> None:
        self.key_bits = key_bits
        self._he: PaillierHE | None = None

    @property
    def name(self) -> str:
        return "paillier-linear"

    def public_params(self) -> dict[str, Any]:
        return {"pir": self.name, "key_bits": self.key_bits}

    def _get_he(self) -> PaillierHE:
        if self._he is None:
            self._he = PaillierHE(bits=self.key_bits)
        return self._he

    def client_generate_query(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not (0 <= target_index < num_buckets):
            raise ValueError(f"target_index {target_index} out of range [0, {num_buckets})")
        he = self._get_he()
        vec = [he.encrypt(1 if i == target_index else 0) for i in range(num_buckets)]
        return {"n": he.n, "vector": vec}, {"he": he}

    def server_answer(
        self, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        num_buckets = len(buckets)
        vec = query["vector"]
        if len(vec) != num_buckets:
            raise ValueError(
                f"PIR query length mismatch: got {len(vec)}, expected {num_buckets}"
            )
        pk = PaillierPublicKey(n=int(query["n"]))
        # Reserve 1 byte of headroom so each chunk is strictly < n
        chunk_size = max(1, (pk.n.bit_length() - 8) // 8)
        bucket_len = len(buckets[0]) if buckets else 0
        encoded = [_chunk_bytes_to_ints(b, chunk_size) for b in buckets]
        num_chunks = len(encoded[0]) if encoded else 0

        response_chunks: list[int] = []
        for j in range(num_chunks):
            acc = 1  # E(0) with r=1
            for i in range(num_buckets):
                val = encoded[i][j]
                acc = pk.add(acc, pk.mul_scalar(vec[i], val))
            response_chunks.append(acc)
        return {
            "chunks": response_chunks,
            "chunk_size": chunk_size,
            "bucket_len": bucket_len,
        }

    def client_extract(
        self, response: dict[str, Any], client_state: dict[str, Any], bucket_byte_len: int
    ) -> bytes:
        he: PaillierHE = client_state["he"]
        chunk_size = int(response["chunk_size"])
        decrypted = [he.decrypt(c) for c in response["chunks"]]
        return _ints_to_bytes(decrypted, chunk_size, bucket_byte_len)


class Paillier2DPIR(SingleServerPIR):
    """2D Square-Root Paillier PIR with O(sqrt(B)) client upload complexity.

    Arranges ``B`` buckets into an ``R x C`` matrix with ``R = ceil(sqrt(B))``.
    Client sends only ``R`` encrypted row-selection indicators; Server computes
    the selected row of ``C`` encrypted buckets; Client decrypts column ``c*``.
    """

    def __init__(self, key_bits: int = 512) -> None:
        self.key_bits = key_bits
        self._he: PaillierHE | None = None

    @property
    def name(self) -> str:
        return "paillier-2d"

    def public_params(self) -> dict[str, Any]:
        return {"pir": self.name, "key_bits": self.key_bits}

    def _get_he(self) -> PaillierHE:
        if self._he is None:
            self._he = PaillierHE(bits=self.key_bits)
        return self._he

    @staticmethod
    def _grid_dims(num_buckets: int) -> tuple[int, int]:
        rows = max(1, math.isqrt(num_buckets))
        if rows * rows < num_buckets:
            rows += 1
        cols = math.ceil(num_buckets / rows)
        return rows, cols

    def client_generate_query(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not (0 <= target_index < num_buckets):
            raise ValueError(f"target_index {target_index} out of range [0, {num_buckets})")
        rows, cols = self._grid_dims(num_buckets)
        target_row = target_index // cols
        target_col = target_index % cols
        he = self._get_he()
        row_vec = [he.encrypt(1 if r == target_row else 0) for r in range(rows)]
        return (
            {"n": he.n, "row_vector": row_vec, "rows": rows, "cols": cols},
            {"he": he, "target_col": target_col},
        )

    def server_answer(
        self, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        num_buckets = len(buckets)
        rows, cols = self._grid_dims(num_buckets)
        row_vec = query["row_vector"]
        if len(row_vec) != rows or int(query["cols"]) != cols:
            raise ValueError(
                f"2D PIR grid mismatch: got {len(row_vec)}x{query['cols']}, expected {rows}x{cols}"
            )
        pk = PaillierPublicKey(n=int(query["n"]))
        chunk_size = max(1, (pk.n.bit_length() - 8) // 8)
        bucket_len = len(buckets[0]) if buckets else 0
        zero_bucket = b"\x00" * bucket_len
        padded = list(buckets) + [zero_bucket] * (rows * cols - num_buckets)
        encoded = [_chunk_bytes_to_ints(b, chunk_size) for b in padded]
        num_chunks = len(encoded[0]) if encoded else 0

        # Return encrypted selected row: list of cols, each having num_chunks ciphertexts
        selected_row: list[list[int]] = []
        for c in range(cols):
            col_chunks: list[int] = []
            for j in range(num_chunks):
                acc = 1
                for r in range(rows):
                    val = encoded[r * cols + c][j]
                    acc = pk.add(acc, pk.mul_scalar(row_vec[r], val))
                col_chunks.append(acc)
            selected_row.append(col_chunks)
        return {
            "selected_row": selected_row,
            "chunk_size": chunk_size,
            "bucket_len": bucket_len,
        }

    def client_extract(
        self, response: dict[str, Any], client_state: dict[str, Any], bucket_byte_len: int
    ) -> bytes:
        he: PaillierHE = client_state["he"]
        target_col: int = client_state["target_col"]
        chunk_size = int(response["chunk_size"])
        col_chunks = response["selected_row"][target_col]
        decrypted = [he.decrypt(c) for c in col_chunks]
        return _ints_to_bytes(decrypted, chunk_size, bucket_byte_len)


class RLWEPIR(SingleServerPIR):
    """Post-Quantum Ring-LWE Lattice PIR over R_q = Z_q[X]/(X^N + 1).

    Each bucket is packed into ceil(bucket_len / N) plaintext polynomials in R_t
    (t = 256 => N bytes per polynomial). The client sends B encrypted constant
    indicator polynomials Enc(1[i == alpha]), and the server evaluates the
    homomorphic negacyclic polynomial inner product in branchless C.
    """

    def __init__(self, params: RLWEParams | None = None) -> None:
        self.params = params or RLWEParams()
        self._ctx: RLWEContext | None = None

    @property
    def name(self) -> str:
        return "rlwe-lattice"

    def public_params(self) -> dict[str, Any]:
        return {"pir": self.name, "rlwe": self.params.to_dict()}

    def _get_ctx(self) -> RLWEContext:
        if self._ctx is None:
            self._ctx = RLWEContext(self.params)
        return self._ctx

    def client_generate_query(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not (0 <= target_index < num_buckets):
            raise ValueError(f"target_index {target_index} out of range [0, {num_buckets})")
        if not self.params.can_decrypt_exact(num_buckets):
            raise ValueError(
                f"RLWE noise budget exceeded for num_buckets={num_buckets} with {self.params}"
            )
        ctx = self._get_ctx()
        cts = [ctx.encrypt_scalar(1 if i == target_index else 0).to_wire() for i in range(num_buckets)]
        return {"rlwe": self.params.to_dict(), "ciphertexts": cts}, {"ctx": ctx}

    def server_answer(
        self, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        from pmset.native import ct_rlwe_pir_dot

        num_buckets = len(buckets)
        cts_raw = query["ciphertexts"]
        if len(cts_raw) != num_buckets:
            raise ValueError(
                f"RLWE PIR query length mismatch: got {len(cts_raw)}, expected {num_buckets}"
            )
        params = RLWEParams.from_dict(query["rlwe"])
        evaluator = RLWEContext.evaluator_only(params)
        cts = [RLWECiphertext.from_wire(c) for c in cts_raw]
        encoded_buckets = [evaluator.encode_bytes_to_polys(b) for b in buckets]
        num_chunks = len(encoded_buckets[0]) if encoded_buckets else 0

        ct_a_list = [ct.a for ct in cts]
        ct_b_list = [ct.b for ct in cts]
        resp_chunks: list[tuple[list[int], list[int]]] = []
        for j in range(num_chunks):
            pt_list = [encoded_buckets[i][j] for i in range(num_buckets)]
            native_dot = ct_rlwe_pir_dot(ct_a_list, ct_b_list, pt_list, params.q)
            if native_dot is not None:
                resp_chunks.append(native_dot)
            else:
                acc = evaluator.zero_ciphertext()
                for i in range(num_buckets):
                    term = evaluator.mul_plaintext_poly(cts[i], pt_list[i])
                    acc = evaluator.add(acc, term)
                resp_chunks.append(acc.to_wire())
        return {"chunks": resp_chunks}

    def client_extract(
        self, response: dict[str, Any], client_state: dict[str, Any], bucket_byte_len: int
    ) -> bytes:
        ctx: RLWEContext = client_state["ctx"]
        polys = [ctx.decrypt_poly(RLWECiphertext.from_wire(c)) for c in response["chunks"]]
        return ctx.decode_polys_to_bytes(polys, bucket_byte_len)


# ---------------------------------------------------------------------------
# Multi-Server PIR Primitives (2-Server BGI15 DPF/FSS & k-Server Shamir IT-PIR)
# ---------------------------------------------------------------------------


class MultiServerPIR(ABC):
    """Generic interface for k-server non-colluding PIR."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical multi-server PIR name."""

    @property
    @abstractmethod
    def num_servers(self) -> int:
        """Number of independent non-colluding servers required."""

    @abstractmethod
    def client_generate_queries(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[int, dict[str, Any]], Any]:
        """Generate per-server isolated queries ``{server_id: query}`` and local state."""

    @abstractmethod
    def server_answer(
        self, server_id: int, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        """Evaluate replica ``server_id``'s isolated share over ``buckets``."""

    @abstractmethod
    def client_combine(
        self,
        responses: dict[int, dict[str, Any]],
        client_state: Any,
        bucket_byte_len: int,
    ) -> bytes:
        """Reconstruct the target bucket from all server responses."""


@dataclass(frozen=True)
class DPFKey:
    """Compact O(log B) key for a 2-party Distributed Point Function (BGI15)."""

    party_id: int  # 0 or 1
    depth: int  # domain size = 2^depth
    root_seed: bytes  # 16 bytes
    root_t: int  # 0 or 1 (root control bit)
    cw_seeds: tuple[bytes, ...]  # depth correction word seeds (16 bytes each)
    cw_tl: tuple[int, ...]  # depth left control-bit corrections
    cw_tr: tuple[int, ...]  # depth right control-bit corrections
    cw_final: int  # final 1-bit output correction word

    def to_dict(self) -> dict[str, Any]:
        return {
            "party_id": self.party_id,
            "depth": self.depth,
            "root_seed": self.root_seed,
            "root_t": self.root_t,
            "cw_seeds": list(self.cw_seeds),
            "cw_tl": list(self.cw_tl),
            "cw_tr": list(self.cw_tr),
            "cw_final": self.cw_final,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DPFKey:
        return cls(
            party_id=int(data["party_id"]),
            depth=int(data["depth"]),
            root_seed=bytes(data["root_seed"]),
            root_t=int(data["root_t"]),
            cw_seeds=tuple(bytes(s) for s in data["cw_seeds"]),
            cw_tl=tuple(int(x) for x in data["cw_tl"]),
            cw_tr=tuple(int(x) for x in data["cw_tr"]),
            cw_final=int(data["cw_final"]),
        )


def _dpf_prg(seed: bytes) -> tuple[bytes, int, bytes, int]:
    """Length-doubling PRG: 16B seed -> (sL:16B, tL:1b, sR:16B, tR:1b)."""
    raw = prg_expand(seed, 34, domain=b"PMSET-BGI15-DPF")
    sL = raw[0:16]
    tL = raw[16] & 1
    sR = raw[17:33]
    tR = raw[33] & 1
    return sL, tL, sR, tR


def dpf_gen(alpha: int, depth: int) -> tuple[DPFKey, DPFKey]:
    """Boyle-Gilboa-Ishai (2015) DPF key generation for point function f_{alpha, 1}.

    Produces two compact keys (k0, k1) of size O(depth) such that for all
    x in [0, 2^depth):
        dpf_eval(k0, x) XOR dpf_eval(k1, x) == (1 if x == alpha else 0)
    while each individual key reveals nothing about alpha (PRG security).
    """
    if depth < 1:
        raise ValueError(f"DPF depth must be >= 1, got {depth}")
    if not (0 <= alpha < (1 << depth)):
        raise ValueError(f"alpha={alpha} out of range [0, {1 << depth})")

    s0 = secrets.token_bytes(16)
    s1 = secrets.token_bytes(16)
    t0 = 0
    t1 = 1
    root_s0, root_s1 = s0, s1

    cw_seeds: list[bytes] = []
    cw_tl: list[int] = []
    cw_tr: list[int] = []

    from pmset.native import ct_cond_xor_bytes, ct_select_bytes, ct_xor_bytes

    for level in range(depth):
        alpha_bit = (alpha >> (depth - 1 - level)) & 1
        s0L, t0L, s0R, t0R = _dpf_prg(s0)
        s1L, t1L, s1R, t1R = _dpf_prg(s1)

        # Branchless Keep/Lose selection on secret alpha_bit (ZERO if alpha_bit == 0 branch!)
        s0_keep = ct_select_bytes(s0L, s0R, alpha_bit)
        s1_keep = ct_select_bytes(s1L, s1R, alpha_bit)
        s0_lose = ct_select_bytes(s0R, s0L, alpha_bit)
        s1_lose = ct_select_bytes(s1R, s1L, alpha_bit)
        s_cw = ct_xor_bytes(s0_lose, s1_lose)

        t_cw_L = t0L ^ t1L ^ alpha_bit ^ 1
        t_cw_R = t0R ^ t1R ^ alpha_bit
        t0_keep = (t0L & (alpha_bit ^ 1)) | (t0R & alpha_bit)
        t1_keep = (t1L & (alpha_bit ^ 1)) | (t1R & alpha_bit)
        t_cw_keep = (t_cw_L & (alpha_bit ^ 1)) | (t_cw_R & alpha_bit)

        s0 = ct_cond_xor_bytes(s0_keep, s_cw, t0)
        s1 = ct_cond_xor_bytes(s1_keep, s_cw, t1)
        t0 = t0_keep ^ (t0 & t_cw_keep)
        t1 = t1_keep ^ (t1 & t_cw_keep)

        cw_seeds.append(s_cw)
        cw_tl.append(t_cw_L)
        cw_tr.append(t_cw_R)

    # Final 1-bit conversion: out_b(x) = (leaf_seed[0] & 1) ^ (t_b & cw_final)
    # At x = alpha: t0 ^ t1 == 1, so out_0 ^ out_1 == (s0[0]&1)^(s1[0]&1)^cw_final == 1.
    # At x != alpha: s0 == s1 and t0 == t1, so out_0 ^ out_1 == 0!
    cw_final = 1 ^ (s0[0] & 1) ^ (s1[0] & 1)

    k0 = DPFKey(0, depth, root_s0, 0, tuple(cw_seeds), tuple(cw_tl), tuple(cw_tr), cw_final)
    k1 = DPFKey(1, depth, root_s1, 1, tuple(cw_seeds), tuple(cw_tl), tuple(cw_tr), cw_final)
    return k0, k1


def dpf_eval_full(key: DPFKey, limit: int | None = None) -> list[int]:
    """Evaluate a DPF key over the full binary tree in O(2^depth) PRG calls (branchless CW apply)."""
    from pmset.native import ct_cond_xor_bytes

    domain = 1 << key.depth
    cap = domain if limit is None else min(domain, limit)
    out = [0] * cap

    def _walk(level: int, prefix: int, seed: bytes, t: int) -> None:
        subtree_size = 1 << (key.depth - level)
        if prefix >= cap:
            return
        if level == key.depth:
            out[prefix] = (seed[0] & 1) ^ (t & key.cw_final)
            return
        sL, tL, sR, tR = _dpf_prg(seed)
        s_cw = key.cw_seeds[level]
        # Branchless correction word application on control bit t
        sL = ct_cond_xor_bytes(sL, s_cw, t)
        sR = ct_cond_xor_bytes(sR, s_cw, t)
        tL ^= t & key.cw_tl[level]
        tR ^= t & key.cw_tr[level]
        half = subtree_size >> 1
        _walk(level + 1, prefix, sL, tL)
        if prefix + half < cap:
            _walk(level + 1, prefix + half, sR, tR)

    _walk(0, 0, key.root_seed, key.root_t)
    return out


class TwoServerDPFPIR(MultiServerPIR):
    """2-Server PIR powered by Boyle-Gilboa-Ishai (BGI15) Distributed Point Functions.

    Upload per server is O(log B) bytes (just one 16-byte seed + 16-byte CW per tree level)!
    """

    @property
    def name(self) -> str:
        return "two-server-dpf"

    @property
    def num_servers(self) -> int:
        return 2

    def client_generate_queries(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
        if not (0 <= target_index < num_buckets):
            raise ValueError(f"target_index {target_index} out of range [0, {num_buckets})")
        depth = max(1, (num_buckets - 1).bit_length())
        k0, k1 = dpf_gen(target_index, depth)
        return {0: {"dpf_key": k0.to_dict()}, 1: {"dpf_key": k1.to_dict()}}, {}

    def server_answer(
        self, server_id: int, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        from pmset.native import ct_dpf_bucket_eval

        key = DPFKey.from_dict(query["dpf_key"])
        if key.party_id != server_id:
            raise ValueError(f"DPF key party_id={key.party_id} sent to server {server_id}")
        bits = dpf_eval_full(key, limit=len(buckets))
        return {"share": ct_dpf_bucket_eval(buckets, bits)}

    def client_combine(
        self,
        responses: dict[int, dict[str, Any]],
        client_state: Any,
        bucket_byte_len: int,
    ) -> bytes:
        from pmset.native import ct_xor_bytes

        s0 = bytes(responses[0]["share"])
        s1 = bytes(responses[1]["share"])
        return ct_xor_bytes(s0, s1)[:bucket_byte_len]


# 257-bit prime > 2^256 for chunking 32-byte blocks in Shamir IT-PIR
_SHAMIR_PIR_PRIME = (1 << 256) + 297  # Verified prime: 2^256 + 297


class ShamirMultiServerPIR(MultiServerPIR):
    """k-Server t-Private Information-Theoretic PIR (CGKS / Shamir Secret Sharing).

    Splits the indicator vector e_alpha in F_p^B coordinate-wise using a random
    degree-t polynomial per coordinate across k >= t + 1 non-colluding servers.
    Any coalition of at most ``t`` servers learns ZERO information (information-
    theoretically) about ``target_index``.
    """

    def __init__(
        self,
        num_servers: int = 3,
        privacy_threshold: int = 1,
        prime: int = _SHAMIR_PIR_PRIME,
    ) -> None:
        if privacy_threshold < 1:
            raise ValueError("privacy_threshold t must be >= 1")
        if num_servers <= privacy_threshold:
            raise ValueError(
                f"Need num_servers ({num_servers}) > privacy_threshold ({privacy_threshold})"
            )
        self._num_servers = num_servers
        self.privacy_threshold = privacy_threshold  # t: max colluding servers
        self.reconstruction_threshold = privacy_threshold + 1  # t + 1
        self.prime = prime
        self.chunk_size = (prime.bit_length() - 1) // 8  # 32 bytes for 257-bit prime

    @property
    def name(self) -> str:
        return f"shamir-it-pir-{self._num_servers}of{self.privacy_threshold}"

    @property
    def num_servers(self) -> int:
        return self._num_servers

    def client_generate_queries(
        self, target_index: int, num_buckets: int
    ) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
        if not (0 <= target_index < num_buckets):
            raise ValueError(f"target_index {target_index} out of range [0, {num_buckets})")
        xs = list(range(1, self._num_servers + 1))
        per_server_vecs: dict[int, list[int]] = {sid: [] for sid in range(self._num_servers)}
        for i in range(num_buckets):
            secret = 1 if i == target_index else 0
            shares = shamir_share(
                secret,
                num_shares=self._num_servers,
                threshold=self.reconstruction_threshold,
                prime=self.prime,
                xs=xs,
            )
            for sid, (_, y) in enumerate(shares):
                per_server_vecs[sid].append(y)
        queries = {
            sid: {"x": xs[sid], "vector": per_server_vecs[sid]}
            for sid in range(self._num_servers)
        }
        return queries, {"xs": xs}

    def server_answer(
        self, server_id: int, buckets: Sequence[bytes], query: dict[str, Any]
    ) -> dict[str, Any]:
        vec = query["vector"]
        if len(vec) != len(buckets):
            raise ValueError(
                f"Shamir PIR query length mismatch: got {len(vec)}, expected {len(buckets)}"
            )
        p = self.prime
        encoded = [_chunk_bytes_to_ints(b, self.chunk_size) for b in buckets]
        num_chunks = len(encoded[0]) if encoded else 0
        out_chunks: list[int] = []
        for j in range(num_chunks):
            acc = 0
            for i in range(len(buckets)):
                acc = (acc + vec[i] * encoded[i][j]) % p
            out_chunks.append(acc)
        return {"x": int(query["x"]), "chunks": out_chunks}

    def client_combine(
        self,
        responses: dict[int, dict[str, Any]],
        client_state: dict[str, Any],
        bucket_byte_len: int,
    ) -> bytes:
        ordered = sorted(responses.items())[: self.reconstruction_threshold]
        xs = [int(resp["x"]) for _, resp in ordered]
        weights = lagrange_coefficients_at_zero(xs, self.prime)
        num_chunks = len(ordered[0][1]["chunks"])
        recovered: list[int] = []
        for j in range(num_chunks):
            acc = 0
            for (_, resp), w in zip(ordered, weights):
                acc = (acc + resp["chunks"][j] * w) % self.prime
            recovered.append(acc)
        return _ints_to_bytes(recovered, self.chunk_size, bucket_byte_len)
