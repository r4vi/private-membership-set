"""Set indexing and bucketization data structures for PMSet protocols.

Provides:
  1. :class:`PrefixBucketizer`: Google PSM's top-N-bits prefix bucketization with
     uniform dummy padding and optional AES-256-GCM AEAD encrypted records.
  2. :class:`ModuloBucketizer`: Modulo-based bucketization with uniform padding.
  3. :class:`CuckooHashTable`: 2-hash Cuckoo table (PSZ14) with 1 entry per slot
     and bounded stash, avoiding bucket padding blowup.
  4. :class:`BloomFilter`: Standard space-efficient Bloom filter.
  5. :class:`GarbledBloomFilter`: Dong-Chen-Wen (2013) XOR-secret-shared Bloom
     filter for OT-based Private Set Membership.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping, Sequence

from pmset.primitives.aead import DecryptionError, aead_decrypt, aead_encrypt
from pmset.primitives.math_utils import hkdf_sha256

_TAG_LEN = 16  # 128-bit truncated OPRF lookup tag


def derive_bucket_and_keys(
    oprf_output: bytes, *, bucket_count: int, mode: str = "prefix"
) -> tuple[int, bytes, bytes]:
    """Derive ``(bucket_idx, lookup_tag_16B, aead_key_32B)`` from a 32-byte OPRF output."""
    val = int.from_bytes(oprf_output, "big")
    if mode == "prefix":
        # Google PSM style: use top bits of the hash
        if bucket_count & (bucket_count - 1) == 0:
            bits = bucket_count.bit_length() - 1
            bucket_idx = (val >> (256 - bits)) if bits > 0 else 0
        else:
            # Uniform reduction of top 64 bits for arbitrary bucket_count
            bucket_idx = (val >> 192) % bucket_count
    elif mode == "modulo":
        bucket_idx = val % bucket_count
    else:
        raise ValueError(f"Unknown bucketization mode: {mode!r}")

    tag = hkdf_sha256(oprf_output, _TAG_LEN, info=b"pmset-lookup-tag")
    aead_key = hkdf_sha256(oprf_output, 32, info=b"pmset-aead-key")
    return bucket_idx, tag, aead_key


def _pack_record(tag: bytes, encrypted_payload: bytes, max_ct_len: int) -> bytes:
    """Pack a fixed-length record: tag (16B) || ct_len (2B) || padded_ct."""
    if len(encrypted_payload) > max_ct_len:
        raise ValueError("Encrypted payload exceeds max_ct_len")
    pad_len = max_ct_len - len(encrypted_payload)
    return (
        tag
        + len(encrypted_payload).to_bytes(2, "big")
        + encrypted_payload
        + secrets.token_bytes(pad_len)
    )


def _unpack_records(bucket_bytes: bytes, record_size: int) -> list[tuple[bytes, bytes]]:
    if record_size == 0 or not bucket_bytes:
        return []
    out: list[tuple[bytes, bytes]] = []
    for off in range(0, len(bucket_bytes), record_size):
        rec = bucket_bytes[off : off + record_size]
        tag = rec[:_TAG_LEN]
        ct_len = int.from_bytes(rec[_TAG_LEN : _TAG_LEN + 2], "big")
        ct = rec[_TAG_LEN + 2 : _TAG_LEN + 2 + ct_len]
        out.append((tag, ct))
    return out


@dataclass(frozen=True)
class BuiltBuckets:
    """Uniformly padded buckets ready for PIR."""

    buckets: tuple[bytes, ...]
    bucket_count: int
    records_per_bucket: int
    record_size: int
    use_aead: bool
    mode: str

    @property
    def bucket_byte_len(self) -> int:
        return len(self.buckets[0]) if self.buckets else 0


class Bucketizer(ABC):
    """Generic interface for mapping OPRF outputs into uniform-size PIR buckets."""

    @property
    @abstractmethod
    def mode(self) -> str:
        """Bucketization strategy identifier ('prefix' or 'modulo')."""

    @abstractmethod
    def build(
        self,
        oprf_entries: Mapping[bytes, bytes | None],
        bucket_count: int,
        *,
        use_aead: bool = True,
    ) -> BuiltBuckets:
        """Group ``{oprf_output: optional_payload}`` into uniformly padded byte buckets."""

    @abstractmethod
    def bucket_index(self, oprf_output: bytes, bucket_count: int) -> int:
        """Determine the bucket index for ``oprf_output``."""

    @abstractmethod
    def lookup_in_bucket(
        self,
        bucket_bytes: bytes,
        oprf_output: bytes,
        *,
        record_size: int,
        use_aead: bool,
    ) -> tuple[bool, bytes | None]:
        """Check whether ``oprf_output`` is present in ``bucket_bytes`` (and decrypt payload)."""


class _BaseBucketizer(Bucketizer):
    _mode: str = "prefix"

    @property
    def mode(self) -> str:
        return self._mode

    def bucket_index(self, oprf_output: bytes, bucket_count: int) -> int:
        idx, _, _ = derive_bucket_and_keys(oprf_output, bucket_count=bucket_count, mode=self._mode)
        return idx

    def build(
        self,
        oprf_entries: Mapping[bytes, bytes | None],
        bucket_count: int,
        *,
        use_aead: bool = True,
    ) -> BuiltBuckets:
        if bucket_count < 1:
            raise ValueError(f"bucket_count must be >= 1, got {bucket_count}")

        raw_buckets: list[list[tuple[bytes, bytes]]] = [[] for _ in range(bucket_count)]
        max_ct_len = 0

        for oprf_out, payload in oprf_entries.items():
            idx, tag, aead_key = derive_bucket_and_keys(
                oprf_out, bucket_count=bucket_count, mode=self._mode
            )
            if use_aead:
                # Encode presence bit (0x01 if payload present else 0x00) || payload
                pt = (b"\x01" + payload) if payload is not None else b"\x00"
                ct = aead_encrypt(aead_key, pt, aad=tag)
            else:
                ct = payload if payload is not None else b""
            max_ct_len = max(max_ct_len, len(ct))
            raw_buckets[idx].append((tag, ct))

        # Ensure at least 1 dummy slot per bucket so empty server sets don't leak emptiness
        records_per_bucket = max(1, max(len(b) for b in raw_buckets))
        if use_aead and max_ct_len == 0:
            # Minimum AEAD size for a 1-byte plaintext (1B scheme + 12B nonce + 1B pt + 16B tag)
            max_ct_len = 30
        record_size = _TAG_LEN + 2 + max_ct_len

        packed_buckets: list[bytes] = []
        for b in raw_buckets:
            records = [_pack_record(tag, ct, max_ct_len) for tag, ct in b]
            while len(records) < records_per_bucket:
                # Dummy entry indistinguishable from real tag + encrypted payload
                dummy_tag = secrets.token_bytes(_TAG_LEN)
                dummy_ct = secrets.token_bytes(max_ct_len)
                records.append(_pack_record(dummy_tag, dummy_ct, max_ct_len))
            # Shuffle records inside each bucket so insertion order is hidden
            for i in range(len(records) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                records[i], records[j] = records[j], records[i]
            packed_buckets.append(b"".join(records))

        return BuiltBuckets(
            buckets=tuple(packed_buckets),
            bucket_count=bucket_count,
            records_per_bucket=records_per_bucket,
            record_size=record_size,
            use_aead=use_aead,
            mode=self._mode,
        )

    def lookup_in_bucket(
        self,
        bucket_bytes: bytes,
        oprf_output: bytes,
        *,
        record_size: int,
        use_aead: bool,
    ) -> tuple[bool, bytes | None]:
        _, target_tag, aead_key = derive_bucket_and_keys(
            oprf_output, bucket_count=1, mode=self._mode
        )
        for tag, ct in _unpack_records(bucket_bytes, record_size):
            if hmac.compare_digest(tag, target_tag):
                if use_aead:
                    try:
                        pt = aead_decrypt(aead_key, ct, aad=target_tag)
                    except DecryptionError:
                        continue
                    if pt and pt[0] == 1:
                        return True, pt[1:]
                    return True, None
                return True, (ct if ct else None)
        return False, None


class PrefixBucketizer(_BaseBucketizer):
    """Google PSM prefix-based bucketizer (uses high bits of OPRF hash)."""

    _mode = "prefix"


class ModuloBucketizer(_BaseBucketizer):
    """Modulo-based bucketizer (uses hash % bucket_count)."""

    _mode = "modulo"


# ---------------------------------------------------------------------------
# Cuckoo Hash Table (Pinkas-Schneider-Zohner PSZ14 optimization)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CuckooTable:
    """2-hash Cuckoo table where every slot holds at most 1 item, plus a tiny stash."""

    num_bins: int
    seed: bytes
    slots: tuple[bytes | None, ...]  # Each slot holds a fixed-size record or None
    stash: tuple[bytes, ...]

    @staticmethod
    def hash_positions(oprf_output: bytes, num_bins: int, seed: bytes) -> tuple[int, int]:
        h1 = int.from_bytes(
            hashlib.sha256(seed + b"\x01" + oprf_output).digest()[:8], "big"
        ) % num_bins
        h2 = int.from_bytes(
            hashlib.sha256(seed + b"\x02" + oprf_output).digest()[:8], "big"
        ) % num_bins
        if h2 == h1 and num_bins > 1:
            h2 = (h1 + 1) % num_bins
        return h1, h2

    @classmethod
    def build(
        cls,
        oprf_entries: Mapping[bytes, bytes | None],
        *,
        num_bins: int | None = None,
        use_aead: bool = True,
        max_kicks: int = 500,
    ) -> tuple[CuckooTable, int]:
        """Build a 2-hash Cuckoo table; returns ``(table, record_size)``."""
        n = len(oprf_entries)
        bins = num_bins if num_bins is not None else max(4, int(math.ceil(max(n, 1) * 2.4)))
        if bins < 2:
            bins = 2
        seed = secrets.token_bytes(16)

        # Prepare fixed-length records
        prepared: list[tuple[bytes, bytes, bytes]] = []  # (oprf_out, tag, ct)
        max_ct_len = 30 if use_aead else 0
        for oprf_out, payload in oprf_entries.items():
            _, tag, aead_key = derive_bucket_and_keys(oprf_out, bucket_count=1)
            if use_aead:
                pt = (b"\x01" + payload) if payload is not None else b"\x00"
                ct = aead_encrypt(aead_key, pt, aad=tag)
            else:
                ct = payload if payload is not None else b""
            max_ct_len = max(max_ct_len, len(ct))
            prepared.append((oprf_out, tag, ct))

        record_size = _TAG_LEN + 2 + max_ct_len
        table_keys: list[bytes | None] = [None] * bins
        table_recs: list[bytes | None] = [None] * bins
        stash: list[bytes] = []

        for oprf_out, tag, ct in prepared:
            cur_key = oprf_out
            cur_rec = _pack_record(tag, ct, max_ct_len)
            placed = False
            pos = cls.hash_positions(cur_key, bins, seed)[0]
            for _ in range(max_kicks):
                if table_keys[pos] is None:
                    table_keys[pos] = cur_key
                    table_recs[pos] = cur_rec
                    placed = True
                    break
                # Evict existing element and move it to its alternate position
                evicted_key = table_keys[pos]
                evicted_rec = table_recs[pos]
                assert evicted_key is not None and evicted_rec is not None
                table_keys[pos] = cur_key
                table_recs[pos] = cur_rec
                p1, p2 = cls.hash_positions(evicted_key, bins, seed)
                pos = p2 if pos == p1 else p1
                cur_key, cur_rec = evicted_key, evicted_rec
            if not placed:
                stash.append(cur_rec)

        # Fill empty slots with dummy indistinguishable records
        final_slots = tuple(
            rec if rec is not None else _pack_record(
                secrets.token_bytes(_TAG_LEN), secrets.token_bytes(max_ct_len), max_ct_len
            )
            for rec in table_recs
        )
        return cls(num_bins=bins, seed=seed, slots=final_slots, stash=tuple(stash)), record_size


# ---------------------------------------------------------------------------
# Standard Bloom Filter (for amortized ECDH-OPRF Filter protocol)
# ---------------------------------------------------------------------------


class BloomFilter:
    """Space-efficient Bloom filter using Kirsch-Mitzenmacher double hashing."""

    def __init__(self, num_bits: int, num_hashes: int, seed: bytes | None = None, bits: bytearray | None = None) -> None:
        if num_bits < 8:
            raise ValueError("BloomFilter num_bits must be >= 8")
        if num_hashes < 1:
            raise ValueError("BloomFilter num_hashes must be >= 1")
        self.num_bits = num_bits
        self.num_hashes = num_hashes
        self.seed = seed if seed is not None else secrets.token_bytes(16)
        byte_len = (num_bits + 7) // 8
        self.bits = bytearray(byte_len) if bits is None else bytearray(bits)

    @classmethod
    def for_capacity(cls, expected_items: int, false_positive_rate: float = 1e-6) -> BloomFilter:
        n = max(1, expected_items)
        if not (0 < false_positive_rate < 1):
            raise ValueError("false_positive_rate must be in (0, 1)")
        m = max(64, int(math.ceil(-n * math.log(false_positive_rate) / (math.log(2) ** 2))))
        k = max(1, int(round((m / n) * math.log(2))))
        return cls(num_bits=m, num_hashes=k)

    def _positions(self, item: bytes) -> list[int]:
        d = hashlib.sha256(self.seed + item).digest()
        h1 = int.from_bytes(d[:16], "big")
        h2 = int.from_bytes(d[16:], "big") | 1  # odd step for full cycle coverage
        return [(h1 + i * h2) % self.num_bits for i in range(self.num_hashes)]

    def add(self, item: bytes) -> None:
        for pos in self._positions(item):
            self.bits[pos >> 3] |= 1 << (pos & 7)

    def contains(self, item: bytes) -> bool:
        return all((self.bits[pos >> 3] >> (pos & 7)) & 1 for pos in self._positions(item))

    def to_dict(self) -> dict[str, object]:
        return {
            "num_bits": self.num_bits,
            "num_hashes": self.num_hashes,
            "seed": self.seed,
            "bits": bytes(self.bits),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> BloomFilter:
        return cls(
            num_bits=int(data["num_bits"]),  # type: ignore[arg-type]
            num_hashes=int(data["num_hashes"]),  # type: ignore[arg-type]
            seed=bytes(data["seed"]),  # type: ignore[arg-type]
            bits=bytearray(bytes(data["bits"])),  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Garbled Bloom Filter (Dong-Chen-Wen 2013)
# ---------------------------------------------------------------------------


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class GarbledBloomFilter:
    """Dong-Chen-Wen (2013) Garbled Bloom Filter for OT-based Private Set Membership.

    Each of the ``m`` array slots stores a ``lambda_bytes``-byte share (default 16B = 128b).
    For every inserted element ``s``, the XOR of its ``k`` hash positions equals
    ``tag(s) = H_tag(seed || s)``. Unassigned slots are filled with fresh CSPRNG bytes.
    False-positive probability is 2^(-8 * lambda_bytes) = 2^(-128) (cryptographically negligible).
    """

    def __init__(
        self,
        num_slots: int,
        num_hashes: int,
        seed: bytes,
        slots: tuple[bytes, ...],
        lambda_bytes: int = 16,
    ) -> None:
        self.num_slots = num_slots
        self.num_hashes = num_hashes
        self.seed = seed
        self.slots = slots
        self.lambda_bytes = lambda_bytes

    @staticmethod
    def positions(item: bytes, num_slots: int, num_hashes: int, seed: bytes) -> list[int]:
        """Compute distinct hash slot indices for ``item``."""
        seen: set[int] = set()
        out: list[int] = []
        counter = 0
        while len(out) < num_hashes:
            digest = hashlib.sha256(seed + b"POS" + counter.to_bytes(4, "big") + item).digest()
            idx = int.from_bytes(digest[:8], "big") % num_slots
            if idx not in seen:
                seen.add(idx)
                out.append(idx)
            counter += 1
        return out

    @staticmethod
    def item_tag(item: bytes, seed: bytes, lambda_bytes: int = 16) -> bytes:
        return hashlib.sha256(seed + b"TAG" + item).digest()[:lambda_bytes]

    @classmethod
    def build(
        cls,
        items: Sequence[bytes],
        *,
        num_slots: int | None = None,
        num_hashes: int = 6,
        lambda_bytes: int = 16,
    ) -> GarbledBloomFilter:
        n = len(items)
        # Ensure generous slot ratio so every element almost certainly finds an empty slot
        m = num_slots if num_slots is not None else max(32, num_hashes * max(n, 1) * 3)
        if m < num_hashes:
            raise ValueError(f"num_slots ({m}) must be >= num_hashes ({num_hashes})")

        for _attempt in range(16):
            seed = secrets.token_bytes(16)
            arr: list[bytes | None] = [None] * m
            ok = True
            for item in items:
                pos_list = cls.positions(item, m, num_hashes, seed)
                final_share = cls.item_tag(item, seed, lambda_bytes)
                empty_slot: int | None = None
                for pos in pos_list:
                    if arr[pos] is None:
                        if empty_slot is None:
                            empty_slot = pos
                        else:
                            arr[pos] = secrets.token_bytes(lambda_bytes)
                            final_share = _xor_bytes(final_share, arr[pos])  # type: ignore[arg-type]
                    else:
                        final_share = _xor_bytes(final_share, arr[pos])  # type: ignore[arg-type]
                if empty_slot is None:
                    ok = False
                    break
                arr[empty_slot] = final_share
            if ok:
                filled = tuple(
                    slot if slot is not None else secrets.token_bytes(lambda_bytes)
                    for slot in arr
                )
                return cls(
                    num_slots=m,
                    num_hashes=num_hashes,
                    seed=seed,
                    slots=filled,
                    lambda_bytes=lambda_bytes,
                )
            m = int(m * 1.5) + num_hashes
        raise RuntimeError("Failed to construct collision-free GarbledBloomFilter")

    def verify_shares(self, item: bytes, retrieved_slots: Mapping[int, bytes]) -> bool:
        """Check XOR of retrieved slot shares against the expected item tag."""
        pos_list = self.positions(item, self.num_slots, self.num_hashes, self.seed)
        acc = bytes(self.lambda_bytes)
        for pos in pos_list:
            acc = _xor_bytes(acc, retrieved_slots[pos])
        expected = self.item_tag(item, self.seed, self.lambda_bytes)
        return hmac.compare_digest(acc, expected)
