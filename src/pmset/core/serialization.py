"""Canonical, deterministic, pickle-free binary serialization for PMSet wire messages.

All protocol messages and public parameters serialize into self-describing
length-prefixed binary frames supporting:
  - None
  - bool
  - arbitrary-precision signed int
  - bytes
  - str (UTF-8)
  - list / tuple
  - dict with str keys
"""

from __future__ import annotations

import struct
from typing import Any

_TAG_NONE = 0x00
_TAG_FALSE = 0x01
_TAG_TRUE = 0x02
_TAG_POS_INT = 0x03
_TAG_NEG_INT = 0x04
_TAG_BYTES = 0x05
_TAG_STR = 0x06
_TAG_LIST = 0x07
_TAG_DICT = 0x08

_U32 = struct.Struct(">I")


class SerializationError(ValueError):
    """Raised when a wire payload cannot be serialized or deserialized."""


def _encode_into(value: Any, out: bytearray) -> None:
    if value is None:
        out.append(_TAG_NONE)
    elif isinstance(value, bool):
        out.append(_TAG_TRUE if value else _TAG_FALSE)
    elif isinstance(value, int):
        if value >= 0:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value > 0 else b""
            out.append(_TAG_POS_INT)
        else:
            mag = -value
            raw = mag.to_bytes((mag.bit_length() + 7) // 8, "big")
            out.append(_TAG_NEG_INT)
        out.extend(_U32.pack(len(raw)))
        out.extend(raw)
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        out.append(_TAG_BYTES)
        out.extend(_U32.pack(len(raw)))
        out.extend(raw)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        out.append(_TAG_STR)
        out.extend(_U32.pack(len(raw)))
        out.extend(raw)
    elif isinstance(value, (list, tuple)):
        out.append(_TAG_LIST)
        out.extend(_U32.pack(len(value)))
        for elem in value:
            _encode_into(elem, out)
    elif isinstance(value, dict):
        out.append(_TAG_DICT)
        out.extend(_U32.pack(len(value)))
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise SerializationError(f"Dict keys must be str, got {type(key).__name__}")
            key_bytes = key.encode("utf-8")
            out.extend(_U32.pack(len(key_bytes)))
            out.extend(key_bytes)
            _encode_into(value[key], out)
    else:
        raise SerializationError(f"Unsupported value type for wire serialization: {type(value).__name__}")


def encode_value(value: Any) -> bytes:
    """Serialize a structured Python value into canonical binary bytes."""
    buf = bytearray()
    _encode_into(value, buf)
    return bytes(buf)


def _decode_from(data: memoryview, offset: int) -> tuple[Any, int]:
    if offset >= len(data):
        raise SerializationError("Unexpected end of wire payload")
    tag = data[offset]
    offset += 1

    if tag == _TAG_NONE:
        return None, offset
    if tag == _TAG_FALSE:
        return False, offset
    if tag == _TAG_TRUE:
        return True, offset
    if tag in (_TAG_POS_INT, _TAG_NEG_INT):
        if offset + 4 > len(data):
            raise SerializationError("Truncated integer length")
        (length,) = _U32.unpack_from(data, offset)
        offset += 4
        if offset + length > len(data):
            raise SerializationError("Truncated integer payload")
        mag = int.from_bytes(data[offset : offset + length], "big") if length > 0 else 0
        offset += length
        return (mag if tag == _TAG_POS_INT else -mag), offset
    if tag == _TAG_BYTES:
        if offset + 4 > len(data):
            raise SerializationError("Truncated bytes length")
        (length,) = _U32.unpack_from(data, offset)
        offset += 4
        if offset + length > len(data):
            raise SerializationError("Truncated bytes payload")
        val = bytes(data[offset : offset + length])
        return val, offset + length
    if tag == _TAG_STR:
        if offset + 4 > len(data):
            raise SerializationError("Truncated str length")
        (length,) = _U32.unpack_from(data, offset)
        offset += 4
        if offset + length > len(data):
            raise SerializationError("Truncated str payload")
        try:
            val = bytes(data[offset : offset + length]).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SerializationError("Invalid UTF-8 in wire payload") from exc
        return val, offset + length
    if tag == _TAG_LIST:
        if offset + 4 > len(data):
            raise SerializationError("Truncated list length")
        (count,) = _U32.unpack_from(data, offset)
        offset += 4
        items = []
        for _ in range(count):
            elem, offset = _decode_from(data, offset)
            items.append(elem)
        return items, offset
    if tag == _TAG_DICT:
        if offset + 4 > len(data):
            raise SerializationError("Truncated dict length")
        (count,) = _U32.unpack_from(data, offset)
        offset += 4
        result: dict[str, Any] = {}
        for _ in range(count):
            if offset + 4 > len(data):
                raise SerializationError("Truncated dict key length")
            (klen,) = _U32.unpack_from(data, offset)
            offset += 4
            if offset + klen > len(data):
                raise SerializationError("Truncated dict key")
            key = bytes(data[offset : offset + klen]).decode("utf-8")
            offset += klen
            val, offset = _decode_from(data, offset)
            result[key] = val
        return result, offset

    raise SerializationError(f"Unknown wire tag: 0x{tag:02x}")


def decode_value(data: bytes) -> Any:
    """Deserialize canonical binary bytes produced by :func:`encode_value`."""
    view = memoryview(data)
    value, offset = _decode_from(view, 0)
    if offset != len(view):
        raise SerializationError(f"Trailing bytes in wire payload: {len(view) - offset}")
    return value
