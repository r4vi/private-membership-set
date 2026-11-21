"""Global registry for discovering and instantiating concrete PMSet protocols."""

from __future__ import annotations

from pmset.core.interfaces import PMSetProtocol
from pmset.core.types import ProtocolMetadata


class ProtocolRegistry:
    """Registry mapping canonical protocol names to :class:`PMSetProtocol` instances."""

    def __init__(self) -> None:
        self._protocols: dict[str, PMSetProtocol] = {}

    def register(self, protocol: PMSetProtocol, *, overwrite: bool = False) -> PMSetProtocol:
        name = protocol.name
        if name in self._protocols and not overwrite:
            raise ValueError(f"Protocol '{name}' is already registered")
        self._protocols[name] = protocol
        return protocol

    def get(self, name: str) -> PMSetProtocol:
        if name not in self._protocols:
            available = ", ".join(sorted(self._protocols))
            raise KeyError(f"Unknown PMSet protocol '{name}'. Available: {available}")
        return self._protocols[name]

    def list_names(self) -> list[str]:
        return sorted(self._protocols.keys())

    def all_protocols(self) -> list[PMSetProtocol]:
        return [self._protocols[name] for name in self.list_names()]

    def catalog(self) -> list[ProtocolMetadata]:
        return [p.metadata for p in self.all_protocols()]


_DEFAULT_REGISTRY = ProtocolRegistry()


def register_protocol(protocol: PMSetProtocol, *, overwrite: bool = False) -> PMSetProtocol:
    """Register a concrete PMSet protocol in the global registry."""
    return _DEFAULT_REGISTRY.register(protocol, overwrite=overwrite)


def get_protocol(name: str) -> PMSetProtocol:
    """Look up a registered PMSet protocol by canonical name."""
    return _DEFAULT_REGISTRY.get(name)


def list_protocols() -> list[str]:
    """Return sorted canonical names of all registered PMSet protocols."""
    return _DEFAULT_REGISTRY.list_names()


def all_protocols() -> list[PMSetProtocol]:
    """Return all registered :class:`PMSetProtocol` instances."""
    return _DEFAULT_REGISTRY.all_protocols()


def protocol_catalog() -> list[ProtocolMetadata]:
    """Return metadata for all registered PMSet protocols."""
    return _DEFAULT_REGISTRY.catalog()
