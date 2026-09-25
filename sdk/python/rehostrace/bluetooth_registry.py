"""Extensible registry for Bluetooth semantic protocol-pack handlers."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from .bluetooth import (
    AttProtocolPack,
    AvdtpProtocolPack,
    BluetoothProtocolPack,
    GattProtocolPack,
    HciProtocolPack,
    L2capProtocolPack,
    SdpProtocolPack,
)
from .bluetooth_profiles import (
    A2dpProtocolPack,
    AvrcpProtocolPack,
    HfpProtocolPack,
    LeAudioProtocolPack,
    RfcommProtocolPack,
    SmpProtocolPack,
)


PackFactory = Callable[[], BluetoothProtocolPack]


class BluetoothPackRegistry:
    """Map data-only manifests to explicitly registered code handlers.

    Manifests never import code. Applications decide which handler factories
    are trusted and register them before resolving a manifest set.
    """

    def __init__(self) -> None:
        self._factories: dict[str, PackFactory] = {}

    def register(self, factory: PackFactory) -> None:
        handler = factory()
        pack_id = getattr(handler, "pack_id", None)
        if not isinstance(pack_id, str) or not pack_id:
            raise ValueError("Bluetooth pack factory returned an invalid handler")
        if pack_id in self._factories:
            raise ValueError(f"duplicate Bluetooth pack factory: {pack_id}")
        self._factories[pack_id] = factory

    def register_many(self, factories: Iterable[PackFactory]) -> None:
        for factory in factories:
            self.register(factory)

    @property
    def pack_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))

    def resolve(self, manifests: list[dict]) -> list[tuple[BluetoothProtocolPack, dict]]:
        registrations: list[tuple[BluetoothProtocolPack, dict]] = []
        for manifest in manifests:
            pack_id = manifest.get("pack_id") if isinstance(manifest, dict) else None
            factory = self._factories.get(pack_id)
            if factory is None:
                raise ValueError(f"no registered handler for protocol-pack manifest: {pack_id!r}")
            registrations.append((factory(), manifest))
        return registrations


def built_in_bluetooth_registry() -> BluetoothPackRegistry:
    registry = BluetoothPackRegistry()
    registry.register_many(
        [
            HciProtocolPack,
            L2capProtocolPack,
            AvdtpProtocolPack,
            SdpProtocolPack,
            AttProtocolPack,
            GattProtocolPack,
            SmpProtocolPack,
            RfcommProtocolPack,
            AvrcpProtocolPack,
            HfpProtocolPack,
            A2dpProtocolPack,
            LeAudioProtocolPack,
        ]
    )
    return registry
