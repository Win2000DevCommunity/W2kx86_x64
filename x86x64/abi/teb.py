"""
Thread Environment Block remapping: 32-bit ``fs:`` to 64-bit ``gs:``.

Win32 reaches the TEB through ``fs:``; Win64 uses ``gs:`` and widens every
pointer field, so the offsets are not the same and are not a constant multiple
of each other either -- ``LastErrorValue`` stays a DWORD while everything
before it doubles.  The table below is the authority for that mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterator, Optional


@dataclass(frozen=True)
class TebField:
    """One TEB member and where it lives under each architecture."""

    fs_offset: int
    gs_offset: int
    name: str
    #: Field width in bytes on x64.
    width: int = 8

    @property
    def is_pointer(self) -> bool:
        return self.width == 8

    def __str__(self) -> str:
        return f'{self.name}: fs:[0x{self.fs_offset:02X}] -> gs:[0x{self.gs_offset:02X}]'


#: Every TEB field the translator knows how to remap, in ``fs:`` order.
TEB_FIELDS = (
    TebField(0x00, 0x00, 'ExceptionList'),
    TebField(0x04, 0x08, 'StackBase'),
    TebField(0x08, 0x10, 'StackLimit'),
    TebField(0x0C, 0x18, 'SubSystemTib'),
    TebField(0x10, 0x20, 'FiberData'),
    TebField(0x14, 0x28, 'ArbitraryUserPointer'),
    TebField(0x18, 0x30, 'Self'),
    TebField(0x1C, 0x38, 'EnvironmentPointer'),
    TebField(0x20, 0x40, 'ClientId.UniqueProcess'),
    TebField(0x24, 0x48, 'ClientId.UniqueThread'),
    TebField(0x28, 0x50, 'ActiveRpcHandle'),
    TebField(0x2C, 0x58, 'ThreadLocalStoragePointer'),
    TebField(0x30, 0x60, 'ProcessEnvironmentBlock'),
    TebField(0x34, 0x68, 'LastErrorValue', width=4),
    TebField(0x38, 0x6C, 'CountOfOwnedCriticalSections', width=4),
    TebField(0x3C, 0x70, 'CsrClientThread'),
    TebField(0x40, 0x78, 'Win32ThreadInfo'),
)

#: Flat ``fs:`` offset -> ``gs:`` offset lookup.
FS_TO_GS: Dict[int, int] = {f.fs_offset: f.gs_offset for f in TEB_FIELDS}
_BY_FS: Dict[int, TebField] = {f.fs_offset: f for f in TEB_FIELDS}
_BY_GS: Dict[int, TebField] = {f.gs_offset: f for f in TEB_FIELDS}
_BY_NAME: Dict[str, TebField] = {f.name: f for f in TEB_FIELDS}

#: Fields that hold a pointer and so must be read as a qword on x64.
POINTER_GS_OFFSETS = frozenset(f.gs_offset for f in TEB_FIELDS if f.is_pointer)


def fs_to_gs(fs_offset: int) -> int:
    """
    Translate an ``fs:`` displacement to its ``gs:`` equivalent.

    Unknown offsets pass through unchanged, matching the legacy behaviour: a
    binary reaching past the fields we model is usually touching TLS slots,
    where the layouts happen to agree closely enough to be worth attempting.
    """
    return FS_TO_GS.get(fs_offset, fs_offset)


def field_at_fs(fs_offset: int) -> Optional[TebField]:
    return _BY_FS.get(fs_offset)


def field_at_gs(gs_offset: int) -> Optional[TebField]:
    return _BY_GS.get(gs_offset)


def field_by_name(name: str) -> Optional[TebField]:
    return _BY_NAME.get(name)


def is_known_fs_offset(fs_offset: int) -> bool:
    return fs_offset in FS_TO_GS


def access_width(gs_offset: int) -> int:
    """Bytes to move for a ``gs:[offset]`` access; 8 unless the field is a DWORD."""
    field = _BY_GS.get(gs_offset)
    return field.width if field else 8


def operand_size(gs_offset: int) -> str:
    """Assembler size keyword for a ``gs:[offset]`` access."""
    return 'qword' if access_width(gs_offset) == 8 else 'dword'


def __iter__() -> Iterator[TebField]:   # pragma: no cover - convenience only
    return iter(TEB_FIELDS)
