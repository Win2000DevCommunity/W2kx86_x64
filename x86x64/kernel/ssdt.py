"""
Ring-0 surface: the System Service Descriptor Table and its dispatch stubs.

Because NT 5.0 never shipped for x64, the "Win2000 x64" target has no
authoritative kernel-side table -- we define one.  Keeping the same service
indices the 32-bit SSDT used means a translated user-mode stub can load its
original number and still land on the right service, which is what the
``win2000`` syscall target relies on.

This module builds that table: the service array, the argument-byte array the
dispatcher uses to copy stack arguments, and the descriptor that points at
both.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from ..core.objfile import ObjectFile, Section, SectionFlags
from ..core.relocs import RelocKind
from ..syscall.table import SyscallEntry, SyscallTable, default_table

#: Entries in a KiServiceTable, sized to the Win2000 SSDT.
DEFAULT_SERVICE_LIMIT = 0x100

#: Symbol names the kernel image exports for its service table.
SERVICE_TABLE_SYMBOL = 'KiServiceTable'
ARGUMENT_TABLE_SYMBOL = 'KiArgumentTable'
DESCRIPTOR_SYMBOL = 'KeServiceDescriptorTable'


@dataclass(frozen=True)
class ServiceEntry:
    """One SSDT slot: an index, the routine it dispatches to, and its arity."""

    index: int
    name: str
    n_args: int
    #: Symbol implementing the service, or empty for an unimplemented slot.
    handler: str = ''

    @property
    def is_implemented(self) -> bool:
        return bool(self.handler)

    @property
    def argument_bytes(self) -> int:
        """Bytes of stack arguments the dispatcher must copy."""
        return self.n_args * 8

    def __str__(self) -> str:
        state = self.handler or '<unimplemented>'
        return f'[0x{self.index:03X}] {self.name}/{self.n_args} -> {state}'


class ServiceTable:
    """
    The kernel-side service table under construction.

    Slots are sparse: a Win2000 SSDT index with no x64 implementation stays
    empty and is emitted pointing at a shared "not implemented" routine, so a
    stray call traps cleanly rather than jumping into whatever follows.
    """

    def __init__(self, *, limit: int = DEFAULT_SERVICE_LIMIT,
                 unimplemented_symbol: str = 'KiServiceNotImplemented') -> None:
        self.limit = limit
        self.unimplemented_symbol = unimplemented_symbol
        self._entries: Dict[int, ServiceEntry] = {}

    @classmethod
    def from_syscall_table(cls, table: Optional[SyscallTable] = None, *,
                           limit: Optional[int] = None,
                           handler_prefix: str = 'Nt') -> 'ServiceTable':
        """
        Build a table mirroring the Win2000 SSDT.

        Handlers are named after the service itself, which is the convention
        the kernel image uses; a slot whose handler the kernel does not define
        falls back to the unimplemented stub at link time.
        """
        src = table or default_table()
        services = src.services()
        highest = max((e.win2000_nr for e in services), default=0)
        out = cls(limit=limit if limit is not None else highest + 1)
        for entry in services:
            out.add(ServiceEntry(entry.win2000_nr, entry.name, entry.n_args,
                                 handler=handler_prefix + entry.name[2:]
                                 if entry.name.startswith('Nt') else entry.name))
        return out

    # -- population ------------------------------------------------------
    def add(self, entry: ServiceEntry) -> ServiceEntry:
        if not 0 <= entry.index < self.limit:
            raise IndexError(
                f'service index 0x{entry.index:X} outside table limit '
                f'0x{self.limit:X}')
        self._entries[entry.index] = entry
        return entry

    def get(self, index: int) -> Optional[ServiceEntry]:
        return self._entries.get(index)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(sorted(self._entries.values(), key=lambda e: e.index))

    @property
    def implemented(self) -> List[ServiceEntry]:
        return [e for e in self if e.is_implemented]

    def coverage(self) -> tuple[int, int]:
        return len(self.implemented), self.limit

    # -- emission --------------------------------------------------------
    def emit_argument_table(self, sec: Section) -> int:
        """
        Emit ``KiArgumentTable``: one byte of stack-argument size per slot.

        Returns the offset it was written at.
        """
        start = sec.tell()
        blob = bytearray(self.limit)
        for entry in self:
            blob[entry.index] = min(entry.argument_bytes, 0xFF)
        sec.emit(bytes(blob))
        return start

    def emit_service_table(self, sec: Section, *,
                           kind: RelocKind = RelocKind.ABS64) -> int:
        """
        Emit ``KiServiceTable``: one relocated pointer per slot.

        Every slot gets a relocation -- implemented ones against their handler,
        empty ones against the shared trap -- so the table needs no fixup pass
        after the kernel image is laid out.
        """
        start = sec.tell()
        for index in range(self.limit):
            entry = self._entries.get(index)
            symbol = (entry.handler if entry and entry.is_implemented
                      else self.unimplemented_symbol)
            sec.emit_reloc(kind, symbol, origin=index)
        return start

    def emit_descriptor(self, sec: Section, *,
                        service_symbol: str = SERVICE_TABLE_SYMBOL,
                        argument_symbol: str = ARGUMENT_TABLE_SYMBOL) -> int:
        """
        Emit a ``KSERVICE_TABLE_DESCRIPTOR``.

        Layout is ``{ Base, Count, Limit, Number }`` with 64-bit pointers; the
        ``Count`` pointer is null because usage counting is a checked-build
        feature we do not provide.
        """
        start = sec.tell()
        sec.emit_reloc(RelocKind.ABS64, service_symbol)
        sec.emit(struct.pack('<Q', 0))
        sec.emit(struct.pack('<Q', self.limit))
        sec.emit_reloc(RelocKind.ABS64, argument_symbol)
        return start

    def build_object(self, name: str = 'ssdt.obj') -> ObjectFile:
        """
        Produce a linkable object holding the whole service-table trio.

        The caller supplies the handlers by linking the kernel image alongside;
        anything still missing surfaces as an undefined-symbol error naming the
        service, which beats a silently null slot.
        """
        obj = ObjectFile(name)
        data = obj.section('.data', SectionFlags.data(), alignment=16)

        data.align_to(16)
        obj.define_here(SERVICE_TABLE_SYMBOL, data)
        self.emit_service_table(data)

        data.align_to(16)
        obj.define_here(ARGUMENT_TABLE_SYMBOL, data)
        self.emit_argument_table(data)

        data.align_to(16)
        obj.define_here(DESCRIPTOR_SYMBOL, data)
        self.emit_descriptor(data)

        obj.metadata['service_limit'] = self.limit
        obj.metadata['implemented'] = len(self.implemented)
        return obj

    def __repr__(self) -> str:
        done, total = self.coverage()
        return f'<ServiceTable {done}/{total} implemented>'
