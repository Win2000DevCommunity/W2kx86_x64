"""
Import dispatch: turning x86 IAT references into x64 calls through the linker.

A PE32 call through the import table is ``call dword [iat_slot]`` -- a 6-byte
instruction naming an absolute 32-bit address.  On x64 the slot is 8 bytes and
the natural encoding is ``call qword [rip+disp32]``, which needs the distance
from the instruction to the slot.

The legacy translator computed that distance itself, which meant every pass
that moved code or data had to find and re-fix each call site.  Here the call
is emitted with a zeroed displacement plus a relocation naming the import
symbol; the linker knows where the slot ended up and fills it in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.objfile import ObjectFile, Section
from ..core.relocs import RelocKind
from ..core.symbols import Symbol, import_symbol_name
from ..encoding import emit

#: Renames applied when a Win2000 import has no x64 counterpart. Keyed by
#: ``(dll, function)``; the value is the replacement in the same DLL.
DEFAULT_IMPORT_RENAMES: Dict[Tuple[str, str], str] = {
    ('msvcrt.dll', '_controlfp'): '_control87',
    ('msvcrt.dll', '__set_app_type'): '_set_app_type',
}


@dataclass(frozen=True)
class ImportRef:
    """One resolved import and the symbol that names its IAT slot."""

    dll: str
    name: str
    symbol: str
    #: Original x86 IAT slot VA, kept so x86-side references can be matched.
    x86_slot_va: int = 0

    @property
    def display(self) -> str:
        return f'{self.dll}!{self.name}'


class ImportTable:
    """
    Tracks which imports a translation needs and what to call them.

    Registration is idempotent, so an emitter can ask for the same import at
    every call site without bookkeeping.
    """

    def __init__(self, obj: ObjectFile, *,
                 renames: Optional[Dict[Tuple[str, str], str]] = None) -> None:
        self._obj = obj
        self._renames = dict(DEFAULT_IMPORT_RENAMES if renames is None else renames)
        self._refs: Dict[str, ImportRef] = {}
        #: x86 IAT slot VA -> symbol, for translating absolute references.
        self._by_x86_slot: Dict[int, str] = {}

    # -- registration ----------------------------------------------------
    def resolve_name(self, dll: str, name: str) -> str:
        """Apply the rename table for imports missing on x64."""
        return self._renames.get((dll.lower(), name), name)

    def declare(self, dll: str, name: str, *, x86_slot_va: int = 0) -> ImportRef:
        """Register an import and return its :class:`ImportRef`."""
        effective = self.resolve_name(dll, name)
        symbol = import_symbol_name(dll, effective)
        ref = self._refs.get(symbol)
        if ref is None:
            self._obj.declare_import(dll, effective)
            ref = ImportRef(dll, effective, symbol, x86_slot_va)
            self._refs[symbol] = ref
        if x86_slot_va:
            self._by_x86_slot[x86_slot_va] = symbol
        return ref

    def symbol_for_x86_slot(self, slot_va: int) -> Optional[str]:
        """The import symbol an original PE32 IAT address refers to."""
        return self._by_x86_slot.get(slot_va)

    def is_import_slot(self, slot_va: int) -> bool:
        return slot_va in self._by_x86_slot

    @property
    def refs(self) -> Sequence[ImportRef]:
        return tuple(self._refs.values())

    def by_dll(self) -> Dict[str, List[ImportRef]]:
        grouped: Dict[str, List[ImportRef]] = {}
        for ref in self._refs.values():
            grouped.setdefault(ref.dll.lower(), []).append(ref)
        for refs in grouped.values():
            refs.sort(key=lambda r: r.name)
        return grouped

    def __len__(self) -> int:
        return len(self._refs)

    def __contains__(self, symbol: object) -> bool:
        return symbol in self._refs


# -- call-site emission ---------------------------------------------------
def emit_import_call(sec: Section, symbol: str, *, origin: Optional[int] = None):
    """
    Emit ``call qword [rip+disp32]`` targeting an import's IAT slot.

    The displacement is relocated, not computed, so the call keeps working if
    either the code or the import table moves.
    """
    start = sec.emit(emit.call_mem_rip(0))
    # The displacement is the last 4 bytes and the instruction ends there, so
    # no pcrel_adjust is needed.
    sec.reloc(start + 2, RelocKind.REL32, symbol, addend=0, origin=origin)
    return start


def emit_import_jmp(sec: Section, symbol: str, *, origin: Optional[int] = None):
    """Emit ``jmp qword [rip+disp32]`` -- the tail of an import thunk."""
    start = sec.emit(emit.jmp_mem_rip(0))
    sec.reloc(start + 2, RelocKind.REL32, symbol, addend=0, origin=origin)
    return start


def emit_import_ptr_load(sec: Section, dst: str, symbol: str, *,
                         origin: Optional[int] = None):
    """
    Emit ``movabs dst, <iat slot va>`` -- the address of the slot, not its value.

    Code that loads a function pointer into a register and calls it indirectly
    needs the slot address; the ``call [reg]`` that follows dereferences it.
    """
    start = sec.emit(emit.mov_reg_imm64(dst, 0))
    sec.reloc(start + emit.MOVABS_IMM_OFFSET, RelocKind.ABS64, symbol,
              origin=origin)
    return start


def emit_import_fn_load(sec: Section, dst: str, symbol: str, *,
                        origin: Optional[int] = None):
    """
    Emit ``mov dst, qword [rip+disp32]`` -- load the function pointer itself.

    This is the direct equivalent of the x86 ``mov reg, [iat_slot]`` idiom and
    is one instruction shorter than a movabs plus dereference.
    """
    start = sec.emit(emit.mov_reg_mem_rip(dst, 0))
    sec.reloc(start + emit.RIP_DISP_OFFSET, RelocKind.REL32, symbol,
              origin=origin)
    return start


def emit_thunk(sec: Section, symbol: str, *, origin: Optional[int] = None):
    """
    A minimal import thunk: a bare tail jump through the IAT slot.

    Arguments are already in place under the x64 ABI, so no shuffling is
    needed and the callee returns straight to the original caller.
    """
    return emit_import_jmp(sec, symbol, origin=origin)


def build_import_directory(refs: Sequence[ImportRef], *,
                           iat_rva: Dict[str, int],
                           directory_rva: int) -> Tuple[bytes, Dict[str, int]]:
    """
    Lay out a PE ``.idata`` directory for *refs*.

    Returns the blob and a map from import symbol to the RVA of its hint/name
    entry.  The IAT itself is allocated by the linker, so this only builds the
    descriptors, lookup tables, and name strings that reference it.
    """
    import struct

    by_dll: Dict[str, List[ImportRef]] = {}
    for ref in refs:
        by_dll.setdefault(ref.dll.lower(), []).append(ref)
    for group in by_dll.values():
        group.sort(key=lambda r: r.name)

    descriptors = bytearray()
    tables = bytearray()
    strings = bytearray()
    name_rvas: Dict[str, int] = {}

    desc_size = 20 * (len(by_dll) + 1)
    lookup_size = sum(8 * (len(g) + 1) for g in by_dll.values())
    tables_base = directory_rva + desc_size
    strings_base = tables_base + lookup_size

    for dll, group in sorted(by_dll.items()):
        lookup_rva = tables_base + len(tables)
        dll_name_rva = strings_base + len(strings)
        strings += dll.encode('ascii') + b'\x00'
        if len(strings) & 1:
            strings += b'\x00'

        for ref in group:
            hint_rva = strings_base + len(strings)
            name_rvas[ref.symbol] = hint_rva
            strings += struct.pack('<H', 0) + ref.name.encode('ascii') + b'\x00'
            if len(strings) & 1:
                strings += b'\x00'
            tables += struct.pack('<Q', hint_rva)
        tables += struct.pack('<Q', 0)

        first_thunk = iat_rva.get(group[0].symbol, 0) if group else 0
        descriptors += struct.pack('<IIIII', lookup_rva, 0, 0,
                                   dll_name_rva, first_thunk)

    descriptors += bytes(20)
    return bytes(descriptors + tables + strings), name_rvas
