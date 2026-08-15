"""
Object files: relocatable sections plus the symbols and relocations they carry.

This is the intermediate form the translator emits instead of a finished image.
A :class:`Section` owns *pristine* bytes -- the emitter's output with zeroes in
every relocated field -- so :meth:`Section.relocated` can be called any number
of times against any layout and always produces the same result for the same
addresses.  That idempotence is what lets the linker move sections freely.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..errors import LayoutError, SymbolError
from .relocs import Relocation, RelocKind
from .symbols import Symbol, SymbolKind, SymbolTable


class SectionFlags(enum.IntFlag):
    """PE section characteristics, restricted to the ones we emit."""

    CODE = 0x0000_0020
    INITIALIZED_DATA = 0x0000_0040
    UNINITIALIZED_DATA = 0x0000_0080
    DISCARDABLE = 0x0200_0000
    EXECUTE = 0x2000_0000
    READ = 0x4000_0000
    WRITE = 0x8000_0000

    @classmethod
    def text(cls) -> 'SectionFlags':
        return cls.CODE | cls.EXECUTE | cls.READ

    @classmethod
    def rdata(cls) -> 'SectionFlags':
        return cls.INITIALIZED_DATA | cls.READ

    @classmethod
    def data(cls) -> 'SectionFlags':
        return cls.INITIALIZED_DATA | cls.READ | cls.WRITE

    @classmethod
    def bss(cls) -> 'SectionFlags':
        return cls.UNINITIALIZED_DATA | cls.READ | cls.WRITE


class Section:
    """
    A named, relocatable run of bytes.

    Writes go through :meth:`emit` / :meth:`patch` so the pristine buffer stays
    authoritative.  Relocation fields are left zeroed until link time.
    """

    __slots__ = ('name', 'flags', 'alignment', '_data', '_relocs', '_virtual_size')

    def __init__(self, name: str, flags: SectionFlags = SectionFlags.data(),
                 *, alignment: int = 16, data: bytes = b'',
                 virtual_size: int = 0) -> None:
        if alignment <= 0 or alignment & (alignment - 1):
            raise LayoutError(f'section {name!r} alignment must be a power of two')
        self.name = name
        self.flags = flags
        self.alignment = alignment
        self._data = bytearray(data)
        self._relocs: List[Relocation] = []
        self._virtual_size = virtual_size

    # -- size ------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._data)

    @property
    def raw_size(self) -> int:
        """Bytes stored in the file."""
        return len(self._data)

    @property
    def virtual_size(self) -> int:
        """Bytes occupied in memory; may exceed ``raw_size`` for .bss tails."""
        return max(self._virtual_size, len(self._data))

    @virtual_size.setter
    def virtual_size(self, value: int) -> None:
        self._virtual_size = value

    @property
    def is_code(self) -> bool:
        return bool(self.flags & SectionFlags.CODE)

    @property
    def is_writable(self) -> bool:
        return bool(self.flags & SectionFlags.WRITE)

    # -- content ---------------------------------------------------------
    @property
    def data(self) -> bytes:
        """Pristine bytes, relocation fields still zeroed."""
        return bytes(self._data)

    def tell(self) -> int:
        """Current end offset -- where the next :meth:`emit` will land."""
        return len(self._data)

    def emit(self, blob: bytes) -> int:
        """Append *blob* and return the offset it was written at."""
        off = len(self._data)
        self._data += blob
        return off

    def emit_zeros(self, count: int) -> int:
        return self.emit(bytes(count))

    def align_to(self, boundary: int, fill: int = 0) -> int:
        """Pad to *boundary* and return the resulting offset."""
        pad = (-len(self._data)) % boundary
        if pad:
            self._data += bytes([fill]) * pad
        return len(self._data)

    def patch(self, offset: int, blob: bytes) -> None:
        """Overwrite pristine bytes at *offset*."""
        if offset < 0 or offset + len(blob) > len(self._data):
            raise LayoutError(
                f'patch at 0x{offset:x}+{len(blob)} exceeds section '
                f'{self.name!r} ({len(self._data)} bytes)')
        self._data[offset:offset + len(blob)] = blob

    def read(self, offset: int, size: int) -> bytes:
        return bytes(self._data[offset:offset + size])

    # -- relocations -----------------------------------------------------
    @property
    def relocations(self) -> Sequence[Relocation]:
        return tuple(self._relocs)

    def add_reloc(self, reloc: Relocation) -> Relocation:
        """Record *reloc*, checking it lands inside this section."""
        if reloc.offset < 0 or reloc.end > len(self._data):
            raise LayoutError(
                f'relocation {reloc} lies outside section {self.name!r} '
                f'({len(self._data)} bytes)')
        self._relocs.append(reloc)
        return reloc

    def reloc(self, offset: int, kind: RelocKind, symbol: str,
              addend: int = 0, **kw) -> Relocation:
        """Convenience wrapper building and recording a :class:`Relocation`."""
        return self.add_reloc(Relocation(offset, kind, symbol, addend, **kw))

    def emit_reloc(self, kind: RelocKind, symbol: str, addend: int = 0,
                   **kw) -> Relocation:
        """Append a zeroed field of *kind* and relocate it against *symbol*."""
        off = self.emit_zeros(kind.width)
        return self.reloc(off, kind, symbol, addend, **kw)

    def relocation_at(self, offset: int) -> Optional[Relocation]:
        for r in self._relocs:
            if r.offset <= offset < r.end:
                return r
        return None

    def clear_relocs(self) -> None:
        self._relocs.clear()

    # -- linking ---------------------------------------------------------
    def relocated(self, resolver, *, base_va: int, image_base: int,
                  section_index: int = 0) -> bytearray:
        """
        Return a copy of the bytes with every relocation applied.

        *resolver* maps a symbol name to its final virtual address.  The
        pristine buffer is untouched, so calling this again after a re-layout
        is correct by construction -- there is nothing to "un-patch".
        """
        from .relocs import apply_relocation  # local: keeps import graph flat

        out = bytearray(self._data)
        for r in self._relocs:
            target_va = resolver(r.symbol)
            apply_relocation(
                out, r, target_va,
                site_va=base_va + r.offset,
                image_base=image_base,
                section_base=base_va,
                section_index=section_index,
                site=f'{self.name}+0x{r.offset:x}')
        return out

    def __repr__(self) -> str:
        return (f'<Section {self.name!r} {len(self._data)}B '
                f'relocs={len(self._relocs)} flags={self.flags!r}>')


class ObjectFile:
    """
    A translation unit: named sections plus the symbols they define.

    Sections are addressed by name; :meth:`section` creates on first use so an
    emitter can write into ``.text``/``.rdata``/``.data`` without bookkeeping.
    """

    def __init__(self, name: str = '<obj>') -> None:
        self.name = name
        self.symbols = SymbolTable(name)
        self._sections: Dict[str, Section] = {}
        #: Free-form notes carried through the pipeline (source path, mode...).
        self.metadata: Dict[str, object] = {}

    # -- sections --------------------------------------------------------
    def section(self, name: str, flags: Optional[SectionFlags] = None,
                *, alignment: int = 16) -> Section:
        """Fetch or create the section called *name*."""
        sec = self._sections.get(name)
        if sec is None:
            sec = Section(name, flags if flags is not None else _default_flags(name),
                          alignment=alignment)
            self._sections[name] = sec
        return sec

    def add_section(self, sec: Section) -> Section:
        if sec.name in self._sections:
            raise LayoutError(f'{self.name}: duplicate section {sec.name!r}')
        self._sections[sec.name] = sec
        return sec

    @property
    def sections(self) -> Sequence[Section]:
        return tuple(self._sections.values())

    def get_section(self, name: str) -> Optional[Section]:
        return self._sections.get(name)

    def __contains__(self, name: object) -> bool:
        return name in self._sections

    def __iter__(self) -> Iterator[Section]:
        return iter(self._sections.values())

    # -- symbols ---------------------------------------------------------
    def define(self, name: str, section: str, offset: int,
               kind: SymbolKind = SymbolKind.GLOBAL, **kw) -> Symbol:
        """Define *name* at *offset* in *section* of this object."""
        if section not in self._sections:
            raise SymbolError(
                f'{self.name}: symbol {name!r} names unknown section {section!r}')
        return self.symbols.at(name, section, offset, kind, **kw)

    def define_here(self, name: str, sec: Section,
                    kind: SymbolKind = SymbolKind.GLOBAL, **kw) -> Symbol:
        """Define *name* at the current end of *sec* -- the usual label idiom."""
        return self.define(name, sec.name, sec.tell(), kind, **kw)

    def declare_import(self, dll: str, func: str) -> Symbol:
        """Register an imported function and return its symbol."""
        from .symbols import import_symbol_name

        sym_name = import_symbol_name(dll, func)
        existing = self.symbols.get(sym_name)
        if existing is not None and existing.kind is SymbolKind.IMPORT:
            return existing
        return self.symbols.define(
            Symbol(sym_name, SymbolKind.IMPORT, dll=dll, import_name=func),
            replace=True)

    # -- stats -----------------------------------------------------------
    def total_size(self) -> int:
        return sum(s.virtual_size for s in self._sections.values())

    def relocation_count(self) -> int:
        return sum(len(s.relocations) for s in self._sections.values())

    def summary(self) -> str:
        parts = [f'{s.name}:{s.raw_size}B/{len(s.relocations)}r'
                 for s in self._sections.values()]
        return f'{self.name} [{", ".join(parts)}] syms={len(self.symbols)}'

    def __repr__(self) -> str:
        return f'<ObjectFile {self.name!r} sections={len(self._sections)}>'


_DEFAULT_FLAGS: Dict[str, SectionFlags] = {
    '.text': SectionFlags.text(),
    '.rdata': SectionFlags.rdata(),
    '.data': SectionFlags.data(),
    '.bss': SectionFlags.bss(),
    '.rsrc': SectionFlags.rdata(),
    '.idata': SectionFlags.data(),
    '.edata': SectionFlags.rdata(),
    '.reloc': SectionFlags.rdata() | SectionFlags.DISCARDABLE,
}


def _default_flags(name: str) -> SectionFlags:
    return _DEFAULT_FLAGS.get(name, SectionFlags.data())
