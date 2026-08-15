"""
The linker: place sections, resolve symbols, apply relocations.

This module is the answer to the "do we still need the shift pass?" question.
We do still need to *move* data sections when translated code grows -- x64
encodings are longer than their x86 originals, so the code region expands past
where the data used to start.  What we do not need is the pass that walked the
finished blob looking for ``movabs`` byte patterns and adding a delta to
anything that resembled an address.

Because every reference is recorded as a :class:`~x86x64.core.relocs.Relocation`
against a symbol, moving a section is just: assign new addresses, re-resolve,
re-apply to the pristine bytes.  :meth:`Linker.link` is a pure function of the
layout, so calling it twice with different bases yields two correct images and
never a double-patched one.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..errors import LayoutError, UndefinedSymbolError
from .objfile import ObjectFile, Section, SectionFlags
from .relocs import Relocation, RelocKind, base_reloc_type
from .symbols import Symbol, SymbolKind, SymbolTable

DEFAULT_SECTION_ALIGN = 0x1000
DEFAULT_FILE_ALIGN = 0x200
#: Order sections are emitted in; anything unlisted follows, sorted by name.
DEFAULT_SECTION_ORDER = ('.text', '.rdata', '.data', '.bss',
                         '.idata', '.edata', '.rsrc', '.reloc')


def align_up(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


@dataclass(frozen=True)
class PlacedSection:
    """A section with its assigned address, after layout."""

    section: Section
    rva: int
    index: int          # 1-based, for SECTION16 relocations
    file_offset: int = 0

    @property
    def name(self) -> str:
        return self.section.name

    @property
    def size(self) -> int:
        return self.section.virtual_size

    @property
    def end_rva(self) -> int:
        return self.rva + self.size

    def __str__(self) -> str:
        return f'{self.name}@0x{self.rva:x}+0x{self.size:x}'


@dataclass
class Layout:
    """Where every section landed, and how big the image is."""

    sections: List[PlacedSection] = field(default_factory=list)
    image_base: int = 0
    section_align: int = DEFAULT_SECTION_ALIGN
    file_align: int = DEFAULT_FILE_ALIGN
    headers_size: int = DEFAULT_SECTION_ALIGN

    def by_name(self, name: str) -> Optional[PlacedSection]:
        for p in self.sections:
            if p.name == name:
                return p
        return None

    @property
    def image_size(self) -> int:
        end = max((p.end_rva for p in self.sections), default=self.headers_size)
        return align_up(end, self.section_align)

    def rva_of(self, name: str) -> int:
        p = self.by_name(name)
        if p is None:
            raise LayoutError(f'no section named {name!r} in layout')
        return p.rva

    def va_of(self, name: str) -> int:
        return self.image_base + self.rva_of(name)

    def describe(self) -> str:
        rows = [f'  {p.index:>2} {p.name:<10} rva=0x{p.rva:06x} '
                f'size=0x{p.size:05x} file=0x{p.file_offset:06x}'
                for p in self.sections]
        return (f'image_base=0x{self.image_base:x} '
                f'image_size=0x{self.image_size:x}\n' + '\n'.join(rows))


@dataclass
class LinkResult:
    """Fully linked sections plus the metadata a PE writer needs."""

    layout: Layout
    #: Section name -> relocated bytes.
    contents: Dict[str, bytes]
    #: Symbol name -> final virtual address.
    addresses: Dict[str, int]
    #: RVAs needing PE base relocations, as ``(rva, IMAGE_REL_BASED_*)``.
    base_relocs: List[Tuple[int, int]] = field(default_factory=list)
    #: Import symbol -> RVA of the IAT slot the linker reserved.
    iat_slots: Dict[str, int] = field(default_factory=dict)

    @property
    def image_base(self) -> int:
        return self.layout.image_base

    @property
    def image_size(self) -> int:
        return self.layout.image_size

    def address_of(self, symbol: str) -> int:
        try:
            return self.addresses[symbol]
        except KeyError:
            raise UndefinedSymbolError(symbol) from None

    def rva_of(self, symbol: str) -> int:
        return self.address_of(symbol) - self.image_base

    def section_bytes(self, name: str) -> bytes:
        return self.contents[name]


class Linker:
    """
    Merges object files, assigns addresses, and produces a linked image.

    Typical use::

        lk = Linker(image_base=0x80000000)
        lk.add_object(obj)
        result = lk.link()

    Re-linking at a different base or after appending more code is safe and
    produces a fresh, correct result -- see :meth:`relink`.
    """

    def __init__(self, *, image_base: int = 0x8000_0000,
                 section_align: int = DEFAULT_SECTION_ALIGN,
                 file_align: int = DEFAULT_FILE_ALIGN,
                 headers_size: int = DEFAULT_SECTION_ALIGN,
                 section_order: Sequence[str] = DEFAULT_SECTION_ORDER) -> None:
        self.image_base = image_base
        self.section_align = section_align
        self.file_align = file_align
        self.headers_size = headers_size
        self.section_order = tuple(section_order)
        self._objects: List[ObjectFile] = []
        #: Extra absolute symbols injected by the driver (e.g. __image_base__).
        self._absolutes: Dict[str, int] = {}

    # -- inputs ----------------------------------------------------------
    def add_object(self, obj: ObjectFile) -> 'Linker':
        self._objects.append(obj)
        return self

    def add_objects(self, objs: Iterable[ObjectFile]) -> 'Linker':
        self._objects.extend(objs)
        return self

    def define_absolute(self, name: str, value: int) -> 'Linker':
        self._absolutes[name] = value
        return self

    @property
    def objects(self) -> Sequence[ObjectFile]:
        return tuple(self._objects)

    # -- merging ---------------------------------------------------------
    def _merge_sections(self) -> Tuple[Dict[str, Section], Dict[Tuple[int, str], int]]:
        """
        Concatenate same-named sections from every object.

        Returns the merged sections and a map from ``(object index, section
        name)`` to the byte offset that object's contribution starts at, which
        is what rebases its symbols and relocations.
        """
        merged: Dict[str, Section] = {}
        offsets: Dict[Tuple[int, str], int] = {}

        for obj_idx, obj in enumerate(self._objects):
            for sec in obj.sections:
                dst = merged.get(sec.name)
                if dst is None:
                    dst = Section(sec.name, sec.flags, alignment=sec.alignment)
                    merged[sec.name] = dst
                else:
                    dst.flags |= sec.flags
                    dst.alignment = max(dst.alignment, sec.alignment)
                start = dst.align_to(sec.alignment)
                offsets[(obj_idx, sec.name)] = start
                dst.emit(sec.data)
                if sec.virtual_size > sec.raw_size:
                    dst.virtual_size = start + sec.virtual_size
                for r in sec.relocations:
                    dst.add_reloc(Relocation(
                        r.offset + start, r.kind, r.symbol, r.addend,
                        r.pcrel_adjust, r.origin))
        return merged, offsets

    def _merge_symbols(self, offsets: Dict[Tuple[int, str], int]) -> SymbolTable:
        """Build the global symbol table with per-object offsets folded in."""
        table = SymbolTable('<link>')
        for name, value in self._absolutes.items():
            table.absolute(name, value)

        for obj_idx, obj in enumerate(self._objects):
            for sym in obj.symbols:
                if sym.kind is SymbolKind.UNDEFINED:
                    table.declare(sym.name)
                    continue
                if sym.kind in (SymbolKind.LOCAL, SymbolKind.GLOBAL):
                    delta = offsets.get((obj_idx, sym.section or ''), 0)
                    moved = Symbol(sym.name, sym.kind, sym.section,
                                   sym.value + delta, sym.size,
                                   origin=sym.origin)
                    table.define(moved, replace=sym.kind is SymbolKind.LOCAL)
                else:
                    table.define(sym, replace=True)
        return table

    # -- layout ----------------------------------------------------------
    def _order_key(self, name: str) -> Tuple[int, str]:
        try:
            return (self.section_order.index(name), '')
        except ValueError:
            return (len(self.section_order), name)

    def plan_layout(self, sections: Dict[str, Section]) -> Layout:
        """
        Assign an RVA and file offset to every section.

        Growth is absorbed here and nowhere else: if ``.text`` is bigger than
        last time, ``.data`` simply starts further along.  No emitted byte
        needs to know.
        """
        layout = Layout(image_base=self.image_base,
                        section_align=self.section_align,
                        file_align=self.file_align,
                        headers_size=self.headers_size)
        rva = align_up(self.headers_size, self.section_align)
        file_off = align_up(self.headers_size, self.file_align)

        for index, name in enumerate(sorted(sections, key=self._order_key), start=1):
            sec = sections[name]
            rva = align_up(rva, max(self.section_align, sec.alignment))
            has_raw = bool(sec.flags & SectionFlags.UNINITIALIZED_DATA) is False
            placed = PlacedSection(sec, rva, index,
                                   file_off if has_raw else 0)
            layout.sections.append(placed)
            rva += max(align_up(sec.virtual_size, self.section_align),
                       self.section_align)
            if has_raw:
                file_off += align_up(sec.raw_size, self.file_align)
        return layout

    # -- resolution ------------------------------------------------------
    def _bind_addresses(self, table: SymbolTable, layout: Layout,
                        iat_slots: Dict[str, int]) -> Dict[str, int]:
        """Map every symbol name to its final virtual address."""
        sec_va = {p.name: layout.image_base + p.rva for p in layout.sections}
        addresses: Dict[str, int] = {}

        for sym in table:
            if sym.kind is SymbolKind.ABSOLUTE:
                addresses[sym.name] = sym.value
            elif sym.kind is SymbolKind.IMPORT:
                slot = iat_slots.get(sym.name)
                if slot is not None:
                    addresses[sym.name] = layout.image_base + slot
            elif sym.kind is SymbolKind.UNDEFINED:
                continue
            else:
                base = sec_va.get(sym.section or '')
                if base is None:
                    raise LayoutError(
                        f'symbol {sym.name!r} lives in section '
                        f'{sym.section!r} which was not laid out')
                addresses[sym.name] = base + sym.value

        addresses.setdefault('__image_base__', layout.image_base)
        addresses.setdefault('__image_end__', layout.image_base + layout.image_size)
        for name, va in sec_va.items():
            addresses.setdefault(f'__section_start__{name}', va)
        return addresses

    def _reserve_iat(self, table: SymbolTable,
                     sections: Dict[str, Section]) -> Dict[str, int]:
        """
        Give every import symbol an 8-byte slot in ``.idata``.

        Offsets are returned relative to the section; they become RVAs once
        layout runs, which is why this happens before :meth:`plan_layout`.
        """
        imports = sorted(table.imports(), key=lambda s: (s.dll.lower(), s.import_name))
        if not imports:
            return {}
        idata = sections.get('.idata')
        if idata is None:
            idata = Section('.idata', SectionFlags.data(), alignment=8)
            sections['.idata'] = idata
        idata.align_to(8)
        slots: Dict[str, int] = {}
        for sym in imports:
            slots[sym.name] = idata.tell()
            idata.emit_zeros(8)
        return slots

    # -- driving ---------------------------------------------------------
    def link(self) -> LinkResult:
        """Merge, lay out, resolve, and apply. Safe to call repeatedly."""
        sections, offsets = self._merge_sections()
        table = self._merge_symbols(offsets)

        iat_offsets = self._reserve_iat(table, sections)
        layout = self.plan_layout(sections)

        idata = layout.by_name('.idata')
        iat_slots = ({name: idata.rva + off for name, off in iat_offsets.items()}
                     if idata is not None else {})

        addresses = self._bind_addresses(table, layout, iat_slots)
        missing = self._missing_symbols(sections, addresses)
        if missing:
            name, site = missing[0]
            raise UndefinedSymbolError(name, site)

        contents: Dict[str, bytes] = {}
        base_relocs: List[Tuple[int, int]] = []
        resolve = addresses.__getitem__

        for placed in layout.sections:
            sec = placed.section
            blob = sec.relocated(resolve,
                                 base_va=layout.image_base + placed.rva,
                                 image_base=layout.image_base,
                                 section_index=placed.index)
            contents[sec.name] = bytes(blob)
            for r in sec.relocations:
                code = base_reloc_type(r.kind)
                if code is not None:
                    base_relocs.append((placed.rva + r.offset, code))

        base_relocs.sort()
        return LinkResult(layout=layout, contents=contents, addresses=addresses,
                          base_relocs=base_relocs,
                          iat_slots={n: layout.image_base + rva
                                     for n, rva in iat_slots.items()})

    def _missing_symbols(self, sections: Dict[str, Section],
                         addresses: Dict[str, int]) -> List[Tuple[str, str]]:
        """Every relocation target with no address, as ``(name, site)``."""
        missing: List[Tuple[str, str]] = []
        seen = set()
        for sec in sections.values():
            for r in sec.relocations:
                if r.symbol not in addresses and r.symbol not in seen:
                    seen.add(r.symbol)
                    missing.append((r.symbol, f'{sec.name}+0x{r.offset:x}'))
        return missing

    def relink(self, *, image_base: Optional[int] = None) -> LinkResult:
        """
        Link again, optionally at a new base.

        This exists to make the point concrete: rebasing or growing the image
        costs one more :meth:`link` call and needs no knowledge of what was
        emitted before.
        """
        if image_base is not None:
            self.image_base = image_base
        return self.link()


def build_base_reloc_blocks(relocs: Sequence[Tuple[int, int]],
                            page_size: int = 0x1000) -> bytes:
    """
    Encode ``(rva, type)`` pairs into a PE ``.reloc`` directory.

    Entries are grouped into per-page blocks and each block is padded to a
    4-byte boundary with ``IMAGE_REL_BASED_ABSOLUTE`` (type 0) filler, exactly
    as the loader expects.
    """
    if not relocs:
        return b''
    pages: Dict[int, List[Tuple[int, int]]] = {}
    for rva, kind in relocs:
        pages.setdefault(rva & ~(page_size - 1), []).append((rva, kind))

    out = bytearray()
    for page in sorted(pages):
        entries = sorted(pages[page])
        words = [((kind & 0xF) << 12) | ((rva - page) & 0xFFF)
                 for rva, kind in entries]
        if len(words) & 1:
            words.append(0)
        out += struct.pack('<II', page, 8 + 2 * len(words))
        for w in words:
            out += struct.pack('<H', w)
    return bytes(out)
