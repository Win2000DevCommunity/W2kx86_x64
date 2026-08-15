"""
PE32 reader for Windows 2000 binaries.

Sections are returned as :class:`PESection` objects that also support
``section['vaddr']`` indexing, because the legacy translator passes these
dictionaries around by key and both spellings need to work while the migration
proceeds.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..errors import PEFormatError
from . import constants as C


@dataclass
class PESection:
    """One section header plus helpers for the ranges it covers."""

    name: str
    vsize: int
    vaddr: int
    raw_sz: int
    raw_ptr: int
    flags: int
    reloc_ptr: int = 0
    nrelocs: int = 0

    # Legacy call sites index these like dictionaries.
    _KEYS = ('name', 'vsize', 'vaddr', 'raw_sz', 'raw_ptr',
             'reloc_ptr', 'nrelocs', 'flags')

    def __getitem__(self, key: str) -> Any:
        if key in self._KEYS:
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default) if key in self._KEYS else default

    def keys(self):
        return self._KEYS

    @property
    def end_rva(self) -> int:
        return self.vaddr + self.vsize

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & C.IMAGE_SCN_MEM_EXECUTE)

    @property
    def is_writable(self) -> bool:
        return bool(self.flags & C.IMAGE_SCN_MEM_WRITE)

    @property
    def is_code(self) -> bool:
        return bool(self.flags & C.IMAGE_SCN_CNT_CODE)

    def contains_rva(self, rva: int) -> bool:
        return self.vaddr <= rva < self.end_rva

    def __str__(self) -> str:
        return f'{self.name}@0x{self.vaddr:x}+0x{self.vsize:x}'


class PE32Image:
    """A parsed PE32 image."""

    def __init__(self, data: bytes) -> None:
        if data[:2] != C.DOS_SIGNATURE:
            raise PEFormatError('not a PE file (bad MZ signature)')
        self.raw = data

        self.pe_off = struct.unpack_from('<I', data, C.PE_OFFSET_FIELD)[0]
        if data[self.pe_off:self.pe_off + 4] != C.PE_SIGNATURE:
            raise PEFormatError('PE signature not found')

        coff = self.pe_off + 4
        (self.machine, self.num_sections, self.timestamp, _sym, _nsym,
         self.opt_header_sz, self.characteristics) = struct.unpack_from(
            '<HHIIIHH', data, coff)

        opt = coff + C.COFF_HEADER_SIZE
        self.magic = struct.unpack_from('<H', data, opt)[0]
        if self.magic != C.PE32_MAGIC:
            raise PEFormatError(
                f'expected a PE32 image, got optional header magic '
                f'0x{self.magic:04X}')

        self.entry_rva = struct.unpack_from('<I', data, opt + 16)[0]
        self.code_base = struct.unpack_from('<I', data, opt + 20)[0]
        self.data_base = struct.unpack_from('<I', data, opt + 24)[0]
        self.image_base = struct.unpack_from('<I', data, opt + 28)[0]
        self.sect_align = struct.unpack_from('<I', data, opt + 32)[0]
        self.file_align = struct.unpack_from('<I', data, opt + 36)[0]
        self.image_size = struct.unpack_from('<I', data, opt + 56)[0]
        self.header_size = struct.unpack_from('<I', data, opt + 60)[0]
        self.subsystem = struct.unpack_from('<H', data, opt + 68)[0]

        dd_off = opt + 96
        self.directories: List[Tuple[int, int]] = [
            struct.unpack_from('<II', data, dd_off + i * 8)
            for i in range(C.NUM_DATA_DIRECTORIES)
        ]

        self.sections: List[PESection] = []
        sec_hdr = opt + self.opt_header_sz
        for i in range(self.num_sections):
            sh = sec_hdr + i * C.SECTION_HEADER_SIZE
            raw_name = data[sh:sh + 8].rstrip(b'\x00')
            vsize, vaddr, raw_sz, raw_ptr, reloc_ptr = struct.unpack_from(
                '<IIIII', data, sh + 8)
            nrelocs = struct.unpack_from('<H', data, sh + 32)[0]
            flags = struct.unpack_from('<I', data, sh + 36)[0]
            self.sections.append(PESection(
                name=raw_name.decode('latin1'), vsize=vsize, vaddr=vaddr,
                raw_sz=raw_sz, raw_ptr=raw_ptr, flags=flags,
                reloc_ptr=reloc_ptr, nrelocs=nrelocs))

    # -- directories -----------------------------------------------------
    def directory(self, index: int) -> Tuple[int, int]:
        return self.directories[index]

    @property
    def dir_export(self) -> Tuple[int, int]:
        return self.directories[C.DIR_EXPORT]

    @property
    def dir_import(self) -> Tuple[int, int]:
        return self.directories[C.DIR_IMPORT]

    @property
    def dir_resource(self) -> Tuple[int, int]:
        return self.directories[C.DIR_RESOURCE]

    @property
    def dir_basereloc(self) -> Tuple[int, int]:
        return self.directories[C.DIR_BASERELOC]

    @property
    def dir_tls(self) -> Tuple[int, int]:
        return self.directories[C.DIR_TLS]

    @property
    def dir_iat(self) -> Tuple[int, int]:
        return self.directories[C.DIR_IAT]

    # -- flags -----------------------------------------------------------
    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & C.IMAGE_FILE_DLL)

    @property
    def is_exe(self) -> bool:
        return bool(self.characteristics & C.IMAGE_FILE_EXECUTABLE_IMAGE)

    # -- address translation ---------------------------------------------
    def section_for_rva(self, rva: int) -> Optional[PESection]:
        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def rva_to_offset(self, rva: int) -> Optional[int]:
        section = self.section_for_rva(rva)
        if section is None:
            return None
        return section.raw_ptr + (rva - section.vaddr)

    def va_to_offset(self, va: int) -> Optional[int]:
        return self.rva_to_offset(va - self.image_base)

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def contains_va(self, va: int) -> bool:
        return self.image_base <= va < self.image_base + self.image_size

    # -- content ---------------------------------------------------------
    def read_rva(self, rva: int, size: int) -> Optional[bytes]:
        off = self.rva_to_offset(rva)
        return None if off is None else self.raw[off:off + size]

    def read_cstring(self, rva: int, *, limit: int = 0x1000) -> str:
        off = self.rva_to_offset(rva)
        if off is None:
            return ''
        end = self.raw.find(b'\x00', off, off + limit)
        end = end if end >= 0 else off + limit
        return self.raw[off:end].decode('latin1', errors='replace')

    def get_section_data(self, section: PESection) -> bytes:
        """Section bytes, zero-padded out to the virtual size."""
        raw = self.raw[section.raw_ptr:section.raw_ptr + section.raw_sz]
        if section.vsize > len(raw):
            raw += bytes(section.vsize - len(raw))
        return raw

    def get_text_section(self) -> Optional[Tuple[PESection, bytes]]:
        for section in self.sections:
            if section.is_executable:
                return section, self.get_section_data(section)
        return None

    def get_executable_sections(self) -> List[Tuple[PESection, bytes]]:
        return [(s, self.get_section_data(s)) for s in self.sections
                if s.is_executable and s.raw_sz]

    # -- tables ----------------------------------------------------------
    def parse_exports(self) -> List[Dict[str, Any]]:
        rva, _size = self.dir_export
        off = self.rva_to_offset(rva) if rva else None
        if off is None:
            return []

        ord_base = struct.unpack_from('<I', self.raw, off + 16)[0]
        n_names = struct.unpack_from('<I', self.raw, off + 24)[0]
        funcs_rva, names_rva, ords_rva = struct.unpack_from(
            '<III', self.raw, off + 28)

        funcs_o = self.rva_to_offset(funcs_rva)
        names_o = self.rva_to_offset(names_rva)
        ords_o = self.rva_to_offset(ords_rva)
        if None in (funcs_o, names_o, ords_o):
            return []

        exports = []
        for i in range(n_names):
            name_rva = struct.unpack_from('<I', self.raw, names_o + i * 4)[0]
            ordi = struct.unpack_from('<H', self.raw, ords_o + i * 2)[0]
            func_rva = struct.unpack_from('<I', self.raw, funcs_o + ordi * 4)[0]
            exports.append({'name': self.read_cstring(name_rva),
                            'rva': func_rva, 'ordinal': ord_base + ordi,
                            'ord_idx': ordi})
        return exports

    def parse_imports(self) -> List[Dict[str, Any]]:
        rva, _size = self.dir_import
        off = self.rva_to_offset(rva) if rva else None
        if off is None:
            return []

        imports: List[Dict[str, Any]] = []
        while off + 20 <= len(self.raw):
            ilt_rva, _ts, _fwd, dll_rva, iat_rva = struct.unpack_from(
                '<IIIII', self.raw, off)
            off += 20
            if not ilt_rva and not dll_rva:
                break

            funcs: List[Dict[str, Any]] = []
            ilt_off = self.rva_to_offset(ilt_rva or iat_rva)
            if ilt_off is not None:
                idx = 0
                while True:
                    thunk = struct.unpack_from('<I', self.raw, ilt_off + idx * 4)[0]
                    if not thunk:
                        break
                    slot = iat_rva + idx * 4
                    if thunk & 0x8000_0000:
                        funcs.append({'ordinal': thunk & 0xFFFF, 'name': None,
                                      'hint': 0, 'iat_rva': slot})
                    else:
                        hint_off = self.rva_to_offset(thunk)
                        if hint_off is not None:
                            hint = struct.unpack_from('<H', self.raw, hint_off)[0]
                            end = self.raw.find(b'\x00', hint_off + 2)
                            name = self.raw[hint_off + 2:end].decode(
                                'latin1', errors='replace')
                        else:
                            hint, name = 0, '??'
                        funcs.append({'ordinal': None, 'name': name,
                                      'hint': hint, 'iat_rva': slot})
                    idx += 1

            imports.append({
                'dll': self.read_cstring(dll_rva) if dll_rva else '',
                'functions': funcs, 'iat_rva': iat_rva, 'ilt_rva': ilt_rva})
        return imports

    def parse_relocations(self, *, types=(C.IMAGE_REL_BASED_HIGHLOW,)
                          ) -> List[Tuple[int, int]]:
        """``(rva, type)`` pairs from the base relocation directory."""
        rva, size = self.dir_basereloc
        off = self.rva_to_offset(rva) if (rva and size) else None
        if off is None:
            return []

        wanted = frozenset(types)
        relocs: List[Tuple[int, int]] = []
        end = off + size
        while off + 8 <= end:
            page_rva, block_sz = struct.unpack_from('<II', self.raw, off)
            if block_sz < 8:
                break
            for i in range((block_sz - 8) // 2):
                entry = struct.unpack_from('<H', self.raw, off + 8 + i * 2)[0]
                rtype = (entry >> 12) & 0xF
                if rtype in wanted:
                    relocs.append((page_rva + (entry & 0xFFF), rtype))
            off += block_sz
        return relocs

    def __iter__(self) -> Iterator[PESection]:
        return iter(self.sections)

    def __repr__(self) -> str:
        kind = 'DLL' if self.is_dll else 'EXE'
        return (f'<PE32Image {kind} base=0x{self.image_base:x} '
                f'entry=0x{self.entry_rva:x} sections={len(self.sections)}>')


def load(path: str) -> PE32Image:
    with open(path, 'rb') as fh:
        return PE32Image(fh.read())
