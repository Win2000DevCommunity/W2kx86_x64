"""
PE64 writer: turn a :class:`~x86x64.core.linker.LinkResult` into an image.

The writer is deliberately dumb.  Every address in the output already came out
of the linker, so this stage only serialises headers and copies section bytes
into place -- there is no address arithmetic here to get wrong, and no pass
that revisits emitted code.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..core.linker import LinkResult, align_up, build_base_reloc_blocks
from ..core.objfile import SectionFlags
from ..errors import LayoutError
from . import constants as C


@dataclass
class PE64Options:
    """Knobs for the emitted image."""

    entry_symbol: str = ''
    entry_rva: int = 0
    subsystem: int = C.IMAGE_SUBSYSTEM_WINDOWS_CUI
    is_dll: bool = False
    timestamp: int = 0
    #: Relocation-stripped images cannot be rebased; keep ASLR off unless the
    #: caller has emitted a full base relocation directory.
    dynamic_base: bool = False
    nx_compat: bool = True
    stack_reserve: int = 0x10_0000
    stack_commit: int = 0x1000
    heap_reserve: int = 0x10_0000
    heap_commit: int = 0x1000
    major_subsystem: int = 5
    minor_subsystem: int = 2

    @property
    def dll_characteristics(self) -> int:
        value = C.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
        if self.dynamic_base:
            value |= C.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if self.nx_compat:
            value |= C.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        return value

    @property
    def characteristics(self) -> int:
        value = (C.IMAGE_FILE_EXECUTABLE_IMAGE
                 | C.IMAGE_FILE_LARGE_ADDRESS_AWARE)
        if self.is_dll:
            value |= C.IMAGE_FILE_DLL
        return value


def _section_characteristics(flags: SectionFlags) -> int:
    """Map framework section flags onto PE characteristics."""
    out = 0
    if flags & SectionFlags.CODE:
        out |= C.IMAGE_SCN_CNT_CODE
    if flags & SectionFlags.INITIALIZED_DATA:
        out |= C.IMAGE_SCN_CNT_INITIALIZED_DATA
    if flags & SectionFlags.UNINITIALIZED_DATA:
        out |= C.IMAGE_SCN_CNT_UNINITIALIZED_DATA
    if flags & SectionFlags.EXECUTE:
        out |= C.IMAGE_SCN_MEM_EXECUTE
    if flags & SectionFlags.READ:
        out |= C.IMAGE_SCN_MEM_READ
    if flags & SectionFlags.WRITE:
        out |= C.IMAGE_SCN_MEM_WRITE
    if flags & SectionFlags.DISCARDABLE:
        out |= C.IMAGE_SCN_MEM_DISCARDABLE
    return out or C.IMAGE_SCN_CNT_INITIALIZED_DATA | C.IMAGE_SCN_MEM_READ


class PE64Writer:
    """Serialises a linked image to PE32+ bytes."""

    def __init__(self, result: LinkResult, options: Optional[PE64Options] = None):
        self.result = result
        self.options = options or PE64Options()
        self._directories: Dict[int, Tuple[int, int]] = {}

    # -- directories -----------------------------------------------------
    def set_directory(self, index: int, rva: int, size: int) -> None:
        self._directories[index] = (rva, size)

    def set_import_directory(self, rva: int, size: int) -> None:
        self.set_directory(C.DIR_IMPORT, rva, size)

    def set_iat_directory(self, rva: int, size: int) -> None:
        self.set_directory(C.DIR_IAT, rva, size)

    def set_export_directory(self, rva: int, size: int) -> None:
        self.set_directory(C.DIR_EXPORT, rva, size)

    def _auto_directories(self, reloc_rva: int, reloc_size: int) -> None:
        if reloc_size:
            self.set_directory(C.DIR_BASERELOC, reloc_rva, reloc_size)
        idata = self.result.layout.by_name('.idata')
        if idata is not None and C.DIR_IAT not in self._directories:
            self.set_iat_directory(idata.rva, idata.size)
        rsrc = self.result.layout.by_name('.rsrc')
        if rsrc is not None and C.DIR_RESOURCE not in self._directories:
            self.set_directory(C.DIR_RESOURCE, rsrc.rva, rsrc.size)

    # -- entry point -----------------------------------------------------
    def _entry_rva(self) -> int:
        if self.options.entry_symbol:
            return self.result.rva_of(self.options.entry_symbol)
        return self.options.entry_rva

    # -- emission --------------------------------------------------------
    def build(self) -> bytes:
        layout = self.result.layout
        placed = sorted(layout.sections, key=lambda p: p.rva)
        if not placed:
            raise LayoutError('cannot write a PE with no sections')

        reloc_blob = build_base_reloc_blocks(self.result.base_relocs)
        contents = dict(self.result.contents)

        # The .reloc directory is generated here rather than by an emitter,
        # since only the writer knows the final relocation set.
        if reloc_blob:
            existing = layout.by_name('.reloc')
            if existing is not None:
                contents['.reloc'] = reloc_blob
                reloc_rva = existing.rva
            else:
                reloc_rva = align_up(
                    max(p.end_rva for p in placed), layout.section_align)
        else:
            reloc_rva = 0
        self._auto_directories(reloc_rva, len(reloc_blob))

        synthetic_reloc = bool(reloc_blob) and layout.by_name('.reloc') is None
        n_sections = len(placed) + (1 if synthetic_reloc else 0)

        headers_size = align_up(
            len(C.DOS_STUB) + 4 + C.COFF_HEADER_SIZE + C.PE64_OPT_TOTAL
            + n_sections * C.SECTION_HEADER_SIZE,
            layout.file_align)

        # Re-derive file offsets: the linker's are advisory, and a synthetic
        # .reloc changes the packing.
        entries: List[Tuple[str, int, int, bytes, int]] = []
        file_off = headers_size
        for p in placed:
            blob = contents.get(p.name, b'')
            raw_size = align_up(len(blob), layout.file_align)
            has_raw = not (p.section.flags & SectionFlags.UNINITIALIZED_DATA)
            entries.append((p.name, p.rva, p.size, blob,
                            file_off if has_raw else 0))
            if has_raw:
                file_off += raw_size
        if synthetic_reloc:
            entries.append(('.reloc', reloc_rva, len(reloc_blob),
                            reloc_blob, file_off))
            file_off += align_up(len(reloc_blob), layout.file_align)

        image_size = align_up(
            max(rva + max(vsize, len(blob)) for _n, rva, vsize, blob, _f in entries),
            layout.section_align)

        out = bytearray()
        out += C.DOS_STUB
        out += C.PE_SIGNATURE
        out += struct.pack('<HHIIIHH',
                           C.IMAGE_FILE_MACHINE_AMD64, n_sections,
                           self.options.timestamp, 0, 0,
                           C.PE64_OPT_TOTAL, self.options.characteristics)

        code_size = sum(align_up(len(b), layout.file_align)
                        for _n, _r, _v, b, _f in entries
                        if _is_code(self.result, _n))
        base_of_code = next((r for n, r, _v, _b, _f in entries if n == '.text'),
                            layout.section_align)
        opt_start = len(out)

        # PE32+ drops the BaseOfData field that PE32 carries, so the standard
        # fields are 24 bytes here rather than 28.
        out += struct.pack(
            '<HBBIIIII',
            C.PE32PLUS_MAGIC, 14, 0,          # magic, linker major/minor
            code_size, 0, 0,                   # code, init data, uninit data
            self._entry_rva(), base_of_code)
        out += struct.pack('<Q', layout.image_base)
        out += struct.pack('<IIHHHHHHIIIIHH',
                           layout.section_align, layout.file_align,
                           5, 0,               # OS version
                           0, 0,               # image version
                           self.options.major_subsystem,
                           self.options.minor_subsystem,
                           0,                  # Win32 version
                           image_size, headers_size, 0,
                           self.options.subsystem,
                           self.options.dll_characteristics)
        out += struct.pack('<QQQQ',
                           self.options.stack_reserve, self.options.stack_commit,
                           self.options.heap_reserve, self.options.heap_commit)
        out += struct.pack('<II', 0, C.NUM_DATA_DIRECTORIES)
        for i in range(C.NUM_DATA_DIRECTORIES):
            out += struct.pack('<II', *self._directories.get(i, (0, 0)))

        written_opt = len(out) - opt_start
        if written_opt != C.PE64_OPT_TOTAL:
            raise LayoutError(
                f'optional header is {written_opt} bytes, expected '
                f'{C.PE64_OPT_TOTAL}')

        for name, rva, vsize, blob, foff in entries:
            section = layout.by_name(name)
            flags = (_section_characteristics(section.section.flags)
                     if section is not None
                     else C.IMAGE_SCN_CNT_INITIALIZED_DATA
                     | C.IMAGE_SCN_MEM_READ | C.IMAGE_SCN_MEM_DISCARDABLE)
            out += (name.encode('latin1')[:8].ljust(8, b'\x00')
                    + struct.pack('<IIII', max(vsize, len(blob)), rva,
                                  align_up(len(blob), layout.file_align), foff)
                    + struct.pack('<IIHHI', 0, 0, 0, 0, flags))

        out += bytes(headers_size - len(out))

        for _name, _rva, _vsize, blob, foff in entries:
            if not foff:
                continue
            if len(out) < foff:
                out += bytes(foff - len(out))
            out[foff:foff + len(blob)] = blob
            padded = align_up(len(blob), layout.file_align)
            if len(out) < foff + padded:
                out += bytes(foff + padded - len(out))

        return bytes(out)

    def write(self, path: str) -> int:
        blob = self.build()
        with open(path, 'wb') as fh:
            fh.write(blob)
        return len(blob)


def _is_code(result: LinkResult, name: str) -> bool:
    placed = result.layout.by_name(name)
    return bool(placed and placed.section.flags & SectionFlags.CODE)


def write_pe64(result: LinkResult, path: str,
               options: Optional[PE64Options] = None) -> int:
    """Convenience wrapper: link result in, file on disk out."""
    return PE64Writer(result, options).write(path)
