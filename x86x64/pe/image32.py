"""The PE32 reader the legacy translator is built on.  New code should prefer
:mod:`x86x64.pe.pe32`.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403


class PE32Image:
    """Parse a Windows 2000 SP4 PE32 image."""

    def __init__(self, data: bytes):
        if data[:2] != b'MZ':
            raise ValueError("Not a PE file (bad MZ signature)")
        self.raw  = data
        self.pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if data[self.pe_off:self.pe_off+4] != b'PE\x00\x00':
            raise ValueError("PE signature not found")

        coff = self.pe_off + 4
        self.machine        = struct.unpack_from('<H', data, coff)[0]
        self.num_sections   = struct.unpack_from('<H', data, coff+2)[0]
        self.timestamp      = struct.unpack_from('<I', data, coff+4)[0]
        self.opt_header_sz  = struct.unpack_from('<H', data, coff+16)[0]
        self.characteristics= struct.unpack_from('<H', data, coff+18)[0]

        opt = coff + 20
        self.magic       = struct.unpack_from('<H', data, opt)[0]
        self.entry_rva   = struct.unpack_from('<I', data, opt+16)[0]
        self.image_base  = struct.unpack_from('<I', data, opt+28)[0]
        self.sect_align  = struct.unpack_from('<I', data, opt+32)[0]
        self.file_align  = struct.unpack_from('<I', data, opt+36)[0]
        self.image_size  = struct.unpack_from('<I', data, opt+56)[0]
        self.header_size = struct.unpack_from('<I', data, opt+60)[0]
        self.subsystem   = struct.unpack_from('<H', data, opt+68)[0]

        # Data directories (16 entries, 8 bytes each)
        dd_off = opt + 96
        def dd(i): return struct.unpack_from('<II', data, dd_off + i*8)
        self.dir_export    = dd(0)
        self.dir_import    = dd(1)
        self.dir_resource  = dd(2)
        self.dir_exception = dd(3)
        self.dir_security  = dd(4)
        self.dir_basereloc = dd(5)
        self.dir_debug     = dd(6)
        self.dir_tls       = dd(9)
        self.dir_iat       = dd(12)

        # Section headers
        sec_hdr = opt + self.opt_header_sz
        self.sections: List[Dict] = []
        for i in range(self.num_sections):
            sh = sec_hdr + i * 40
            name     = data[sh:sh+8].rstrip(b'\x00').decode('latin1')
            vsize    = struct.unpack_from('<I', data, sh+8)[0]
            vaddr    = struct.unpack_from('<I', data, sh+12)[0]
            raw_sz   = struct.unpack_from('<I', data, sh+16)[0]
            raw_ptr  = struct.unpack_from('<I', data, sh+20)[0]
            reloc_ptr= struct.unpack_from('<I', data, sh+24)[0]
            nrelocs  = struct.unpack_from('<H', data, sh+32)[0]
            flags    = struct.unpack_from('<I', data, sh+36)[0]
            self.sections.append({
                'name': name, 'vsize': vsize, 'vaddr': vaddr,
                'raw_sz': raw_sz, 'raw_ptr': raw_ptr,
                'reloc_ptr': reloc_ptr, 'nrelocs': nrelocs, 'flags': flags,
            })

        self.is_dll = bool(self.characteristics & 0x2000)
        self.is_exe = bool(self.characteristics & 0x0002)

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                return s['raw_ptr'] + (rva - s['vaddr'])
        return None

    def va_to_offset(self, va: int) -> Optional[int]:
        return self.rva_to_offset(va - self.image_base)

    def read_rva(self, rva: int, size: int) -> Optional[bytes]:
        off = self.rva_to_offset(rva)
        if off is None: return None
        return self.raw[off:off+size]

    def read_cstring(self, rva: int) -> str:
        off = self.rva_to_offset(rva)
        if off is None: return ''
        return self.raw[off:].split(b'\x00',1)[0].decode('latin1', errors='replace')

    def section_for_rva(self, rva: int) -> Optional[Dict]:
        for s in self.sections:
            if s['vaddr'] <= rva < s['vaddr'] + s['vsize']:
                return s
        return None

    def get_section_data(self, section: Dict) -> bytes:
        p = section['raw_ptr']; sz = section['raw_sz']
        raw = self.raw[p:p + sz]
        vsize = section['vsize']
        if vsize > len(raw):
            raw = raw + b'\x00' * (vsize - len(raw))
        return raw

    # ── Export table ───────────────────────────────────────────────────────────
    def parse_exports(self) -> List[Dict]:
        rva, sz = self.dir_export
        if not rva: return []
        off = self.rva_to_offset(rva)
        if off is None: return []
        ordbase  = struct.unpack_from('<I', self.raw, off+16)[0]
        nfuncs   = struct.unpack_from('<I', self.raw, off+20)[0]
        nnames   = struct.unpack_from('<I', self.raw, off+24)[0]
        funcs_rva= struct.unpack_from('<I', self.raw, off+28)[0]
        names_rva= struct.unpack_from('<I', self.raw, off+32)[0]
        ords_rva = struct.unpack_from('<I', self.raw, off+36)[0]
        funcs_o  = self.rva_to_offset(funcs_rva)
        names_o  = self.rva_to_offset(names_rva)
        ords_o   = self.rva_to_offset(ords_rva)
        if None in (funcs_o, names_o, ords_o): return []
        exports = []
        for i in range(nnames):
            name_rva = struct.unpack_from('<I', self.raw, names_o + i*4)[0]
            ordi     = struct.unpack_from('<H', self.raw, ords_o  + i*2)[0]
            func_rva = struct.unpack_from('<I', self.raw, funcs_o + ordi*4)[0]
            name     = self.read_cstring(name_rva)
            exports.append({'name': name, 'rva': func_rva,
                            'ordinal': ordbase + ordi, 'ord_idx': ordi})
        return exports

    # ── Import table ───────────────────────────────────────────────────────────
    def parse_imports(self) -> List[Dict]:
        rva, sz = self.dir_import
        if not rva: return []
        imports = []
        off = self.rva_to_offset(rva)
        if off is None: return []
        while True:
            ilt_rva, ts, fwd, dll_rva, iat_rva = struct.unpack_from('<IIIII', self.raw, off)
            off += 20
            if ilt_rva == 0 and dll_rva == 0: break
            dll_name = self.read_cstring(dll_rva) if dll_rva else ''
            funcs = []
            ilt_off = self.rva_to_offset(ilt_rva or iat_rva)
            iat_off = self.rva_to_offset(iat_rva)
            if ilt_off:
                idx = 0
                while True:
                    thunk = struct.unpack_from('<I', self.raw, ilt_off + idx*4)[0]
                    if thunk == 0: break
                    if thunk & 0x80000000:  # ordinal
                        funcs.append({'ordinal': thunk & 0xFFFF, 'name': None,
                                      'hint': 0, 'iat_rva': iat_rva + idx*4})
                    else:
                        hint_off = self.rva_to_offset(thunk)
                        if hint_off:
                            hint = struct.unpack_from('<H', self.raw, hint_off)[0]
                            fname = self.raw[hint_off+2:].split(b'\x00',1)[0].decode('latin1','replace')
                        else:
                            hint, fname = 0, '??'
                        funcs.append({'ordinal': None, 'name': fname,
                                      'hint': hint, 'iat_rva': iat_rva + idx*4})
                    idx += 1
            imports.append({'dll': dll_name, 'functions': funcs,
                            'iat_rva': iat_rva, 'ilt_rva': ilt_rva})
        return imports

    # ── Base relocations ───────────────────────────────────────────────────────
    def parse_relocations(self) -> List[Tuple[int,int]]:
        """Return list of (rva, type) pairs from .reloc directory."""
        rva, sz = self.dir_basereloc
        if not rva or not sz: return []
        relocs = []
        off = self.rva_to_offset(rva)
        if off is None: return []
        end = off + sz
        while off < end:
            page_rva = struct.unpack_from('<I', self.raw, off)[0]
            blk_sz   = struct.unpack_from('<I', self.raw, off+4)[0]
            if blk_sz < 8: break
            for i in range((blk_sz - 8) // 2):
                entry = struct.unpack_from('<H', self.raw, off + 8 + i*2)[0]
                rtype = (entry >> 12) & 0xF
                roff  = entry & 0xFFF
                if rtype == 3:   # IMAGE_REL_BASED_HIGHLOW — standard 32-bit
                    relocs.append((page_rva + roff, rtype))
                elif rtype == 0: # padding
                    pass
            off += blk_sz
        return relocs

    def get_text_section(self) -> Optional[Tuple[Dict, bytes]]:
        for s in self.sections:
            if s['flags'] & 0x20000000:   # IMAGE_SCN_MEM_EXECUTE
                return (s, self.get_section_data(s))
        return None

    def get_executable_sections(self) -> List[Tuple[Dict, bytes]]:
        result = []
        for s in self.sections:
            if s['flags'] & 0x20000000 and s['raw_sz']:
                result.append((s, self.get_section_data(s)))
        return result
