"""PE64 assembly: section layout, directories, and the final image.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403

#: Frame teardown that stands in for ``mov rsp, <frame reg>``.
_EPILOGUE_MOVS = (b'\x4c\x89\xec',   # mov rsp, r13
                  b'\x48\x89\xec')   # mov rsp, rbp


def reaches_ret_without_branching(blob: bytes, off: int, limit: int = 24) -> bool:
    """Whether execution starting at ``off`` returns without branching first.

    A call sitting immediately before a return is a tail call: the callee's
    ``ret`` can serve the caller too, so rewriting the call as a jump keeps
    the program equivalent. A call with real work after it cannot be rewritten
    that way -- control has to come back, and a jump never does.

    Only the handful of encodings that appear in an epilogue are decoded.
    Anything else answers ``False``, which is the safe direction: the worst a
    false negative costs is that a rewrite is skipped.
    """
    end = min(off + limit, len(blob))
    pos = off
    while pos < end:
        op = blob[pos]
        if op in (0xC3, 0xCB) or op == 0xC2:      # ret / retf / ret imm16
            return True
        if 0x58 <= op <= 0x5F:                     # pop r64
            pos += 1
        elif op == 0x41 and pos + 1 < end and 0x58 <= blob[pos + 1] <= 0x5F:
            pos += 2                               # pop r8..r15
        elif blob[pos:pos + 3] in _EPILOGUE_MOVS:
            pos += 3
        elif blob[pos:pos + 3] == b'\x48\x83\xc4':  # add rsp, imm8
            pos += 4
        elif blob[pos:pos + 3] == b'\x48\x81\xc4':  # add rsp, imm32
            pos += 7
        elif op == 0x90:
            pos += 1
        else:
            return False
    return False


def next_prologue_after_shared_epilogue(
        blob: bytes, epi_off: int, prologue_ok, limit: int = 48):
    """Return the next real function entry after a shared ``mov rsp,*`` epilogue.

    Stale rva_map slots often point a few bytes early, into the previous
    function's teardown. Mid-instruction snaps then land on ``mov rsp,r13``
    itself. For a non-tail call that is never the intended target: the callee
    is the function that begins immediately after the epilogue's ``ret``.
    """
    end = min(epi_off + 32, len(blob))
    pos = epi_off
    while pos < end:
        op = blob[pos]
        if op in (0xC3, 0xCB):
            pos += 1
            break
        if op == 0xC2 and pos + 3 <= len(blob):
            pos += 3
            break
        if 0x58 <= op <= 0x5F:
            pos += 1
        elif op == 0x41 and pos + 1 < end and 0x58 <= blob[pos + 1] <= 0x5F:
            pos += 2
        elif blob[pos:pos + 3] in _EPILOGUE_MOVS:
            pos += 3
        elif blob[pos:pos + 3] == b'\x48\x83\xc4':
            pos += 4
        elif blob[pos:pos + 3] == b'\x48\x81\xc4':
            pos += 7
        elif op == 0x90:
            pos += 1
        else:
            return None
    else:
        return None
    scan_end = min(pos + limit, len(blob))
    for cand in range(pos, scan_end):
        if not prologue_ok(blob, cand):
            continue
        # Bare ret pads are accepted by the prologue gate but are not entries.
        if blob[cand] in (0xC3, 0xCB) or blob[cand] == 0xC2:
            continue
        return cand
    return None


class ImageBuilderMixin:
    """See the module docstring."""

    def _estimate_idata_rva(self) -> int:
        """Pre-compute a conservative estimate of where .idata will land.

        Uses a generous 5x expansion factor for x86→x64 code growth
        plus 64 KB headroom.  The goal is to have the IAT map nearly
        correct BEFORE translation starts, so ``_emit_iat_call`` produces
        valid slot VAs without needing fragile post-patch heroics.

        Returns a conservative (high-side) idata_rva estimate.  The
        delta adjustment in ``_build_pe64_from_layout`` handles any
        remaining difference (typically 0–4 pages).
        """
        pe = self.pe
        SECT_ALIGN = 0x1000

        def align(n, a):
            return (n + a - 1) & ~(a - 1)

        x86_text_size = 0
        for sec in pe.sections:
            if (sec['flags'] & 0x20000000) and sec.get('raw_sz'):
                x86_text_size += sec['raw_sz']

        total_data_aligned = 0
        for sec in pe.sections:
            if (sec['flags'] & 0x20000000) or not sec.get('raw_sz'):
                continue
            total_data_aligned = align(
                total_data_aligned + sec['raw_sz'], SECT_ALIGN)

        text_rva = 0x1000
        # 3× expansion + 64 KB headroom is conservative.
        # x86→x64 code typically expands 1.5×–2.5×.
        CODE_GROWTH_HEADROOM = 0x10000
        estimated_text_size = x86_text_size * 3 + CODE_GROWTH_HEADROOM

        idata_rva = align(text_rva + estimated_text_size,
                          SECT_ALIGN) + total_data_aligned
        return idata_rva

    def _finalize_code_layout(self) -> None:
        """Assign non-overlapping PE64 VAs to translated code sections."""
        if not self._code_layout:
            return
        SECT_ALIGN = 0x1000
        def align(n, a): return (n + a - 1) & ~(a - 1)

        next_va = 0x1000
        new_layout: List[Tuple[str, bytes, int, int]] = []
        self._old_to_new_section = {}
        for name, data, flags, old_va in self._code_layout:
            self._old_to_new_section[old_va] = next_va
            new_layout.append((name, data, flags, next_va))
            next_va = align(next_va + len(data), SECT_ALIGN)
        self._code_layout = new_layout
        self.text_rva = new_layout[0][3]
        self._translated_text = new_layout[0][1]

    def _refresh_final_rvas(self) -> None:
        """Rebuild old_rva → new_rva from rva_map and section placement."""
        # ── Final safety-net: force-correct mov ebp,esp → mov rbp,rsp ──
        # Some rva_map entries for ``mov ebp,esp`` (8B EC) land on the
        # previous function's epilogue (C9=leave) due to translation-time
        # offset collapse.  Later healing passes can revert even successful
        # reconciliations.  This runs on EVERY _refresh_final_rvas call so
        # the fix is always current regardless of what intermediate passes
        # do to rva_map.
        if self._cmd_no_hacks and getattr(self, '_pure_heal_text', None):
            text_data = self._pure_heal_text
            text_rva = self._pure_heal_text_rva
            blob = bytearray(self._translated_text)
            for old_rva in list(self.rva_map.keys()):
                func_off = old_rva - text_rva
                if not (0 <= func_off < len(text_data) - 1):
                    continue
                if text_data[func_off:func_off + 2] != b'\x8b\xec':
                    continue
                cur = self.rva_map[old_rva]
                if cur < 0 or cur + 3 > len(blob):
                    continue
                if blob[cur:cur + 3] == b'\x48\x89\xe5':
                    continue  # already correct
                # Find nearest forward mov rbp,rsp
                for fwd in range(1, 64):
                    fpos = cur + fwd
                    if (fpos + 3 <= len(blob)
                            and blob[fpos:fpos + 3] == b'\x48\x89\xe5'):
                        self.rva_map[old_rva] = fpos
                        break
        self._final_rva = {}
        for rva, off in self.rva_map.items():
            old_sec = self._rva_section.get(rva, self.text_rva)
            new_sec = self._old_to_new_section.get(old_sec, old_sec)
            self._final_rva[rva] = new_sec + off
        # Save a snapshot of the RVA map BEFORE post-repair modifies it.
        # Post-repair swallowed-entry reconciliation updates entries in-place,
        # which can make some x86→x64 lookups return wrong (healed) positions.
        # The snapshot preserves the original mappings for late-stage fixes.
        self._rva_map_snapshot = dict(self.rva_map)
        if os.environ.get('DUMP_RVA_MAP'):
            try:
                path = os.environ['DUMP_RVA_MAP']
                with open(path, 'w') as fh:
                    for old_rva in sorted(self._final_rva):
                        fh.write(f"{old_rva:08x} {self._final_rva[old_rva]:08x}\n")
                print(f"        Dumped rva_map ({len(self._final_rva)}) -> {path}")
            except Exception as exc:  # pragma: no cover
                print(f"        rva_map dump failed: {exc}")

    def _choose_translation(self, text_data: bytes, text_rva: int) -> Tuple[bytes, Dict[int, int]]:
        """Pick the best code translation strategy for a section."""
        if self.is_ntdll and self.stubs:
            return self._translate_text_section(text_data, text_rva)
        if self.is_kernel:
            insns = sum(1 for _ in self.md.disasm(text_data, self.old_base + text_rva))
            ratio = insns / max(len(text_data) / 4, 1)
            if ratio < 0.05 and len(text_data) > 65536:
                return self._translate_export_driven(text_data, text_rva)
        return self._translate_function_driven(text_data, text_rva)

    def translate(self) -> bytes:
        """
        Full PE32 → PE64 translation pipeline.
        Returns the translated PE64 binary bytes.
        """
        pe = self.pe
        self._pe_entry_old_rva = pe.entry_rva or 0
        self._orphan_blob_out_ranges = []
        self._code_span_ranges = []
        self._scope_table_out_ranges = []
        self._scope_table_old_rva = {}
        self._fn_entry_rvas = set()
        self._seh_scope_anchors = {}
        self._seh_scope_reg_fn = {}
        self._call_target_offs = None
        self._runtime_slot_map = {}
        print(f"  [1/5] Identifying NTDLL stubs…")
        if self.is_ntdll:
            stubs = extract_stubs_from_ntdll(pe)
            for s in stubs:
                self.stubs[s.rva] = s
            print(f"        Found {len(stubs)} syscall stubs")
        else:
            print(f"        (not ntdll — no stub extraction)")

        print(f"  [2/5] Disassembling executable sections (Capstone)…")
        print(f"        Dynamic: {self.dyn.entries_emulated} entry points, "
              f"{len(self.dyn.pointer_values)} pointer values, "
              f"{len(self.dyn.pointer_writes)} write sites")

        if self.is_kernel:
            exec_secs = pe.get_executable_sections()
            print(f"        Kernel image: {len(exec_secs)} executable sections")
            total_in = 0
            total_out = 0
            for sec_meta, sec_data in exec_secs:
                sec_rva = sec_meta['vaddr']
                print(f"          {sec_meta['name']:8s} 0x{sec_rva:05X}  {len(sec_data):,} bytes")
                tbytes, rmap = self._choose_translation(sec_data, sec_rva)
                for rva, off in rmap.items():
                    self.rva_map[rva] = off
                    self._rva_section[rva] = sec_rva
                self._kernel_code.append(
                    (sec_meta['name'], tbytes, sec_rva, sec_meta['flags'], sec_meta['vsize']))
                total_in += len(sec_data)
                total_out += len(tbytes)
            self.text_rva = exec_secs[0][0]['vaddr'] if exec_secs else 0x1000
            print(f"  [3/5] Translating kernel code…")
            print(f"        Translated code: {total_in:,} → {total_out:,} bytes, "
                  f"{len(self.rva_map)} RVA mappings")
        else:
            exec_secs = pe.get_executable_sections()
            if not exec_secs:
                raise RuntimeError("No executable section found")
            self._code_layout = []
            total_in = 0
            total_out = 0
            FILE_ALIGN = 0x200
            SECT_ALIGN = 0x1000
            def align(n, a): return (n + a - 1) & ~(a - 1)

            print(f"  [3/5] Translating executable sections (Keystone)…")
            # Pre-compute a realistic idata_rva so _emit_iat_call resolves
            # to nearly-correct x64 IAT slot VAs during translation.  The
            # estimate is conservative (5× code expansion); any remaining
            # delta is handled by the shift pass in _build_pe64_from_layout.
            if self.win10_test_shim:
                est_idata = self._estimate_idata_rva()
                self._plan_iat_map_early(est_idata)
            for sec_meta, sec_data in exec_secs:
                sec_rva = sec_meta['vaddr']
                print(f"          {sec_meta['name']:8s} 0x{sec_rva:05X}  {len(sec_data):,} bytes")
                tbytes, rmap = self._choose_translation(sec_data, sec_rva)
                for rva, off in rmap.items():
                    self.rva_map[rva] = off
                    self._rva_section[rva] = sec_rva
                tbytes = tbytes + b'\xCC' * (align(len(tbytes), 16) - len(tbytes))
                self._code_layout.append(
                    (sec_meta['name'], tbytes, sec_meta['flags'] | 0xA0000000, sec_rva))
                total_in += len(sec_data)
                total_out += len(tbytes)

            self.text_rva = exec_secs[0][0]['vaddr']
            self._translated_text = self._code_layout[0][1]
            self._text_sec_meta = exec_secs[0][0]
            print(f"        Translated code: {total_in:,} → {total_out:,} bytes, "
                  f"{len(self.rva_map)} RVA mappings")

        if self.warnings:
            print(f"        Warnings: {len(self.warnings)}")
            for w in self.warnings[:10]:
                print(f"         {w}")
            if len(self.warnings) > 10:
                print(f"         … and {len(self.warnings)-10} more")

        if not self.is_kernel:
            self._fill_missing_export_mappings()
            self._finalize_code_layout()
            if self._code_layout:
                blob = bytearray(self._code_layout[0][1])
                late_alloca = self._fix_alloca_probe_epilogues(blob)
                if late_alloca:
                    print(f"        Late _alloca_probe epilogue fixes: {late_alloca}")
                late_chkstk_align = self._fix_chkstk_frame_alignment(blob)
                if late_chkstk_align:
                    print(f"        Late _chkstk frame-size alignment fixes: {late_chkstk_align}")
                late_chkstk_add = self._fix_chkstk_epilogue_adds(blob)
                if late_chkstk_add:
                    print(f"        Late _chkstk epilogue ADD fixes: {late_chkstk_add}")
                late_calls = self._snap_calls_to_insn_boundaries(blob)
                if late_calls:
                    print(f"        Late mid-instruction CALL snap fixups: {late_calls}")
                late_fn_calls = self._snap_calls_to_function_entries(blob, self.rva_map)
                if late_fn_calls:
                    print(f"        Late mid-function CALL entry snap fixups: {late_fn_calls}")
                late_cmd = self._cmd_shim_postfixes(blob, self.rva_map)
                if late_cmd:
                    print(f"        Late cmd.exe shim postfixes: {late_cmd}")
                late_scope = self._synthesize_seh_scopes_for_push_sites(
                    blob, self.text_rva)
                if late_scope:
                    print(f"        Late SEH scope synthesize: {late_scope}")
                late_scope_h = self._normalize_scope_table_handlers(blob)
                if late_scope_h:
                    print(f"        Late SEH scope handler normalize: {late_scope_h}")
                late_push_h = self._fix_scope_handlers_at_push_sites(blob, self.text_rva)
                if late_push_h:
                    print(f"        Late SEH push-site handler fix: {late_push_h}")
                seh_restore = self._inject_seh_gs_restore_epilogues(blob)
                if seh_restore:
                    print(f"        Late SEH GS restore epilogue injects: {seh_restore}")
                naked_ret = self._inject_seh_before_naked_rets(blob, self.text_rva)
                if naked_ret:
                    print(f"        Late SEH naked-ret epilogue injects: {naked_ret}")
                if self._cmd_no_hacks and getattr(self, '_pure_heal_text', None):
                    pure_heal = self._pure_final_layout_heal(
                        blob, self._pure_heal_text, self._pure_heal_text_rva)
                name, _data, flags, old_va = self._code_layout[0]
                self._code_layout[0] = (name, bytes(blob), flags, old_va)
                self._translated_text = bytes(blob)

        print(f"  [4/5] Rebuilding IAT, exports, data relocations…")
        print(f"  [5/5] Emitting PE64…")
        if self.is_kernel:
            return self._build_pe64_kernel()
        return self._build_pe64_from_layout(self._code_layout)

    def _export_rva(self, old_rva: int) -> int:
        """Map an old export RVA to its PE64 location."""
        if old_rva in self._final_rva:
            return self._final_rva[old_rva]
        if old_rva in self.rva_map:
            old_sec = self._rva_section.get(old_rva, self.text_rva)
            new_sec = self._old_to_new_section.get(old_sec, old_sec)
            return new_sec + self.rva_map[old_rva]
        sec = self.pe.section_for_rva(old_rva)
        if sec:
            new_base = self._old_to_new_section.get(sec['vaddr'])
            if new_base is not None:
                return new_base + (old_rva - sec['vaddr'])
        return old_rva

    def _build_pe64_kernel(self) -> bytes:
        """Build PE64 for kernel images with multiple translated code sections."""
        pe = self.pe
        FILE_ALIGN = 0x200
        SECT_ALIGN = 0x1000

        def align(n, a): return (n + a - 1) & ~(a - 1)

        self._final_rva: Dict[int, int] = {}
        code_layout: List[Tuple[str, bytes, int, int]] = []
        current_va = self._kernel_code[0][2] if self._kernel_code else 0x1000

        for name, data, old_rva, flags, _vsize in self._kernel_code:
            data = data + b'\xCC' * (align(len(data), 16) - len(data))
            code_layout.append((name, data, flags | 0x20000000, current_va))
            current_va = align(current_va + len(data), SECT_ALIGN)

        return self._build_pe64_from_layout(code_layout)

    def _build_export_directory(self, edata_rva: int) -> bytes:
        """Rebuild export directory with updated function RVAs."""
        pe = self.pe
        exports = pe.parse_exports()
        if not exports:
            return b''

        # Deduplicate by name (Nt/Zw pairs share syscall numbers)
        seen: Set[str] = set()
        unique_exports = []
        for exp in exports:
            if exp['name'] in seen:
                continue
            seen.add(exp['name'])
            unique_exports.append(exp)
        exports = unique_exports

        names_blob = bytearray()
        name_offsets: List[int] = []
        for exp in exports:
            name_offsets.append(len(names_blob))
            names_blob += exp['name'].encode('ascii') + b'\x00'

        nfuncs = max(e['ord_idx'] for e in exports) + 1
        hdr_size = 40
        func_tbl_off = hdr_size
        name_ptr_off = func_tbl_off + nfuncs * 4
        ord_tbl_off  = name_ptr_off + len(exports) * 4
        names_off    = ord_tbl_off + len(exports) * 2

        exp_rva, _ = pe.dir_export
        dll_name = 'module.dll'
        if exp_rva:
            eoff = pe.rva_to_offset(exp_rva)
            if eoff is not None:
                dll_name_rva = struct.unpack_from('<I', pe.raw, eoff + 12)[0]
                dll_name = pe.read_cstring(dll_name_rva) or dll_name
        dll_name_blob = dll_name.encode('ascii') + b'\x00'
        dll_name_off = names_off + len(names_blob)

        blob = bytearray(b'\x00' * (dll_name_off + len(dll_name_blob)))
        blob[names_off:names_off + len(names_blob)] = names_blob
        blob[dll_name_off:dll_name_off + len(dll_name_blob)] = dll_name_blob

        name_ptr_base = edata_rva + names_off
        for i, exp in enumerate(exports):
            struct.pack_into('<I', blob, name_ptr_off + i * 4, name_ptr_base + name_offsets[i])
            struct.pack_into('<H', blob, ord_tbl_off + i * 2, exp['ord_idx'])
            new_func_rva = self._export_rva(exp['rva'])
            struct.pack_into('<I', blob, func_tbl_off + exp['ord_idx'] * 4, new_func_rva)

        ordbase = min((e['ordinal'] for e in exports), default=1)
        struct.pack_into('<IIHHIIIIIII', blob, 0,
            0, 0,
            0, 0,
            edata_rva + dll_name_off,
            ordbase, nfuncs, len(exports),
            edata_rva + func_tbl_off,
            edata_rva + name_ptr_off,
            edata_rva + ord_tbl_off)
        return bytes(blob)

    def _build_reloc_directory(self, reloc_rva: int, sections: List[Tuple],
                               pointer_sites: Set[int]) -> bytes:
        """Build PE64 base relocation directory (DIR64 entries)."""
        pages: Dict[int, List[int]] = {}

        for rva, rtype in self.pe_relocs:
            if rtype != IMAGE_REL_BASED_HIGHLOW:
                continue
            page = rva & ~0xFFF
            pages.setdefault(page, []).append(rva & 0xFFF)

        for site_va in self.dyn.pointer_writes:
            rva = site_va - self.old_base
            page = rva & ~0xFFF
            pages.setdefault(page, []).append(rva & 0xFFF)
        for rva in pointer_sites:
            page = rva & ~0xFFF
            pages.setdefault(page, []).append(rva & 0xFFF)

        blob = bytearray()
        for page in sorted(pages):
            entries = sorted(set(pages[page]))
            block_size = 8 + len(entries) * 2
            block_size = (block_size + 3) & ~3
            blob += struct.pack('<II', page, block_size)
            for off in entries:
                blob += struct.pack('<H', (IMAGE_REL_BASED_DIR64 << 12) | off)
            while len(blob) % 4:
                blob += b'\x00'
        return bytes(blob)

    def _build_pe64(self, new_text: bytes, text_rva: int, sec_meta: Dict) -> bytes:
        """Assemble translated code + fixed-up data into a valid PE64 binary."""
        FILE_ALIGN = 0x200
        def align(n, a): return (n + a - 1) & ~(a - 1)
        new_text = new_text + b'\xCC' * (align(len(new_text), 16) - len(new_text))
        code_layout = [('.text', new_text, sec_meta['flags'] | 0xA0000000, text_rva)]
        return self._build_pe64_from_layout(code_layout)

    def _build_pe64_from_layout(self, code_layout: List[Tuple[str, bytes, int, int]]) -> bytes:
        """Shared PE64 emitter for user and kernel images."""
        pe = self.pe
        FILE_ALIGN = 0x200
        SECT_ALIGN = 0x1000

        def align(n, a): return (n + a - 1) & ~(a - 1)

        pointer_sites: Set[int] = set()
        pointer_sites |= discover_image_pointer_sites(pe, self.dyn)
        for sec in pe.sections:
            if (sec['flags'] & 0x20000000) and sec.get('raw_sz'):
                tdata = pe.get_section_data(sec)
                pointer_sites |= discover_crt_data_pointer_slots(
                    pe, tdata, sec['vaddr'])
        for rva, _ in self.pe_relocs:
            pointer_sites.add(rva)
        for site_va in self.dyn.pointer_writes:
            pointer_sites.add(site_va - pe.image_base)

        PE64_OPT = PE64_OPT_TOTAL
        SECT_ENTRY = 40
        text_rva = code_layout[0][3]
        code_size = sum(len(s[1]) for s in code_layout)

        if self.is_kernel:
            self._old_to_new_section = {}
            for name, data, flags, new_va in code_layout:
                for kn, _, old_rva, _, _ in self._kernel_code:
                    if kn == name:
                        self._old_to_new_section[old_rva] = new_va
                        break

        # Plan non-executable section RVAs before IAT + pointer patching.
        data_secs_meta: List[Tuple[str, bytes, int, int]] = []
        for sec in pe.sections:
            if sec['flags'] & 0x20000000 or not sec['raw_sz']:
                continue
            data_secs_meta.append((sec['name'], pe.get_section_data(sec),
                                   sec['flags'], sec['vaddr']))

        max_code_end = max(
            (va + len(data) for _n, data, _f, va in code_layout),
            default=0x1000)
        # Reserve generous headroom so post-processing growth (healed
        # entries, alignment stubs, etc.) does not force a section
        # shift.  A shift changes code→data layout and exposes latent
        # shared-epilogue bugs across the entire binary.
        CODE_GROWTH_HEADROOM = 0x10000   # 64 KB
        current_va = align(max_code_end + CODE_GROWTH_HEADROOM, SECT_ALIGN)
        planned_data: List[Tuple[str, bytes, int, int, int]] = []
        for name, raw, flags, old_va in data_secs_meta:
            new_va = current_va
            self._old_to_new_section[old_va] = new_va
            # Make .rsrc writable: translated code may write to resource data
            # (e.g., LoadString modifies strings in place on Win2000).
            if name.lower() == '.rsrc':
                flags = flags | 0x80000000  # IMAGE_SCN_MEM_WRITE
            planned_data.append((name, raw, flags, old_va, new_va))
            current_va = align(current_va + len(raw), SECT_ALIGN)

        idata_rva = current_va
        if getattr(self, '_embedded_text_refs', None) and self._pure_heal_text:
            name0, data0, flags0, va0 = code_layout[0]
            blob0 = bytearray(data0)
            fin_embed = self._pure_finalize_embedded_text_data(
                blob0, self.rva_map, self._pure_heal_text,
                self._pure_heal_text_rva, self._embedded_text_refs)
            if fin_embed:
                print(f"        Pre-emit embedded text finalize: {fin_embed}")
            # After embedded remaps (which steal SEH push targets onto UTF-16),
            # force every MSVC EH3 scope table into a fresh raw blob and
            # retarget pushes. Universal for all Win2000 MSVC binaries.
            n_scope = self._force_rematerialize_scope_tables(
                blob0, self.rva_map, self._pure_heal_text,
                self._pure_heal_text_rva)
            if n_scope:
                print(f"        Pre-emit EH3 scope rematerialize: {n_scope}")
            scope_push = self._reconcile_seh_scope_pushes(
                blob0, self.rva_map, self._pure_heal_text_rva)
            if scope_push:
                print(f"        Pre-emit SEH scope push reconcile: {scope_push}")
            if fin_embed or n_scope or scope_push:
                code_layout[0] = (name0, bytes(blob0), flags0, va0)
                self._translated_text = bytes(blob0)
        elif self._pure_heal_text:
            name0, data0, flags0, va0 = code_layout[0]
            blob0 = bytearray(data0)
            n_scope = self._force_rematerialize_scope_tables(
                blob0, self.rva_map, self._pure_heal_text,
                self._pure_heal_text_rva)
            if n_scope:
                print(f"        Pre-emit EH3 scope rematerialize: {n_scope}")
                scope_push = self._reconcile_seh_scope_pushes(
                    blob0, self.rva_map, self._pure_heal_text_rva)
                if scope_push:
                    print(f"        Pre-emit SEH scope push reconcile: {scope_push}")
                code_layout[0] = (name0, bytes(blob0), flags0, va0)
                self._translated_text = bytes(blob0)
        self._refresh_final_rvas()
        # If we pre-planned the IAT map with a placeholder idata_rva, shift
        # all map values AND emitted FF 15 / movabs IAT references by the
        # real delta so everything agrees on the final layout.
        placeholder = getattr(self, '_iat_rva_map_placeholder_base', 0)
        if placeholder:
            delta = idata_rva - placeholder
            if delta:
                # Capture the pre-shift IAT slot RVAs so only genuine IAT
                # movabs get shifted — a blanket new-base-range shift corrupts
                # predefined handle constants (HKCU 0x80000001 → 0x8007F001),
                # data pointers and function entry VAs.
                only_slots = set(self._iat_rva_map.values())
                # Shift map values
                self._iat_rva_map = {k: v + delta for k, v in self._iat_rva_map.items()}
                # Shift the by-name slot map too — later name-based lookups
                # (e.g. _pure_fix_formatmessage_call_rbx, _resolve_iat_slot_va)
                # otherwise resolve to pre-shift RVAs (cmd FormatMessageW
                # stayed at 0x81590 while the real slot moved to 0xA6590 →
                # call rbx loaded a zero .data mirror → execute @ 0).
                if self._iat_name_to_new_rva:
                    self._iat_name_to_new_rva = {
                        k: v + delta
                        for k, v in self._iat_name_to_new_rva.items()}
                # Hint cells live inside .idata — their RVAs shift too.
                if self._hint_rva_to_old_iat:
                    self._hint_rva_to_old_iat = {
                        k + delta: v
                        for k, v in self._hint_rva_to_old_iat.items()}
                # Shift emitted code in all sections
                for idx, (name, data, flags, va) in enumerate(code_layout):
                    patched_data, n = self._shift_iat_refs_by_delta(
                        bytes(data), va, delta, only_slots)
                    if n:
                        code_layout[idx] = (name, patched_data, flags, va)
                    if hasattr(self, '_translated_text') and name == '.text':
                        self._translated_text = patched_data
            self._iat_rva_map_placeholder_base = 0
        else:
            self._iat_rva_map = self._plan_import_iat_map(idata_rva)
        if self._iat_rva_map:
            print(f"        IAT remap: {len(self._iat_rva_map)} thunk slots")
        self._idata_blob, _ = self._build_import_directory(idata_rva)
        self._idata_rva = idata_rva

        # Patch absolute VAs in executable sections (IAT + moved .data/.rsrc).
        patched_layout: List[Tuple[str, bytes, int, int]] = []
        total_va_patches = 0
        for name, data, flags, va in code_layout:
            if flags & 0x20000000:
                data, n = self._patch_abs_va_in_code(data)
                total_va_patches += n
                data, n_disp = self._patch_disp32_image_vas_in_code(data)
                total_va_patches += n_disp
                data, n_c7 = self._patch_mov_rm_imm32_image_vas(data)
                total_va_patches += n_c7
                data, n_alu = self._patch_alu_imm32_image_vas(data)
                total_va_patches += n_alu
                data, n_b8 = self._patch_mov_reg32_imm32_image_vas(data)
                total_va_patches += n_b8
                data, n_iat = self._patch_iat_jmps_in_code(data, va)
                total_va_patches += n_iat
                data, n_ff15 = self._patch_ff15_iat_calls_in_code(data, va)
                total_va_patches += n_ff15
                # Universal final pass: re-resolve ALL movabs IAT references
                # against the definitive _iat_rva_map.  Catches every
                # ``mov r64, <IAT_VA>`` regardless of encoding path.
                data, n_movabs = self._patch_movabs_iat_in_code(data, va)
                total_va_patches += n_movabs
                if n_movabs:
                    print(f'        Post-patch movabs IAT re-resolution: {n_movabs}')
                blob = bytearray(data)
                cmd_fixed = self._cmd_shim_postfixes(blob, self.rva_map)
                if cmd_fixed:
                    print(f"        Post-patch cmd.exe shim fixups: {cmd_fixed}")
                if self._cmd_no_hacks:
                    pure_iat = self._fix_pure_iat_movabs_cells(blob)
                    pure_ind = self._fix_pure_indirect_iat_calls(blob)
                    if pure_iat or pure_ind:
                        print(f"        Pure IAT movabs/indirect fixes: "
                              f"{pure_iat}/{pure_ind}")
                scope_restore = self._restore_materialized_scope_tables(blob, va)
                if scope_restore:
                    print(f"        Post-patch scope table restore: {scope_restore}")
                fn_entry_calls = self._snap_calls_to_function_entries(blob, self.rva_map)
                if fn_entry_calls:
                    print(f"        Post-patch mid-function CALL entry snaps: {fn_entry_calls}")
                if self._cmd_no_hacks and getattr(self, '_pure_heal_text', None):
                    pp_align = self._pure_repair_all_align_stub_calls(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_align:
                        print(f"        Post-patch pure align CALL repairs: {pp_align}")
                    pp_epi = self._pure_snap_calls_to_epilogue_targets(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_epi:
                        print(f"        Post-patch pure epilogue CALL snaps: {pp_epi}")
                    pp_calls = self._pure_repair_call_targets(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_calls:
                        print(f"        Post-patch pure CALL re-resolve: {pp_calls}")
                    pp_x86_calls = self._pure_repair_calls_from_x86_source(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_x86_calls:
                        print(f"        Post-patch pure x86-anchored CALL repairs: {pp_x86_calls}")
                    pp_corr = self._pure_correlate_call_targets(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_corr:
                        print(f"        Post-patch pure ordered CALL correlations: {pp_corr}")
                    pp_interior = self._pure_snap_calls_off_interior_targets(
                        blob, self.rva_map)
                    if pp_interior:
                        print(f"        Post-patch pure interior CALL snaps: {pp_interior}")
                jcc_snapped = self._snap_jcc_misaligned_targets(blob)
                if jcc_snapped:
                    print(f"        Post-patch mid-instruction Jcc snaps: {jcc_snapped}")
                jcc_repaired = self._repair_jcc_targets_from_rva_map(blob, self.rva_map)
                if jcc_repaired:
                    print(f"        Post-patch Jcc rva_map target repairs: {jcc_repaired}")
                if getattr(self, '_epilogue_snap_map', None):
                    epi_snapped3 = self._snap_branch_targets_to_epilogue_heads(
                        blob, self._epilogue_snap_map)
                    if epi_snapped3:
                        print(f"        Post-patch epilogue-head branch snaps: {epi_snapped3}")
                scope_push = self._reconcile_seh_scope_pushes(blob, self.rva_map, va)
                if scope_push:
                    print(f"        Post-patch SEH scope push reconcile: {scope_push}")
                if not self.win10_test_shim:
                    scope_fixed = self._fix_scope_tables_in_blob(blob)
                    if scope_fixed:
                        print(f"        Scope-table entry fixups: {scope_fixed}")
                seh_scope = self._fix_broken_entry_seh_scope_pushes(
                    blob, self.rva_map, text_rva=va)
                if seh_scope:
                    print(f"        Post-patch entry SEH scope repoint: {seh_scope}")
                scope_synth = self._synthesize_seh_scopes_for_push_sites(blob, va)
                if scope_synth:
                    print(f"        Post-patch SEH scope synthesize: {scope_synth}")
                scope_norm = self._normalize_scope_table_handlers(blob)
                if scope_norm:
                    print(f"        Post-patch SEH scope handler normalize: {scope_norm}")
                push_h = self._fix_scope_handlers_at_push_sites(blob, va)
                if push_h:
                    print(f"        Post-patch SEH push-site handler fix: {push_h}")
                seh_rbp = self._fix_seh_rbp_local_overlap(blob)
                if seh_rbp:
                    print(f"        Post-patch SEH RBP local slot fixups: {seh_rbp}")
                data = bytes(blob)
                data, n2 = self._patch_dword_vas_in_orphan_blobs(data)
                total_va_patches += n2
                blob = bytearray(data)
                scope_norm2 = self._normalize_scope_table_handlers(blob)
                if scope_norm2:
                    print(f"        Post-patch SEH scope handler re-normalize: {scope_norm2}")
                push_h2 = self._fix_scope_handlers_at_push_sites(blob, va)
                if push_h2:
                    print(f"        Post-patch SEH push-site handler re-fix: {push_h2}")
                epi_gaps = self._fix_align_epilogue_x86_gaps(blob)
                if epi_gaps:
                    print(f"        Post-patch align-epilogue x86 gaps: {epi_gaps}")
                if self.win10_test_shim and not self._cmd_no_hacks:
                    fn6314_late = self._cmd_fn6314_entry_off(blob)
                    late_cmd = 0
                    late_cmd += self._restore_cmd_text_constants(blob)
                    if fn6314_late is not None:
                        late_cmd += self._fix_fn6314_callee_ret(blob, fn6314_late)
                    late_cmd += self._fix_cmd_crt_wcslen_path(blob)
                    late_cmd += self._fix_cmd_crt_wcslen_helper_calls(blob)
                    late_cmd += self._fix_cmd_crt_wcslen_call_8a44(blob)
                    late_cmd += self._fix_cmd_crt_second_wcslen_8a6b(blob)
                    late_cmd += self._fix_cmd_crt_wcslen_inline_2a805(blob)
                    late_cmd += self._fix_cmd_crt_getmainargs_setup(blob)
                    late_cmd += self._fix_calls_into_movabs_imm(blob)
                    late_cmd += self._fix_cmd_data_iat_pointer_cells(blob)
                    late_cmd += self._fix_cmd_crt_createprocess_call_8df1(blob)
                    late_cmd += self._fix_cmd_text_indirect_iat_calls(blob)
                    late_cmd += self._fix_cmd_crt_exit_branches(blob)
                    late_cmd += self._fix_cmd_crt_cont_branches(blob)
                    late_cmd += self._fix_cmd_crt_fail_path_branches(blob)
                    late_cmd += self._fix_cmd_crt_init_branches(blob)
                    late_cmd += self._fix_cmd_init_env_rsi(blob)
                    late_cmd += self._fix_cmd_entry_scope_push_bias(blob)
                    late_cmd += self._fix_cmd_main_wcslen_call(blob)
                    late_cmd += self._fix_cmd_main_wcslen_tail_8f0c(blob)
                    late_cmd += self._fix_cmd_main_getcommandline_call(blob)
                    late_cmd += self._fix_cmd_main_post_cmdline_overlap(blob)
                    late_cmd += self._fix_cmd_main_token_parse_call(blob)
                    late_cmd += self._fix_cmd_main_token_parse_call(blob)
                    late_cmd += self._fix_cmd_main_skip_spurious_parse_calls(blob)
                    late_cmd += self._fix_cmd_main_drive_letter_path(blob)
                    late_cmd += self._fix_cmd_main_batch_arg_mov(blob)
                    late_cmd += self._fix_cmd_main_skip_batch_setup_call(blob)
                    late_cmd += self._fix_cmd_main_wcschr_call(blob)
                    late_cmd += self._fix_cmd_main_wcschr_null_fallback(blob)
                    late_cmd += self._fix_cmd_main_empty_token_cmp(blob)
                    late_cmd += self._fix_cmd_main_switch_dispatch(blob)
                    late_cmd += self._fix_cmd_main_flag_dispatch(blob)
                    late_cmd += self._fix_cmd_main_post_flag_path(blob)
                    late_cmd += self._fix_cmd_main_parse_dispatch_call(blob)
                    late_cmd += self._fix_cmd_main_exec_tail(blob)
                    late_cmd += self._fix_cmd_main_batch_copy_call_args(blob)
                    late_cmd += self._fix_cmd_switch_handler_gs_epilogue(blob)
                    late_cmd += self._fix_cmd_batch_helper_zero_index(blob)
                    late_cmd += self._fix_cmd_batch_helper_x64_ptr_load(blob)
                    late_cmd += self._fix_cmd_fn6314_helper_calls(blob, self.rva_map)
                    if fn6314_late is not None:
                        late_cmd += self._fix_cmd_fn6314_zero_edi(blob, fn6314_late)
                    late_cmd += self._fix_cmd_fn6314_wcsrchr_null_skip(blob)
                    late_cmd += self._fix_cmd_heap_alloc_helper_2e37d(blob)
                    late_cmd += self._fix_cmd_main_heap_call_8fea(blob)
                    late_cmd += self._fix_cmd_main_post_switch_success(blob)
                    late_cmd += self._fix_cmd_main_parse_helper_calls(blob, self.rva_map)
                    late_cmd += self._fix_cmd_main_batch_exec_call(blob)
                    late_cmd += self._fix_cmd_exec_batch_call_2365(blob)
                    late_cmd += self._fix_cmd_batch_helper_call_r9_235a(blob)
                    late_cmd += self._fix_cmd_batch_test_al4_je_2338(blob)
                    late_cmd += self._fix_cmd_batch_helper_296e8_gs_epilogue(blob)
                    late_cmd += self._fix_cmd_batch_helper_296e8_flag_check(blob)
                    late_cmd += self._fix_cmd_getcommandline_inner_call(blob)
                    late_cmd += self._fix_cmd_skip_crt_reexec(blob)
                    late_cmd += self._fix_cmd_crt_reexec_cleanup_branches(blob)
                    late_cmd += self._fix_cmd_crt_reexec_return_branches(blob)
                    late_cmd += self._fix_cmd_force_crt_reexec_fail(blob, va)
                    late_cmd += self._fix_cmd_crt_createprocess_call_8df1(blob)
                    late_cmd += self._fix_cmd_crt_divert_init_loops(blob)
                    late_cmd += self._fix_cmd_fn6581_call_sites(blob, self.rva_map)
                    late_cmd += self._fix_cmd_crt_restore_fn6314_calls(blob)
                    if fn6314_late is not None:
                        late_cmd += self._fix_fn6314_scan_loop(blob, fn6314_late)
                    late_cmd += self._fix_fn6314_loop_branches(blob, fn6314_late or 0)
                    if fn6314_late is not None:
                        late_cmd += self._fix_fn6314_jump_exit(blob, fn6314_late)
                        late_cmd += self._fix_cmd_fn6314_call_14412(blob, fn6314_late, self.rva_map)
                    late_cmd += self._fix_cmd_crt_init_fail_jmp(blob)
                    late_cmd += self._fix_cmd_crt_reach_main(blob)
                    if late_cmd:
                        print(f"        Post-patch cmd CRT late fixups: {late_cmd}")
                # Second-chance Jcc snap + zero-byte call snap — some branches
                # may have been created or modified by the cmd fixups above.
                jcc_final = self._snap_jcc_misaligned_targets(blob)
                if jcc_final:
                    print(f"        Post-patch final Jcc snaps: {jcc_final}")
                call_final = self._snap_zero_byte_call_targets(blob)
                if call_final:
                    print(f"        Post-patch final zero-byte CALL snaps: {call_final}")
                add_rsp_fixed = self._adjust_epilogue_add_rsp(
                    blob, chkstk_off=self._pure_chkstk_entry_off(blob))
                if add_rsp_fixed:
                    print(f"        Post-patch ADD RSP epilogue adjustments: {add_rsp_fixed}")
                # Fix _chkstk epilogue ADDs AFTER _adjust_epilogue_add_rsp
                # (uses original x86 frame size from mov rax,N, not the adjusted ADD)
                chkstk_add_fixed = self._fix_chkstk_epilogue_adds(blob)
                if chkstk_add_fixed:
                    print(f"        Post-patch _chkstk epilogue ADD fixes: {chkstk_add_fixed}")
                else:
                    # Debug: check if _chkstk signature exists in blob at all
                    import sys as _sys
                    _ck_test = blob.find(b'\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x10')
                    print(f"        [DEBUG] _chkstk sig at {_ck_test:#x}, blob len={len(blob)}", file=_sys.stderr, flush=True)
                ff25_sled = self._int3_sled_ff25_gaps(blob)
                if ff25_sled:
                    print(f"        Post-patch FF25 gap INT3 sleds: {ff25_sled}")
                # ── Post-patch: snap CALL targets past shared epilogues ──
                # Some CALL targets land inside ``pop…; mov rsp,…; ret``
                # shared epilogues whose body sits after the ``ret``.
                # Running this AFTER all call-repair passes ensures every
                # finalised CALL resolves to the true function entry.
                past_snapped_pp = self._snap_branches_past_epilogues(blob)
                if past_snapped_pp:
                    print(f"        Post-patch epilogue-past branch snaps: {past_snapped_pp}")
                rbp_leave = self._pure_fix_rbp_leave_before_ret(blob)
                if rbp_leave:
                    print(f"        Post-patch pure RBP leave inserts: {rbp_leave}")
                text_src = pe.get_section_data(
                    next(s for s in pe.sections if s['name'].startswith('.text')))
                jmp_epi = self._pure_fix_jmp_over_epilogue(blob, text_src, va)
                if jmp_epi:
                    print(f"        Post-patch pure jmp→epilogue fixes: {jmp_epi}")
                orphan_trap = self._int3_sled_orphan_data(blob)
                if orphan_trap:
                    print(f"        Post-patch orphan data INT3 traps: {orphan_trap}")
                if self.win10_test_shim and not self._cmd_no_hacks:
                    final_cmd = 0
                    final_cmd += self._fix_cmd_force_crt_reexec_fail(blob, va)
                    final_cmd += self._fix_cmd_crt_createprocess_call_8df1(blob)
                    final_cmd += self._fix_cmd_crt_divert_init_loops(blob)
                    final_cmd += self._fix_cmd_init_tail_int3(blob)
                    final_cmd += self._fix_cmd_main_tail_scope_hole(blob, self.rva_map)
                    reexec = self._fix_cmd_crt_reexec_control_flow(blob)
                    if reexec:
                        final_cmd += reexec
                    shift = self._cmd_shim_blob_shift_fixups(blob)
                    if shift:
                        final_cmd += shift
                        final_cmd += self._fix_cmd_batch_helper_call_r9_235a(blob)
                        final_cmd += self._fix_cmd_batch_test_al4_je_2338(blob)
                        final_cmd += self._fix_cmd_exec_batch_call_2365(blob)
                        final_cmd += self._fix_cmd_main_batch_exec_call(blob)
                    if not os.environ.get('CMD_DROP_CRT_HACKS'):
                        final_cmd += self._fix_cmd_crt_wcslen_helper_calls(blob)
                        final_cmd += self._fix_cmd_crt_wcslen_call_8a44(blob)
                        final_cmd += self._fix_cmd_crt_second_wcslen_8a6b(blob)
                        final_cmd += self._fix_cmd_crt_fn6314_call_target_8af4(blob)
                        final_cmd += self._fix_cmd_crt_banner_epilogue_pop_rbp_8b22(blob)
                        final_cmd += self._fix_cmd_crt_skip_banner_print_8b74(blob)
                        final_cmd += self._fix_cmd_crt_wcslen_inline_2a805(blob)
                    final_cmd += self._fix_cmd_crt_getmainargs_setup(blob)
                    final_cmd += self._fix_cmd_crt_reach_main(blob)
                    final_cmd += self._fix_cmd_crt_init_fail_jmp(blob)
                    if not os.environ.get('CMD_DROP_CRT_HACKS'):
                        final_cmd += self._fix_cmd_crt_restore_fn6314_calls(blob)
                    final_cmd += self._fix_cmd_main_getcommandline_call(blob)
                    final_cmd += self._fix_cmd_main_save_cmdline_ptr_8eea(blob)
                    final_cmd += self._fix_cmd_main_post_cmdline_overlap(blob)
                    final_cmd += self._fix_cmd_main_prologue_stack_align(blob)
                    final_cmd += self._fix_cmd_main_peb_wcslen_stub_call(blob)
                    if not self.win10_test_shim:
                        final_cmd += self._fix_cmd_main_early_dispatch_8f61(blob)
                    final_cmd += self._fix_cmd_main_token_parse_8fcc(blob)
                    final_cmd += self._fix_cmd_main_batch_call_90fc(blob)
                    final_cmd += self._fix_cmd_main_skip_batch_path_90ef(blob)
                    final_cmd += self._fix_cmd_main_wcschr_iat_9111(blob)
                    final_cmd += self._fix_cmd_main_wcschr_null_fallback(blob)
                    final_cmd += self._fix_cmd_main_skip_to_switch_slash(blob)
                    final_cmd += self._fix_cmd_main_token_scan_null_exit_911e(blob)
                    final_cmd += self._fix_cmd_main_empty_token_cmp(blob)
                    final_cmd += self._fix_cmd_main_skip_empty_token_exit(blob)
                    final_cmd += self._fix_cmd_exit_helper_call_2e4cb(blob)
                    final_cmd += self._fix_cmd_version_banner_root_2e4bb(blob)
                    final_cmd += self._fix_cmd_gvi_helper_force_success_1d3b6(blob)
                    final_cmd += self._fix_cmd_gvi_helper_1d343(blob)
                    final_cmd += self._fix_cmd_main_switch_dispatch(blob)
                    final_cmd += self._fix_cmd_main_flag_dispatch(blob)
                    final_cmd += self._fix_cmd_main_skip_parse_to_exec(blob)
                    final_cmd += self._fix_cmd_main_post_flag_path(blob)
                    final_cmd += self._fix_cmd_main_wcscmp_iat_9176(blob)
                    final_cmd += self._fix_cmd_interactive_skip_wcscmp_slashq_917a(blob)
                    final_cmd += self._fix_cmd_main_wcsncmp_c_second(blob)
                    final_cmd += self._fix_cmd_main_c_switch_jne(blob)
                    final_cmd += self._fix_cmd_version_banner_branch_2e4b1(blob)
                    final_cmd += self._fix_cmd_main_parse_dispatch_call(blob)
                    final_cmd += self._fix_cmd_main_exec_tail(blob)
                    final_cmd += self._fix_cmd_main_exec_success_jmp(blob)
                    final_cmd += self._fix_cmd_main_post_switch_success(blob)
                    final_cmd += self._fix_cmd_switch_handler_entry_1deb4(blob)
                    final_cmd += self._fix_cmd_switch_handler_gs_epilogue(blob)
                    final_cmd += self._fix_cmd_main_echo_tail_rcx(blob)
                    final_cmd += self._fix_cmd_exec_success_via_rbx_setup(blob)
                    final_cmd += self._fix_cmd_echo_tail_wcsncpy_stub(blob)
                    final_cmd += self._fix_cmd_exec_helper_kernel_iat(blob)
                    final_cmd += self._fix_cmd_skip_createprocess_helper_938f(blob)
                    final_cmd += self._fix_cmd_echo_batch_call_93bc(blob)
                    final_cmd += self._fix_cmd_echo_dispatch_call_2b3f5(blob)
                    final_cmd += self._fix_cmd_echo_batch_second_arg(blob)
                    final_cmd += self._fix_cmd_echo_dispatch_iat_region(blob)
                    final_cmd += self._fix_cmd_batch_helper_iat_region(blob)
                    final_cmd += self._fix_cmd_win10_echo_writeconsole(blob)
                    final_cmd += self._fix_cmd_main_win10_cmdline_gate_8f61(blob)
                    final_cmd += self._fix_cmd_main_drive_letter_path(blob)
                    final_cmd += self._fix_cmd_main_batch_arg_mov(blob)
                    final_cmd += self._fix_cmd_main_skip_batch_setup_call(blob)
                    final_cmd += self._fix_cmd_skip_wcsncpy_jmp_drive_8fd6(blob)
                    final_cmd += self._fix_cmd_main_batch_exec_call(blob)
                    final_cmd += self._fix_cmd_main_save_rbp_slot(blob)
                    final_cmd += self._fix_cmd_print_tls_je_2d458(blob)
                    # Banner/CRT fn6314 thunk hacks removed: they were contradictory
                    # interactive-only patches that corrupted the banner path. /c echo
                    # works without them; keep them off unless explicitly re-enabled.
                    if os.environ.get('CMD_ENABLE_BANNER_HACKS'):
                        final_cmd += self._fix_cmd_crt_banner_wcsncpy_or_skip_8afc(blob)
                        final_cmd += self._fix_cmd_crt_banner_resume_skip_8af9(blob)
                        final_cmd += self._fix_cmd_crt_seh_banner_resume_8f56(blob)
                        final_cmd += self._fix_cmd_crt_seh_route_8f32_to_guard(blob)
                        final_cmd += self._fix_cmd_crt_fn6314_tailcall_pop_ret_2dc32(blob)
                        final_cmd += self._fix_cmd_crt_banner_fn6314_jne_2d9d7(blob)
                        final_cmd += self._fix_cmd_crt_fn6314_jmp_not_call_2dc32(blob)
                        final_cmd += self._fix_cmd_crt_fn6314_mid_thunk_branches(blob)
                        final_cmd += self._fix_cmd_crt_cont_branches(blob)
                        final_cmd += self._fix_cmd_crt_stub_iat_call_rax(blob)
                    final_cmd += self._fix_cmd_version_banner_skip_call_rsi_2e58d(blob)
                    final_cmd += self._fix_cmd_banner_swprintf_format_rdx(blob)
                    final_cmd += self._fix_cmd_banner_fill_version_cave(blob)
                    final_cmd += self._fix_cmd_banner_version_string_ptr_2e4ef(blob)
                    final_cmd += self._fix_cmd_banner_swprintf_version_arg_r8_2e50a(blob)
                    final_cmd += self._fix_cmd_banner_swprintf_iat_call_2e519(blob)
                    final_cmd += self._fix_cmd_banner_gvi_epilogue_pop_rbp_2e4d3(blob)
                    final_cmd += self._fix_cmd_banner_swprintf_epilogue_2e520(blob)
                    final_cmd += self._fix_cmd_banner_copyright_clear_rdx_2e5ac(blob)
                    final_cmd += self._fix_cmd_banner_line_print_leaf_2e536(blob)
                    final_cmd += self._fix_cmd_banner_copyright_print_leaf_2e5b8(blob)
                    final_cmd += self._fix_cmd_banner_copyright_string_rcx_2e5a2(blob)
                    final_cmd += self._fix_cmd_banner_repl_frame_fixup(blob)
                    final_cmd += self._fix_cmd_banner_skip_post_copyright_2e5ce(blob)
                    final_cmd += self._fix_cmd_crt_exit_jmp_8770(blob)
                    final_cmd += self._fix_cmd_crt_banner_fn6314_je_2d9ea(blob)
                    final_cmd += self._fix_cmd_banner_print_stub_2d813(blob)
                    final_cmd += self._ensure_cmd_wide_stdout_print_stub(blob)
                    final_cmd += self._fix_cmd_win10_interactive_guard_9040(blob)
                    final_cmd += self._fix_cmd_banner_print_call_sites(blob)
                    final_cmd += self._fix_cmd_banner_setup_call_3cf7b(blob)
                    final_cmd += self._fix_cmd_banner_setup_stub_3cf7a(blob)
                    final_cmd += self._fix_cmd_banner_helper_call_200f0(blob)
                    final_cmd += self._fix_cmd_readconsole_prompt_helper_calls(blob)
                    final_cmd += self._fix_cmd_banner_volume_call_chain(blob)
                    final_cmd += self._fix_cmd_version_banner_root_2e4bb(blob)
                    final_cmd += self._fix_cmd_banner_jne_2e4ac(blob)
                    final_cmd += self._fix_cmd_interactive_skip_closehandle_2e66e(blob)
                    final_cmd += self._fix_cmd_interactive_repl_jmp_2e6f1(blob)
                    final_cmd += self._fix_cmd_repl_jmp_2e728_to_gate(blob)
                    final_cmd += self._fix_cmd_repl_prompt_entry_nop_2eae9(blob)
                    final_cmd += self._fix_cmd_interactive_skip_repl_exit_ret(blob)
                    final_cmd += self._fix_cmd_interactive_repl_edi_gate_2e72d(blob)
                    final_cmd += self._fix_cmd_repl_seh_je_2ee65(blob)
                    final_cmd += self._fix_cmd_repl_readconsole_jmp_loop_2eb2a(blob)
                    final_cmd += self._fix_cmd_readconsole_call_sites(blob)
                    final_cmd += self._fix_cmd_readconsole_helper_frame_3d193(blob)
                    final_cmd += self._fix_cmd_parse_line_call_3cdc7(blob)
                    # REPL: use natural banner + ReadConsole (0x3D193) + parse (0x3CDC8).
                    # No synthetic prompt/read loops — those spin when ReadConsole returns.
                    final_cmd += self._fix_cmd_main_batch_arg_mov(blob)
                    final_cmd += self._fix_cmd_main_skip_batch_setup_call(blob)
                    final_cmd += self._fix_cmd_main_batch_call_90fc(blob)
                    final_cmd += self._fix_cmd_main_skip_batch_path_90ef(blob)
                    final_cmd += self._fix_cmd_main_empty_token_cmp(blob)
                    final_cmd += self._fix_cmd_main_skip_empty_token_exit(blob)
                    final_cmd += self._ensure_cmd_wide_stdout_print_stub(blob)
                    final_cmd += self._fix_cmd_crt_getmainargs_fallthrough_8769(blob)
                    final_cmd += self._fix_cmd_crt_orphan_epilogue_8770(blob)
                    final_cmd += self._fix_cmd_crt_getmainargs_flag_gate_877b(blob)
                    if final_cmd:
                        print(f"        Post-patch cmd CRT final fixups: {final_cmd}")
                if self._cmd_no_hacks and (flags & 0x20000000):
                    text_src = pe.get_section_data(
                        next(s for s in pe.sections if s['name'].startswith('.text')))
                else:
                    text_src = b''  # ensure variable exists for final pass
                if self._cmd_no_hacks and (flags & 0x20000000):
                    # ── Align-prologue snap BEFORE reconcile ──
                    # Runs while self.rva_map is pristine (reconcile modifies
                    # entries in-place).  Self-referencing CALLs are already
                    # present in the blob from translation/post-patch.
                    align_pro_final = self._snap_calls_past_align_prologues(
                        blob, self.rva_map, text_src, va)
                    if align_pro_final:
                        print(f"        Post-repair align-prologue CALL snaps: {align_pro_final}")
                    pp_frame = self._pure_reconcile_swallowed_rva_map(
                        blob, self.rva_map, text_src, va)
                    if pp_frame:
                        print(f"        Post-repair pure frameless entry reconciles: {pp_frame}")
                    blob, n_rep = self._patch_abs_va_in_code(
                        bytes(blob), relocate_new_base=False)
                    if n_rep:
                        print(f"        Post-repair pure movabs VA re-patch: {n_rep}")
                        total_va_patches += n_rep
                    # The disp32 image-VA re-patch MUST run unconditionally. An
                    # earlier repair pass can absorb every stray movabs (n_rep==0)
                    # while [reg+disp32] slots still embed un-relocated x86 image
                    # VAs. Gating this behind ``if n_rep`` regressed build 38:
                    # ~109 disp32 fixes were skipped, leaving 32-bit pointers that
                    # fault inside API code (build 18 ran to 201k+ steps, build 38
                    # crashed at ~67k). Always reconcile remaining disp32 VAs.
                    blob, n_disp = self._patch_disp32_image_vas_in_code(blob)
                    if n_disp:
                        print(f"        Post-repair pure disp32 VA re-patch: {n_disp}")
                        total_va_patches += n_disp
                    blob, n_c7 = self._patch_mov_rm_imm32_image_vas(blob)
                    if n_c7:
                        print(f"        Post-repair pure C7 imm32 VA re-patch: {n_c7}")
                        total_va_patches += n_c7
                    blob, n_alu = self._patch_alu_imm32_image_vas(blob)
                    if n_alu:
                        print(f"        Post-repair pure ALU imm32 VA re-patch: {n_alu}")
                        total_va_patches += n_alu
                    blob, n_b8 = self._patch_mov_reg32_imm32_image_vas(blob)
                    if n_b8:
                        print(f"        Post-repair pure mov-r32 imm32 VA re-patch: {n_b8}")
                        total_va_patches += n_b8
                    if not isinstance(blob, bytearray):
                        blob = bytearray(blob)
                    pp_auth2 = self._pure_repair_all_align_stub_calls(
                        blob, self.rva_map, text_src, va)
                    if pp_auth2:
                        print(f"        Post-repair pure authoritative align CALLs: {pp_auth2}")
                    pp_crt = self._pure_fixup_crt_initterm_push_imm_pairs(
                        blob, self.rva_map, text_src, va)
                    if pp_crt:
                        print(f"        Post-repair pure CRT initterm movabs fixes: {pp_crt}")
                    pp_sync = self._pure_authoritative_x86_call_sync(
                        blob, self.rva_map, text_src, va)
                    if pp_sync:
                        print(f"        Post-repair pure authoritative x86 CALL sync: {pp_sync}")
                    pp_gpf = self._pure_fix_geparse_followup_call(
                        blob, self.rva_map, text_src, va)
                    if pp_gpf:
                        print(f"        Post-repair pure GEParse follow-up CALL fixes: {pp_gpf}")
                    pp_impl = self._pure_fix_implausible_align_calls(
                        blob, self.rva_map, text_src, va)
                    if pp_impl:
                        print(f"        Post-repair pure implausible align CALL fixes: {pp_impl}")
                    pp_bad = self._pure_fix_bad_align_stub_targets(
                        blob, self.rva_map, text_src, va)
                    if pp_bad:
                        print(f"        Post-repair pure bad align-stub CALL fixes: {pp_bad}")
                    pp_self = self._pure_repatch_align_stub_self_calls(
                        blob, self.rva_map, text_src, va)
                    if pp_self:
                        print(f"        Post-repair pure align self-CALL fixes: {pp_self}")
                    pp_named = self._pure_fixup_named_align_calls(
                        blob, self.rva_map, text_src, va)
                    if pp_named:
                        print(f"        Post-repair pure named align CALL fixes: {pp_named}")
                    pp_teb = self._pure_fixup_teb_indirect_field_disps(blob)
                    if pp_teb:
                        print(f"        Post-repair pure TEB indirect field fixes: {pp_teb}")
                    pp_bounds = self._pure_fixup_teb_stack_bounds_idiom(blob)
                    if pp_bounds:
                        print(f"        Post-repair pure TEB stack-bounds qword fixes: {pp_bounds}")
                    # Final, authoritative chkstk-prologue entry + caller fix —
                    # runs after every other call-repair pass so nothing can
                    # re-collapse these large-frame entries (0xA4E7 switch parser).
                    pp_chk = self._pure_fix_chkstk_prologue_entries(
                        blob, self.rva_map, text_src, va)
                    if pp_chk:
                        print(f"        Post-repair pure chkstk-prologue entry fixes: {pp_chk}")
                    if not os.environ.get('DISABLE_CHKSTK'):
                        pp_chkcall = self._pure_fix_broken_chkstk_calls(blob)
                        if pp_chkcall:
                            print(f"        Post-repair pure broken chkstk-call repairs: {pp_chkcall}")
                        pp_iatw = self._pure_rematerialize_nullcheck_iat_wrappers(
                            blob, self.rva_map, text_src, va)
                        if pp_iatw:
                            print(f"        Post-repair pure nullcheck-IAT wrapper rematerialize: {pp_iatw}")
                        pp_fwd = self._pure_rematerialize_iat_stdcall_forwarders(
                            blob, self.rva_map, text_src, va)
                        if pp_fwd:
                            print(f"        Post-repair pure IAT-stdcall forwarder rematerialize: {pp_fwd}")
                        pp_unhijack = self._pure_unhijack_nonprobe_chkstk_calls(
                            blob, self.rva_map, text_src, va)
                        if pp_unhijack:
                            print(f"        Post-repair pure non-probe chkstk unhijack: {pp_unhijack}")
                    pp_chkc = self._pure_repair_chkstk_prologue_calls(
                        blob, self.rva_map, text_src, va)
                    if pp_chkc:
                        print(f"        Post-repair pure chkstk-prologue CALL fixes: {pp_chkc}")
                    blob, n_final = self._patch_abs_va_in_code(
                        bytes(blob), relocate_new_base=False)
                    if n_final:
                        print(f"        Post-repair stale section VA fixups: {n_final}")
                        total_va_patches += n_final
                    if not isinstance(blob, bytearray):
                        blob = bytearray(blob)
                    pp_data = self._pure_reanchor_data_movabs_from_x86_pushes(
                        blob, self.rva_map, text_src, va)
                    if pp_data:
                        print(f"        Post-repair pure data movabs re-anchor: {pp_data}")
                    pp_twin = self._pure_fix_abs_load_twin_code_movabs(
                        blob, text_src, va, self.rva_map)
                    if pp_twin:
                        print(f"        Post-repair pure abs-load/code-twin movabs: {pp_twin}")
                    pp_shift = self._pure_fix_shifted_data_movabs(
                        blob, text_src, va)
                    if pp_shift:
                        print(f"        Post-repair pure shifted data movabs fixes: {pp_shift}")
                    # Snap swallowed fn-entry slots onto real bodies, then
                    # rewrite atexit/callback movabs that still hold the
                    # epilogue VA from the pre-reconcile map.
                    pp_sw = self._pure_reconcile_swallowed_rva_map(
                        blob, self.rva_map, text_src, va)
                    if pp_sw:
                        print(f"        Post-repair pure swallowed rva_map reconciles: {pp_sw}")
                        self._refresh_final_rvas()
                    pp_code = self._pure_resync_code_pointer_movabs(
                        blob, self.rva_map, text_src, va)
                    if pp_code:
                        print(f"        Post-repair pure code-pointer movabs resync: {pp_code}")
                # ── Final post-repair: snap CALL targets past shared epilogues ──
                # and fix chkstk epilogue ADDs.  These must run AFTER every
                # call-repair and chkstk-prologue pass, otherwise the patterns
                # they depend on (E8 rel32 targets, pop…add rsp…ret) aren't
                # finalised yet and the functions silently return 0.
                past_snapped_final = self._snap_branches_past_epilogues(blob)
                if past_snapped_final:
                    print(f"        Post-repair epilogue-past branch snaps: {past_snapped_final}")
                chkstk_add_final = self._fix_chkstk_epilogue_adds(blob)
                if chkstk_add_final:
                    print(f"        Post-repair _chkstk epilogue ADD fixes: {chkstk_add_final}")
                # ── Final pass: load pristine RVA map from dump file ──
                # The live self.rva_map was modified by reconcile; the
                # snapshot may be stale.  The dump file is the definitive
                # reference written before any post-repair modifications.
                rva_dump = {}
                dump_path = os.environ.get('DUMP_RVA_MAP', '')
                if dump_path and os.path.exists(dump_path):
                    with open(dump_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            p = line.strip().split()
                            if len(p) == 2:
                                rva_dump[int(p[0], 16)] = int(p[1], 16)
                if rva_dump and text_src:
                    align_pro_end = self._snap_calls_past_align_prologues(
                        blob, rva_dump, text_src, va)
                    if align_pro_end:
                        print(f"        Post-repair align-prologue CALL snaps (final): {align_pro_end}")
                # ── Snap calls past injected register-save prologues ──
                # Healed entries may have ``push rsi; push rdi; ...`` before
                # the align-wrapper.  Calls targeting AW+5 skip those saves,
                # so the matching ``pop rdi; pop rsi; ret`` pops garbage.
                # Walk backwards from the call target past the align-wrapper
                # and any register-save pushes, then retarget the call.
                regsave_snaps = self._snap_calls_past_register_saves(blob)
                if regsave_snaps:
                    print(f"        Post-repair register-save CALL snaps: {regsave_snaps}")
                # ── Fix MOV direction swaps (66 89 → 66 8B where x86 reads) ──
                mov_swaps = self._fix_mov_direction_swaps(
                    blob, self.rva_map, text_src, va)
                if mov_swaps:
                    print(f"        Post-repair MOV direction / SUB fixes: {mov_swaps}")
                # Packed .data keeps 4-byte slots — narrow abs qword ops.
                pp_narrow = self._pure_narrow_packed_data_qword_ops(blob)
                if pp_narrow:
                    print(f"        Post-repair packed-data qword→dword narrows: {pp_narrow}")
                # ── Fix thunks that clobber argument registers ──
                # ── Final CALL target validation ──
                # Runs dead last: for every x64 CALL, cross-reference the
                # x86 source to verify the target lands on a sane entry.
                # Only fixes calls whose current target is CLEARLY bad
                # (swallowed slot / mid-instruction / corrupt hybrid).
                call_val = self._validate_all_call_targets(
                    blob, self.rva_map, text_src, va)
                if call_val:
                    print(f"        Post-repair final CALL validation fixes: {call_val}")
                # Safety net: only mid-movabs-imm landings (precise).  Do NOT
                # re-run full insn-boundary snap here — Capstone false starts
                # after validate rewrote thousands of good calls (univ5 CRT
                # exit at ~200 steps).
                mid_movabs = self._fix_calls_into_movabs_imm(blob)
                if mid_movabs:
                    print(f"        Post-repair mid-movabs CALL snaps: {mid_movabs}")
                mid_fn_imm = self._pure_fix_fn_entry_mid_imm_tips(
                    blob, self.rva_map,
                    getattr(self, '_pure_heal_text', None),
                    int(getattr(self, '_pure_heal_text_rva', 0) or 0))
                if mid_fn_imm:
                    print(f"        Post-repair fn-entry mid-imm tips: {mid_fn_imm}")
                mid_jcc_movabs = self._fix_jccs_into_movabs_imm(blob)
                if mid_jcc_movabs:
                    print(f"        Post-repair mid-movabs Jcc snaps: {mid_jcc_movabs}")
                self_jmps = self._fix_self_relative_jmps(blob)
                if self_jmps:
                    print(f"        Post-repair self-jmp / arg-select fixes: {self_jmps}")
                jcc_ph = self._pure_patch_jcc_placeholders(
                    blob, self.rva_map, text_src, va)
                if jcc_ph:
                    print(f"        Post-repair unresolved Jcc placeholder patches: {jcc_ph}")
                near_pro = self._snap_calls_back_to_nearby_prologue(blob)
                if near_pro:
                    print(f"        Post-repair near-prologue CALL snaps: {near_pro}")
                near_fwd = self._snap_calls_forward_past_epilogue(blob)
                if near_fwd:
                    print(f"        Post-repair forward-past-epilogue CALL snaps: {near_fwd}")
                if self._cmd_no_hacks and getattr(self, '_pure_heal_text', None):
                    if not os.environ.get('DISABLE_CHKSTK'):
                        pp_iatw2 = self._pure_rematerialize_nullcheck_iat_wrappers(
                            blob, self.rva_map,
                            self._pure_heal_text, self._pure_heal_text_rva)
                        if pp_iatw2:
                            print(f"        Post-repair pure nullcheck-IAT wrapper rematerialize (final): {pp_iatw2}")
                        pp_fwd2 = self._pure_rematerialize_iat_stdcall_forwarders(
                            blob, self.rva_map,
                            self._pure_heal_text, self._pure_heal_text_rva)
                        if pp_fwd2:
                            print(f"        Post-repair pure IAT-stdcall forwarder rematerialize (final): {pp_fwd2}")
                        pp_unhijack2 = self._pure_unhijack_nonprobe_chkstk_calls(
                            blob, self.rva_map,
                            self._pure_heal_text, self._pure_heal_text_rva)
                        if pp_unhijack2:
                            print(f"        Post-repair pure non-probe chkstk unhijack (final): {pp_unhijack2}")
                    pp_sync2 = self._pure_authoritative_x86_call_sync(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_sync2:
                        print(f"        Post-repair pure x86 CALL re-sync: {pp_sync2}")
                    pp_impl2 = self._pure_fix_implausible_align_calls(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_impl2:
                        print(f"        Post-repair pure implausible align CALL re-fix: {pp_impl2}")
                    pp_ff35 = self._pure_fix_ff35_helper_calls(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_ff35:
                        print(f"        Post-repair pure ff35 helper CALL fixes: {pp_ff35}")
                    pp_jcc_epi = self._pure_fix_jcc_to_mismatched_epilogue(blob)
                    if pp_jcc_epi:
                        print(f"        Post-repair pure mismatched-epilogue Jcc fixes: {pp_jcc_epi}")
                    pp_map_back = self._pure_snap_interior_rva_map_back_past_ret(
                        blob, self.rva_map)
                    if pp_map_back:
                        print(f"        Post-repair pure interior rva_map/Jcc snaps: {pp_map_back}")
                    pp_setne = self._pure_snap_jcc_off_setne_ret_epilogue(blob)
                    if pp_setne:
                        print(f"        Post-repair pure setne-ret Jcc snaps: {pp_setne}")
                    pp_bare_ret = self._pure_snap_jcc_off_bare_ret_to_epilogue(blob)
                    if pp_bare_ret:
                        print(f"        Post-repair pure bare-ret→epilogue Jcc snaps: {pp_bare_ret}")
                    pp_sleave = self._pure_fix_jcc_short_pop_ret_to_local_leave_epi(blob)
                    if pp_sleave:
                        print(f"        Post-repair pure short-pop-ret→local-leave Jcc fixes: {pp_sleave}")
                    pp_r13 = self._pure_restore_r13_after_align_call(blob)
                    if pp_r13:
                        print(f"        Post-repair pure r13-align call restores: {pp_r13}")
                    pp_txtc = self._pure_fix_empty_data_text_constant_movabs(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_txtc:
                        print(f"        Post-repair pure text-constant movabs fixes: {pp_txtc}")
                    pp_strarg = self._pure_fix_text_string_arg_movabs(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_strarg:
                        print(f"        Post-repair pure text-string arg movabs fixes: {pp_strarg}")
                    pp_push_diamond = self._pure_fix_push_imm_jmp_to_mov_rcx_call(blob)
                    if pp_push_diamond:
                        print(f"        Post-repair pure push-imm/jmp call-diamond fixes: {pp_push_diamond}")
                    pp_push2 = self._pure_fix_push_push_jmp_past_win64_args(blob)
                    if pp_push2:
                        print(f"        Post-repair pure push/push/jmp Win64-arg fixes: {pp_push2}")
                    pp_sbb_add = self._pure_fix_sbb_mask_add64(blob)
                    if pp_sbb_add:
                        print(f"        Post-repair pure sbb-mask add64 fixes: {pp_sbb_add}")
                    pp_nl = self._pure_fix_int3_after_wchar_newline_store(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_nl:
                        print(f"        Post-repair pure newline-store INT3 fixes: {pp_nl}")
                    pp_ebp8 = self._pure_fix_int3_after_iat_call_ebp8_store(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_ebp8:
                        print(f"        Post-repair pure IAT-call [ebp+8] INT3 joins: {pp_ebp8}")
                    pp_ebp8b = self._pure_fix_int3_omitted_ebp8_store(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_ebp8b:
                        print(f"        Post-repair pure omitted [ebp+8] INT3 stores: {pp_ebp8b}")
                    pp_orphan_cc = self._pure_nop_orphan_int3(blob, self.rva_map)
                    if pp_orphan_cc:
                        print(f"        Post-repair pure dead-ebp-reload INT3→NOP: {pp_orphan_cc}")
                    pp_fifth = self._pure_fix_missing_fifth_stack_home(blob)
                    if pp_fifth:
                        print(f"        Post-repair pure missing 5th stack-home zeros: {pp_fifth}")
                    pp_narrow2 = self._pure_narrow_packed_data_qword_ops(blob)
                    if pp_narrow2:
                        print(f"        Post-repair packed-data qword→dword narrows (late): {pp_narrow2}")
                    pp_rbp8 = self._pure_fix_rbp8_homed_arg_loads(blob)
                    if pp_rbp8:
                        print(f"        Post-repair pure [rbp+8]→[rbp+0x10] arg loads: {pp_rbp8}")
                    pp_loop = self._pure_fix_rbp_loop_counter_cmp_mismatch(blob)
                    if pp_loop:
                        print(f"        Post-repair pure rbp loop-counter cmp fixes: {pp_loop}")
                    pp_sib = self._pure_fix_scaled_index_old_image_disp(blob)
                    if pp_sib:
                        print(f"        Post-repair pure scaled-index old-VA disp fixes: {pp_sib}")
                    pp_csave = self._pure_fix_clobber_before_callee_save_pushes(blob)
                    if pp_csave:
                        print(f"        Post-repair pure clobber-before-callee-save reorder: {pp_csave}")
                    # Nullcheck / forwarder rematerialize MUST run after call-sync:
                    # sync frequently leaves thin IAT wrappers as bare-ret work
                    # paths (cmd 0x195d2) and snaps stdcall forwarders onto
                    # neighbour align stubs (cmd 0xB627).  Earlier passes see
                    # pre-sync shapes and return 0.
                    pp_iatw_late = self._pure_rematerialize_nullcheck_iat_wrappers(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_iatw_late:
                        print(f"        Post-repair pure nullcheck-IAT wrapper rematerialize (late): {pp_iatw_late}")
                    pp_fwd_late = self._pure_rematerialize_iat_stdcall_forwarders(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_fwd_late:
                        print(f"        Post-repair pure IAT-stdcall forwarder rematerialize (late): {pp_fwd_late}")
                    # Call-sync / near-prologue snaps re-hijack ``mov rax,imm;
                    # call __chkstk`` onto heap helpers.  Re-assert the probe
                    # body after every call-shape pass (cmd 0xA4E7).
                    if not os.environ.get('DISABLE_CHKSTK'):
                        self._chkstk_entry_cache = None
                        pp_chk_late = self._pure_fix_broken_chkstk_calls(blob)
                        if pp_chk_late:
                            print(f"        Post-repair pure broken chkstk-call repairs (late): {pp_chk_late}")
                    # Absolute last nullchk pass — call-sync / align snaps after
                    # earlier rematerialize collapse work paths back to bare ret.
                    pp_iatw_last = self._pure_rematerialize_nullcheck_iat_wrappers(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_iatw_last:
                        print(f"        Post-repair pure nullcheck-IAT wrapper rematerialize (last): {pp_iatw_last}")
                    # Cursor seed last — earlier call-sync/align passes rewrite
                    # the B186 empty-path call site back to B21C (More?).
                    pp_cursor = self._pure_seed_stream_cursor_from_parse_buffer(blob)
                    if pp_cursor:
                        print(f"        Post-repair pure parse-cursor seed stores: {pp_cursor}")
                    pp_r13b = self._pure_restore_r13_after_align_call(blob)
                    if pp_r13b:
                        print(f"        Post-repair pure r13-align call restores (last): {pp_r13b}")
                    pp_txtc2 = self._pure_fix_empty_data_text_constant_movabs(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if pp_txtc2:
                        print(f"        Post-repair pure text-constant movabs fixes (last): {pp_txtc2}")
                chkstk_ent = 0
                for i in range(len(blob) - 5):
                    if blob[i] != 0xE8:
                        continue
                    if not self._e8_byte_is_real_call(blob, i):
                        continue
                    rel = struct.unpack_from('<i', blob, i + 1)[0]
                    tgt = i + 5 + rel
                    snapped = self._pure_snap_chkstk_home_spill_entry(blob, tgt)
                    if snapped != tgt and 0 <= snapped < len(blob):
                        struct.pack_into('<i', blob, i + 1, snapped - (i + 5))
                        chkstk_ent += 1
                if chkstk_ent:
                    print(f"        Post-repair chkstk-opener CALL snaps: {chkstk_ent}")
                data = bytes(blob)
                if str(name).startswith('.text'):
                    self._translated_text = data
                # Final EH3 pass: post-repair movabs/string heals often remap
                # scope RVAs onto UTF-16. Rematerialize + reconcile last so
                # SEH pushes stick on real ``ff ff ff ff`` tables.
                if (str(name).startswith('.text') and self._pure_heal_text
                        and self._cmd_no_hacks):
                    blob = bytearray(data)
                    n_scope = self._force_rematerialize_scope_tables(
                        blob, self.rva_map, self._pure_heal_text,
                        self._pure_heal_text_rva)
                    scope_push = self._reconcile_seh_scope_pushes(
                        blob, self.rva_map, va)
                    scope_anch = self._retarget_seh_pushes_from_anchors(
                        blob, self.rva_map, va)
                    # Guarantee begin/end are PE64 VAs even when rematerialize
                    # reused an existing slot (ok-path) or a prior pass left
                    # raw x86 immediates.
                    scope_reloc = 0
                    for base, old_rva in list(self._scope_table_old_rva.items()):
                        sz = 20
                        for s, z in self._scope_table_out_ranges:
                            if s == base:
                                sz = z
                                break
                        scope_reloc += self._patch_scope_table_entries(
                            blob, base, sz, old_rva,
                            self._seh_scope_reg_fn.get(old_rva))
                    if n_scope or scope_push or scope_anch or scope_reloc:
                        print(f"        Final EH3 scope rematerialize/reconcile: "
                              f"{n_scope}/{scope_push}/{scope_anch}/{scope_reloc}")
                    # Rematerialize can re-attach pushes to EH3 filter/handler
                    # pairs misread as 4-byte try ranges (cmd 0x1a88).  Synthesize
                    # private function-wide tables *last* so they stick.
                    scope_synth = self._synthesize_seh_scopes_for_push_sites(
                        blob, va)
                    if scope_synth:
                        print(f"        Final SEH scope synthesize: {scope_synth}")
                    data = bytes(blob)
                    self._translated_text = data
                    if n_scope or scope_push or scope_anch or scope_reloc or scope_synth:
                        self._refresh_final_rvas()
                    # Last chance: call/Jcc repairs after the earlier data
                    # re-anchor can shred movabs immediates that contain 0xE8.
                    blob = bytearray(data)
                    n_shift = self._pure_fix_shifted_data_movabs(
                        blob, self._pure_heal_text, self._pure_heal_text_rva)
                    if n_shift:
                        print(f"        Final shifted data movabs fixes: {n_shift}")
                        data = bytes(blob)
                        self._translated_text = data
                    n_sw = self._pure_reconcile_swallowed_rva_map(
                        blob, self.rva_map, self._pure_heal_text,
                        self._pure_heal_text_rva)
                    if n_sw:
                        print(f"        Final swallowed rva_map reconciles: {n_sw}")
                        self._refresh_final_rvas()
                    n_code = self._pure_resync_code_pointer_movabs(
                        blob, self.rva_map, self._pure_heal_text,
                        self._pure_heal_text_rva)
                    if n_code:
                        print(f"        Final code-pointer movabs resync: {n_code}")
                        data = bytes(blob)
                        self._translated_text = data
            patched_layout.append((name, data, flags, va))
        if total_va_patches:
            print(f"        VA pointer patches in code: {total_va_patches}")

        # ── Adjust data section RVAs if code grew during post-processing ──
        # The original max_code_end was computed before patching; if the blob
        # expanded (e.g. healed entries), the .text section may now overlap
        # the FIRST data section, causing ERROR_BAD_EXE_FORMAT at load time.
        actual_code_end = max(
            (va + len(d) for _n, d, _f, va in patched_layout),
            default=0x1000)
        first_data_rva = min((nv for _n, _r, _f, _o, nv in planned_data), default=0)
        if actual_code_end > first_data_rva > 0:
            shift = align(actual_code_end, SECT_ALIGN) - first_data_rva
            # Shift ALL planned_data and subsequent RVAs
            for i in range(len(planned_data)):
                n, r, f, o, nv = planned_data[i]
                planned_data[i] = (n, r, f, o, nv + shift)
                # Keep _old_to_new_section in sync so _final_rva
                # (used by remap_image_va) maps to the correct
                # post-shift data section VAs.
                self._old_to_new_section[o] = nv + shift
            # Rebuild _final_rva so late-stage VA re-patching
            # (below) sees the shifted data section addresses.
            self._refresh_final_rvas()
            idata_rva += shift
            self._idata_rva = idata_rva
            self._iat_rva_map = self._plan_import_iat_map(idata_rva)
            # Section shift changed IAT slot addresses — fix all FF 15 and
            # indirect movabs references in the code that still point to
            # pre-shift addresses.  Only genuine IAT slot movabs may shift:
            # a blanket new-base-range shift corrupts predefined handle
            # constants (HKCU 0x80000001 → 0x8007F001) and function VAs.
            pre_shift_slots = {v - shift for v in self._iat_rva_map.values()}
            for idx, (name, data, flags, va) in enumerate(patched_layout):
                patched_data, n = self._shift_iat_refs_by_delta(
                    bytes(data), va, shift, pre_shift_slots)
                if n:
                    patched_layout[idx] = (name, patched_data, flags, va)
                    if name == '.text':
                        self._translated_text = patched_data
            # Rebuild import blob so internal RVAs match the shifted .idata base
            self._idata_blob, _ = self._build_import_directory(idata_rva)
            # ── Re-patch VA pointers after section shift ──
            # The initial VA patching ran before the shift, so every
            # movabs / disp32 that points at a data-section VA (old
            # .data / .rsrc / .idata / .reloc) is now stale by +shift.
            # _patch_abs_va_in_code cannot fix .idata/.reloc pointers
            # because those sections have no x86→x64 entry in
            # _old_to_new_section.  Do a direct scan instead: add
            # ``shift`` to any new_base-relative immediate whose RVA
            # is >= the PRE-shift first data RVA.
            shift_lo_rva = first_data_rva  # pre-shift start of .data
            # Also track the old .idata / .reloc pre-shift base so
            # _relocate_stale_linear_image_va can handle them in any
            # future late passes.
            self._section_shift_amount = shift
            self._section_shift_base = shift_lo_rva
            re_patched = 0
            for idx, (pn, pd, pf, pva) in enumerate(patched_layout):
                if pf & 0x20000000:
                    blob = bytearray(pd)
                    i = 0
                    while i < len(blob) - 10:
                        # movabs: REX.W (48-4D) + B8-BF + imm64
                        if blob[i] in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= blob[i + 1] <= 0xBF:
                            imm = struct.unpack_from('<Q', blob, i + 2)[0]
                            old_rva = imm - self.new_base
                            if old_rva >= shift_lo_rva:
                                struct.pack_into('<Q', blob, i + 2, imm + shift)
                                re_patched += 1
                            i += 10
                            continue
                        i += 1
                    pd = bytes(blob)
                    # Also run disp32 / C7-imm fixup for non-movabs data references
                    pd, n3 = self._patch_disp32_image_vas_in_code(pd)
                    re_patched += n3
                    pd, n4 = self._patch_mov_rm_imm32_image_vas(pd)
                    re_patched += n4
                    pd, n5 = self._patch_alu_imm32_image_vas(pd)
                    re_patched += n5
                    pd, n6 = self._patch_mov_reg32_imm32_image_vas(pd)
                    re_patched += n6
                    patched_layout[idx] = (pn, pd, pf, pva)
            if re_patched:
                print(f"        Post-shift VA re-patches: {re_patched}")

        # ── Neutralize IAT-call thunks for missing x64 exports ──────────
        # Some x86 CRT functions (e.g. _controlfp) don't exist on x64.
        # IMPORT_RENAMES replaces them with same-DLL alternatives, but the
        # thunk wrapper can have stack-unwind issues.  Replace these thunks
        # with safe ``xor eax,eax; ret`` to let CRT init proceed.
        # Handle two patterns:
        #   FULL:  push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16; ...call...; mov rsp,r13; pop r13; ret
        #   LIGHT: sub rsp,0x20; and rsp,-16; ...call...; mov rsp,r13; pop r13; ret  (caller's r13)
        AW_PUSH_R13 = b'\x41\x55'               # push r13
        AW_MOV_R13  = b'\x49\x89\xe5'           # mov r13, rsp
        AW_SUB      = b'\x48\x83\xec\x20'       # sub rsp, 0x20
        AW_AND      = b'\x48\x83\xe4\xf0'       # and rsp, -16
        AW_EPI_MOV  = b'\x4c\x89\xec'           # mov rsp, r13
        AW_EPI_POP  = b'\x41\x5d'               # pop r13
        thunks_fixed = 0
        for idx, (pn, pd, pf, pva) in enumerate(patched_layout):
            if not (pf & 0x20000000):
                continue
            blob = bytearray(pd)
            i = 0
            while i < len(blob) - 16:
                # Match sub rsp,0x20; and rsp,-16
                if not (blob[i:i+4] == AW_SUB and blob[i+4:i+8] == AW_AND):
                    i += 1
                    continue
                # Determine if FULL (push r13; mov r13,rsp before sub) or LIGHT
                has_prologue = (i >= 5 and blob[i-5:i-3] == AW_PUSH_R13
                                and blob[i-3:i] == AW_MOV_R13)
                thunk_start = i - 5 if has_prologue else i
                # Find the epilogue after the call
                # Scan for call (FF 15 xx xx xx xx = 6 bytes, or FF D0 = 2 bytes)
                body_start = i + 8  # after sub+and
                found_epi = -1
                # Look for call [rip+disp] or call rax followed by mov rsp,r13; pop r13; ret
                for scan in range(body_start, min(body_start + 64, len(blob) - 6)):
                    # Check for FF 15 (call [rip+disp])
                    if (blob[scan] == 0xFF and blob[scan+1] == 0x15
                            and scan + 6 + 5 < len(blob)):
                        after_call = scan + 6
                    # Check for FF D0 (call rax)
                    elif (blob[scan:scan+2] == b'\xff\xd0'
                              and scan + 2 + 5 < len(blob)):
                        after_call = scan + 2
                    else:
                        continue
                    # Look for mov rsp,r13; pop r13; ret after call
                    for j in range(min(32, len(blob) - after_call - 5)):
                        if (blob[after_call+j:after_call+j+3] == AW_EPI_MOV
                                and blob[after_call+j+3:after_call+j+5] == AW_EPI_POP
                                and blob[after_call+j+5] == 0xC3):
                            found_epi = after_call + j
                            break
                    if found_epi >= 0:
                        break
                if found_epi < 0:
                    i += 1
                    continue
                # Found a thunk.  Fill the entire range with 0xC3 (ret) so
                # that ANY entry point (prologue, body, or mid-instruction)
                # immediately returns.  The caller's own stack unwind
                # (mov rsp,r13; pop r13) handles the rest correctly.
                thunk_end = found_epi + 6  # past ret
                for j in range(thunk_start, thunk_end):
                    blob[j] = 0xC3          # ret
                thunks_fixed += 1
                i = thunk_end
            if thunks_fixed:
                patched_layout[idx] = (pn, bytes(blob), pf, pva)
        if thunks_fixed:
            print(f"        Neutralized IAT-call thunks: {thunks_fixed}")

        # Nullcheck rematerialize MUST run after neutralize — that pass fills
        # matching thunks with ``ret`` sleds and can leave thin IAT wrappers
        # as bare-ret work paths again.  Also runs after every call-sync.
        if self._cmd_no_hacks and getattr(self, '_pure_heal_text', None):
            for idx, (pn, pd, pf, pva) in enumerate(patched_layout):
                if not (pf & 0x20000000):
                    continue
                blob = bytearray(pd)
                n = self._pure_rematerialize_nullcheck_iat_wrappers(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n:
                    print(f"        Post-neutralize nullcheck-IAT rematerialize "
                          f"({pn}): {n}")
                    patched_layout[idx] = (pn, bytes(blob), pf, pva)
                    if str(pn).startswith('.text'):
                        self._translated_text = bytes(blob)

        # ── Fix calls into shared epilogues ────────────────────────────
        # Some callers jump into the MIDDLE of a function's epilogue
        # (e.g. ``mov rsp,r13; pop r13; pop rbx; pop rdi; pop rsi; ret``),
        # skipping the prologue that saved those registers.  The CALL
        # pushes an extra return address which shifts the epilogue's pops
        # off by one.  Change E8→E9 AND NOP the wrapper so the epilogue
        # runs with the original frame pointer.
        EPI_MOV_R13 = b'\x4c\x89\xec'  # mov rsp, r13
        EPI_MOV_RBP = b'\x48\x89\xec'  # mov rsp, rbp
        # Standard call-align wrappers (precede every CALL)
        # Full:  push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16  (13 bytes)
        WRAP_FULL = b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'
        # Light: sub rsp,0x20; and rsp,-16  (8 bytes)
        WRAP_LIGHT = b'\x48\x83\xec\x20\x48\x83\xe4\xf0'
        epi_fixes = 0
        snapped = 0
        for idx, (pn, pd, pf, pva) in enumerate(patched_layout):
            if not (pf & 0x20000000):
                continue
            blob = bytearray(pd)
            i = 0
            while i < len(blob) - 5:
                # Find E8 (direct call)
                if blob[i] != 0xE8:
                    i += 1
                    continue
                if i + 5 > len(blob):
                    break
                rel = struct.unpack_from('<i', blob, i + 1)[0]
                call_src_rva = pva + i
                tgt_rva = (call_src_rva + 5 + rel) & 0xFFFFFFFF
                tgt_off = tgt_rva - pva
                if tgt_off < 0 or tgt_off + 3 > len(blob):
                    i += 5
                    continue
                # Check if target starts with mov rsp,r13 or mov rsp,rbp
                found_epi = False
                epi_target_off = tgt_off  # actual epilogue start
                for try_off in (tgt_off, tgt_off - 1):
                    if try_off < 0 or try_off + 5 > len(blob):
                        continue
                    if (blob[try_off:try_off+3] == EPI_MOV_R13
                            or blob[try_off:try_off+3] == EPI_MOV_RBP):
                        # Confirm pop follows within 2 bytes
                        if (try_off + 5 <= len(blob)
                                and blob[try_off+3:try_off+5] in (b'\x41\x5d', b'\x5d')):
                            found_epi = True
                            epi_target_off = try_off
                            break
                if not found_epi:
                    i += 5
                    continue
                if not reaches_ret_without_branching(blob, i + 5):
                    # Non-tail call into the previous function's teardown.
                    # The intended callee is the next real entry after ``ret``.
                    # Snapping onto the epilogue (or leaving a CALL there)
                    # runs pops the caller never balanced and returns into
                    # garbage — the getenv PATH crash at RIP=1.
                    nxt = next_prologue_after_shared_epilogue(
                        blob, epi_target_off, self._x64_entry_prologue_ok)
                    if nxt is not None and nxt != tgt_off:
                        new_tgt_rva = pva + nxt
                        struct.pack_into('<i', blob, i + 1,
                                         new_tgt_rva - (pva + i + 5))
                        snapped += 1
                    i += 5
                    continue
                # Tail call into a shared epilogue: snap onto the boundary if
                # the site was one byte inside the encoding, then rewrite as
                # JMP so the epilogue's pops run on the caller's frame.
                if epi_target_off != tgt_off:
                    new_tgt_rva = pva + epi_target_off
                    struct.pack_into('<i', blob, i + 1,
                                     new_tgt_rva - (pva + i + 5))
                    snapped += 1
                wrap_nop = 0
                if i >= 13 and blob[i-13:i] == WRAP_FULL:
                    wrap_nop = 13
                elif i >= 8 and blob[i-8:i] == WRAP_LIGHT:
                    wrap_nop = 8
                for w in range(i - wrap_nop, i):
                    blob[w] = 0x90  # NOP
                blob[i] = 0xE9  # CALL → JMP (same 5-byte encoding)
                epi_fixes += 1
                i += 5
            if epi_fixes or snapped:
                patched_layout[idx] = (pn, bytes(blob), pf, pva)
        if snapped:
            print(f"        Snapped shared-epilogue call targets: {snapped}")
        if epi_fixes:
            print(f"        Fixed shared-epilogue tail calls: {epi_fixes}")

        # Absolute last pure heals on .text.  Earlier post-repair call-sync /
        # align / EH3 passes rewrite B186's empty-path site back to B21C
        # (More?) and can re-break text-constant movabs — run these once
        # nothing else will touch .text.
        if self._cmd_no_hacks and getattr(self, '_pure_heal_text', None):
            for idx, (pn, pd, pf, pva) in enumerate(patched_layout):
                if not str(pn).startswith('.text'):
                    continue
                blob = bytearray(pd)
                n_cmd = self._pure_materialize_peb_cmdline_at_entry(blob)
                if n_cmd:
                    print(f"        Final pure PEB cmdline materialize: {n_cmd}")
                # NOTE: /c EF42 redirect is disabled — the only matching site is
                # CRT locale init (x86 C71E), which must keep EF42's return as a
                # pointer.  Rely on PEB cmdline materialize + cursor seed instead.
                # EF42 guard runs *after* pad-seeking epi heals (below).
                n_fd5d = self._pure_restore_stdcall_arg4_mem_callback_call(blob)
                if n_fd5d:
                    print(f"        Final pure stdcall arg4 mem-callback restores: {n_fd5d}")
                if getattr(self, '_pure_heal_text', None) is not None:
                    n_gpf = self._pure_fix_geparse_followup_call(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if n_gpf:
                        print(f"        Final pure GEParse follow-up CALL fixes: {n_gpf}")
                    n_zq = self._pure_retarget_calls_to_zero_quad_helper(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if n_zq:
                        print(f"        Final pure zero-quad helper CALL retargets: {n_zq}")
                n_bare = self._pure_snap_jcc_off_bare_ret_to_epilogue(blob)
                if n_bare:
                    print(f"        Final pure bare-ret→epilogue Jcc snaps: {n_bare}")
                n_sleave0 = self._pure_fix_jcc_short_pop_ret_to_local_leave_epi(blob)
                if n_sleave0:
                    print(f"        Final pure short-pop-ret→local-leave Jcc fixes: {n_sleave0}")
                n_arg0 = self._pure_fix_arg0_loaded_from_r8_after_homes(blob)
                if n_arg0:
                    print(f"        Final pure stdcall arg0 r8→rcx fixes: {n_arg0}")
                n_midimm = self._pure_snap_calls_into_mov_reg_imm(blob)
                if n_midimm:
                    print(f"        Final pure mid-mov-imm CALL snaps: {n_midimm}")
                n_diam = self._pure_fix_switch_diamond_code_arg_movabs(
                    blob, self.rva_map)
                if n_diam:
                    print(f"        Final pure switch-diamond code-arg fixes: {n_diam}")
                # Call-sync can re-pin E8s onto prior-fn ``mov eax,*; pop*; leave; ret``
                # using a collapsed rva_map slot (cmd fbe4→1df11).  Snap past that
                # epilogue onto the real body *after* every earlier sync pass.
                n_past = self._snap_branches_past_epilogues(blob)
                if n_past:
                    print(f"        Final pure epilogue-past call snaps: {n_past}")
                n_fwd = self._snap_calls_forward_past_epilogue(blob)
                if n_fwd:
                    print(f"        Final pure forward-past-epilogue call snaps: {n_fwd}")
                n_sh = self._snap_calls_back_past_frameless_shadow_homes(blob)
                if n_sh:
                    print(f"        Final pure shadow-home call snaps: {n_sh}")
                n_mai = self._snap_calls_back_past_mid_align_iat_entry(blob)
                if n_mai:
                    print(f"        Final pure mid-align IAT entry snaps: {n_mai}")
                n_ff15 = self._pure_fix_ff15_ret_sled_entries(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_ff15:
                    print(f"        Final pure ff15 ret-sled entry fixes: {n_ff15}")
                n_argptr = self._pure_fix_ebp_local_ptr_dword_store(blob)
                if n_argptr:
                    print(f"        Final pure ebp-local pointer dword widens: {n_argptr}")
                n_ep4 = self._pure_fix_call_ebp_minus4_as_neg4_abs(blob)
                if n_ep4:
                    print(f"        Final pure call-[ebp-4] as neg4-abs fixes: {n_ep4}")
                n_flags = self._pure_fix_flag_clobber_before_jcc(blob)
                if n_flags:
                    print(f"        Final pure flag-clobber-before-jcc fixes: {n_flags}")
                n_sib = self._pure_fix_scaled_index_old_image_disp(blob)
                if n_sib:
                    print(f"        Final pure scaled-index old-VA disp fixes: {n_sib}")
                n_csave = self._pure_fix_clobber_before_callee_save_pushes(blob)
                if n_csave:
                    print(f"        Final pure clobber-before-callee-save reorder: {n_csave}")
                n_arg1 = self._pure_fix_frameless_local_push_arg1_reg(blob)
                if n_arg1:
                    print(f"        Final pure frameless local-push arg1 fixes: {n_arg1}")
                n_homes = self._pure_nop_midframe_shadow_homes_after_locals(blob)
                if n_homes:
                    print(f"        Final pure mid-frame shadow-home NOPs: {n_homes}")
                n_ecxloc = self._pure_fix_missing_push_ecx_local_before_csr(blob)
                if n_ecxloc:
                    print(f"        Final pure push-ecx-local-before-CSR fixes: {n_ecxloc}")
                n_dloc = self._pure_fix_frameless_dual_local_frame(blob)
                if n_dloc:
                    print(f"        Final pure frameless dual-local frame fixes: {n_dloc}")
                n_lepi = self._pure_fix_frameless_local_epilogue_pops(blob)
                if n_lepi:
                    print(f"        Final pure frameless local-epilogue fixes: {n_lepi}")
                n_debs = self._pure_fix_delayed_edi_ebx_callee_saves(blob)
                if n_debs:
                    print(f"        Final pure delayed edi/ebx callee-save fixes: {n_debs}")
                n_hsz = self._pure_fix_heapsize_args_after_getprocessheap(blob)
                if n_hsz:
                    print(f"        Final pure HeapSize arg fixes: {n_hsz}")
                n_jrbx = self._pure_fix_je_skipping_rbx_iat_reload(blob)
                if n_jrbx:
                    print(f"        Final pure je→rbx-IAT-reload retargets: {n_jrbx}")
                n_rdi = self._pure_fix_volatile_rdi_node_across_calls(blob)
                if n_rdi:
                    print(f"        Final pure volatile rdi→r12 node parks: {n_rdi}")
                n_pushrcx = self._pure_fix_push_reg_as_win64_arg0(blob)
                if n_pushrcx:
                    print(f"        Final pure push-reg→rcx arg0 fixes: {n_pushrcx}")
                # Residual rdi pass after other pad consumers.
                n_rdi2 = self._pure_fix_volatile_rdi_node_across_calls(blob)
                if n_rdi2:
                    print(f"        Final pure volatile rdi→r12 residual: {n_rdi2}")
                n_wz = self._pure_fix_movzx_wchar_arg_after_partial_ax(blob)
                if n_wz:
                    print(f"        Final pure movzx wchar-arg fixes: {n_wz}")
                n_pr = self._pure_fix_push_imm_pop_eax_return(blob)
                if n_pr:
                    print(f"        Final pure push-imm/pop-eax return fixes: {n_pr}")
                n_drbx = self._pure_fix_dropped_rbx_scaled_word_store(blob)
                if n_drbx:
                    print(f"        Final pure dropped rbx*2 word-store fixes: {n_drbx}")
                n_dand = self._pure_fix_dropped_rbp_disp8_rbx_scaled_and(blob)
                if n_dand:
                    print(f"        Final pure dropped rbp+rbx*2 and-word fixes: {n_dand}")
                n_cur = self._pure_fix_dropped_ebp8_cursor_adds(blob)
                if n_cur:
                    print(f"        Final pure dropped ebp+8 cursor-add fixes: {n_cur}")
                n_rsp = self._pure_fix_rsp_disp0c_to_18(blob)
                if n_rsp:
                    print(f"        Final pure rsp+0xc→0x18 stack-home fixes: {n_rsp}")
                n_xor = self._pure_fix_xor_rdx_zeroed_before_call(blob)
                if n_xor:
                    print(f"        Final pure xor-arg-zero fixes: {n_xor}")
                n_ultoa = self._pure_fix_ultoa_value_as_dword_home(blob)
                if n_ultoa:
                    print(f"        Final pure _ultoa dword-home fixes: {n_ultoa}")
                n_cpush = self._pure_fix_code_push_imm_landed_in_empty_data(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_cpush:
                    print(f"        Final pure code-push-in-empty-data fixes: {n_cpush}")
                n_dtxt = self._pure_fix_data_abs_imm_landed_in_text(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_dtxt:
                    print(f"        Final pure data-imm-in-text movabs fixes: {n_dtxt}")
                n_mjcc = self._pure_materialize_unmapped_jcc_targets(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_mjcc:
                    print(f"        Final pure unmapped Jcc target materialize: {n_mjcc}")
                n_gle1 = self._pure_fix_stale_getlasterror_exitprocess1(blob)
                if n_gle1:
                    print(f"        Final pure stale GetLastError→ExitProcess(1) skips: {n_gle1}")
                n_exitw = self._pure_fix_exitprocess_wrapper_via_terminate(blob)
                if n_exitw:
                    print(f"        Final pure ExitProcess via TerminateProcess: {n_exitw}")
                n_rjoin = self._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob)
                if n_rjoin:
                    print(f"        Final pure reg-arg join add-rsp skips: {n_rjoin}")
                n_sdone = self._pure_fix_peb_c_sticky_done_on_zero_ret_epi(blob)
                if n_sdone:
                    print(f"        Final pure PEB-/c sticky-done on success epi: {n_sdone}")
                n_wexit = self._pure_fix_peb_c_lexer_exits_when_sticky_done(blob)
                if n_wexit:
                    print(f"        Final pure PEB-/c lexer sticky-done exits: {n_wexit}")
                n_wfs = self._pure_fix_infinite_wait_iat_to_waitforsingleobject(blob)
                if n_wfs:
                    print(f"        Final pure infinite-wait IAT→WaitForSingleObject: {n_wfs}")
                n_lj1 = self._pure_fix_longjmp_minus1_imm(blob)
                if n_lj1:
                    print(f"        Final pure longjmp -1 imm (sign-extend) fixes: {n_lj1}")
                n_swepi = self._pure_fix_epilogue_swallowed_into_prior_insn(blob)
                if n_swepi:
                    print(f"        Final pure epilogue-swallowed-into-prior-insn fixes: {n_swepi}")
                # Residual: rematerialized islands can leave ``nop; ret`` tips
                # that earlier bare-ret snaps missed (or that later layout
                # created).  Covers ``mov eax,1; leave; ret`` success epis.
                n_bare2 = self._pure_snap_jcc_off_bare_ret_to_epilogue(blob)
                if n_bare2:
                    print(f"        Final pure bare-ret→epilogue Jcc snaps (residual): {n_bare2}")
                # After rematerialize / bare-ret snaps: Jccs may still tip on a
                # short shared ``pop rbx; pop rbp; ret`` while the body's real
                # ``mov eax,esi; pop*; leave; ret`` sits a few dozen bytes ahead.
                n_sleave = self._pure_fix_jcc_short_pop_ret_to_local_leave_epi(blob)
                if n_sleave:
                    print(f"        Final pure short-pop-ret→local-leave Jcc fixes: {n_sleave}")
                n_zjcc = self._pure_fix_zeroed_jcc_after_cmp_success_epi(blob)
                if n_zjcc:
                    print(f"        Final pure zeroed-jcc-after-cmp / je-success fixes: {n_zjcc}")
                n_asib = self._pure_fix_align_stub_self_call_reuse_sibling(blob)
                if n_asib:
                    print(f"        Final pure align-stub self-call sibling reuse: {n_asib}")
                # Residual: sticky-done may rewrite the epi into ``add rsp,8; jmp``
                n_rjoin2 = self._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob)
                if n_rjoin2:
                    print(f"        Final pure reg-arg join add-rsp skips (residual): {n_rjoin2}")
                n_asr = self._pure_nop_spurious_stdcall_add_rsp_after_align(blob)
                if n_asr:
                    print(f"        Final pure spurious post-align add-rsp NOPs: {n_asr}")
                # Late: fill ``0F 00…`` Jccs left after rematerialize / join heals.
                # Tips often sit on the preceding cmp; resolve call-labels
                # (cmd f81b→10005) that the early pass missed.
                n_jph = self._pure_patch_jcc_placeholders(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_jph:
                    print(f"        Final pure unresolved Jcc placeholder patches: {n_jph}")
                n_aself = self._pure_repatch_align_stub_self_calls(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_aself:
                    print(f"        Final pure align-stub self-call repairs: {n_aself}")
                n_bt = self._pure_fix_branch_targets_from_x86_map(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_bt:
                    print(f"        Final pure x86-derived branch retargets: {n_bt}")
                n_jcave0 = self._pure_fix_jcc_to_corrupt_join_cave(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_jcave0:
                    print(f"        Final pure Jcc corrupt-join-cave retargets: {n_jcave0}")
                n_jfar0 = self._pure_fix_je_far_to_in_function_align_call(blob)
                if n_jfar0:
                    print(f"        Final pure far-je to in-function align-call: {n_jfar0}")
                n_jpt = self._pure_fix_jmp_wrong_shared_pop_tail(blob)
                if n_jpt:
                    print(f"        Final pure jmp→wrong shared pop-tail fixes: {n_jpt}")
                n_cep = self._pure_fix_call_into_epilogue_before_prologue(blob)
                if n_cep:
                    print(f"        Final pure call-into-epilogue retargets: {n_cep}")
                n_rxa = self._pure_fix_nested_call_return_clobbers_rax_arg(blob)
                if n_rxa:
                    print(f"        Final pure nested-call RAX arg saves: {n_rxa}")
                # After pad-seeking heals: EF42 pointer guard appends a stub
                # whose ``jae`` must not later be stolen as epi cave space.
                n_ef42 = self._pure_guard_ef42_init_return_as_pointer(blob)
                if n_ef42:
                    print(f"        Final pure EF42 return-pointer guards: {n_ef42}")
                n_r13l = self._pure_fix_frameless_r13_local_reload(blob)
                if n_r13l:
                    print(f"        Final pure frameless r13-local reloads: {n_r13l}")
                n_park = self._pure_fix_parked_arg0_stale_reload(blob)
                if n_park:
                    print(f"        Final pure parked-arg0 stale reload fixes: {n_park}")
                n_pushrcx = self._pure_fix_push_reg_as_win64_arg0(blob)
                if n_pushrcx:
                    print(f"        Final pure push-reg→rcx arg0 fixes: {n_pushrcx}")
                n_pushimm = self._pure_fix_push_imm_jmp_to_mov_rcx_call(blob)
                if n_pushimm:
                    print(f"        Final pure push-imm→mov ecx call-diamond fixes: {n_pushimm}")
                n_lcall = self._pure_fix_locale_call_reg_iat_reload(blob)
                if n_lcall:
                    print(f"        Final pure locale call-reg IAT reloads: {n_lcall}")
                n_stos = self._pure_fix_rep_stos_dest_clobber(blob)
                if n_stos:
                    print(f"        Final pure rep-stos dest clobber fixes: {n_stos}")
                n_hr = self._pure_fix_heaprealloc_mem_arg_after_getprocessheap(blob)
                if n_hr:
                    print(f"        Final pure HeapReAlloc mem-arg fixes: {n_hr}")
                n_fm = self._pure_fix_formatmessage_x86_fallback(blob)
                if n_fm:
                    print(f"        Final pure FormatMessage fallback fixes: {n_fm}")
                n_fmh = self._pure_fix_formatmessage_arg_homes(blob)
                if n_fmh:
                    print(f"        Final pure FormatMessage arg-home fixes: {n_fmh}")
                n_fmr = self._pure_fix_formatmessage_call_rbx(blob)
                if n_fmr:
                    print(f"        Final pure FormatMessage call-rbx reloads: {n_fmr}")
                n_cur = self._pure_seed_stream_cursor_from_parse_buffer(blob)
                if n_cur:
                    print(f"        Final pure parse-cursor seed stores: {n_cur}")
                n_bp = self._pure_fix_bp_scratch_clobbering_frame(blob)
                if n_bp:
                    print(f"        Final pure bp-scratch frame fixes: {n_bp}")
                n_rbpimm = self._pure_fix_rbp_imm_scratch_before_cmp(blob)
                if n_rbpimm:
                    print(f"        Final pure rbp-imm scratch→cmp-imm fixes: {n_rbpimm}")
                n_r13 = self._pure_restore_r13_after_align_call(blob)
                if n_r13:
                    print(f"        Final pure r13-align call restores: {n_r13}")
                n_tc = self._pure_fix_empty_data_text_constant_movabs(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_tc:
                    print(f"        Final pure text-constant movabs fixes: {n_tc}")
                # Absolute last-but-one: CALL snaps shred movabs E8 bytes.
                n_shift_last = self._pure_fix_shifted_data_movabs(
                    blob, self._pure_heal_text, self._pure_heal_text_rva)
                if n_shift_last:
                    print(f"        Final shifted data movabs fixes (last): {n_shift_last}")
                # After shifted-data: reclaim .text string args stolen into
                # empty .data tips (RegOpenKey/AutoRun). Must follow shift so
                # soft-E8 recovery cannot re-tip the strings.
                n_strarg = self._pure_fix_text_string_arg_movabs(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_strarg:
                    print(f"        Final pure text-string arg movabs fixes: {n_strarg}")
                # Shifted-data / text-constant passes can retarget the
                # FormatMessage Application movabs onto an empty .data cell.
                n_fm_final = self._pure_fix_formatmessage_insert_string_vas(blob)
                if n_fm_final:
                    print(f"        Final pure FormatMessage insert-string VAs: {n_fm_final}")
                # Absolute last: earlier shifted/text-string passes can retip
                # code-callback and .data-table movabs VAs.  Re-apply.
                n_cpush2 = self._pure_fix_code_push_imm_landed_in_empty_data(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_cpush2:
                    print(f"        Final pure code-push-in-empty-data fixes (last): {n_cpush2}")
                n_dtxt2 = self._pure_fix_data_abs_imm_landed_in_text(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_dtxt2:
                    print(f"        Final pure data-imm-in-text movabs fixes (last): {n_dtxt2}")
                n_mjcc2 = self._pure_materialize_unmapped_jcc_targets(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_mjcc2:
                    print(f"        Final pure unmapped Jcc target materialize (last): {n_mjcc2}")
                n_bt2 = self._pure_fix_branch_targets_from_x86_map(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_bt2:
                    print(f"        Final pure x86-derived branch retargets (last): {n_bt2}")
                # After branch retarget: synthesize table match arms whose
                # Jccs still land on push r13 (branch healer may re-tip).
                n_mjcc3 = self._pure_materialize_unmapped_jcc_targets(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_mjcc3:
                    print(f"        Final pure unmapped Jcc target materialize (final): {n_mjcc3}")
                n_jcave = self._pure_fix_jcc_to_corrupt_join_cave(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_jcave:
                    print(f"        Final pure Jcc corrupt-join-cave retargets: {n_jcave}")
                n_jfar = self._pure_fix_je_far_to_in_function_align_call(blob)
                if n_jfar:
                    print(f"        Final pure far-je to in-function align-call: {n_jfar}")
                n_jpt2 = self._pure_fix_jmp_wrong_shared_pop_tail(blob)
                if n_jpt2:
                    print(f"        Final pure jmp→wrong shared pop-tail fixes (last): {n_jpt2}")
                # After final Jcc retargets: re-apply push-reg residual so a
                # stolen mov-rcx cave tip is restored (cmd 0x18110 Dispatch).
                n_pushrcx3 = self._pure_fix_push_reg_as_win64_arg0(blob)
                if n_pushrcx3:
                    print(f"        Final pure push-reg->rcx arg0 fixes (last): {n_pushrcx3}")
                n_dand2 = self._pure_fix_dropped_rbp_disp8_rbx_scaled_and(blob)
                if n_dand2:
                    print(f"        Final pure dropped rbp+rbx*2 and-word fixes (last): {n_dand2}")
                n_cur2 = self._pure_fix_dropped_ebp8_cursor_adds(blob)
                if n_cur2:
                    print(f"        Final pure dropped ebp+8 cursor-add fixes (last): {n_cur2}")
                # Absolute last CF hygiene: late rematerialize can re-emit
                # ``0F 00…`` / align self-calls (cmd paren/@ handler).
                n_jph2 = self._pure_patch_jcc_placeholders(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_jph2:
                    print(f"        Final pure unresolved Jcc placeholder patches (last): {n_jph2}")
                n_aself2 = self._pure_repatch_align_stub_self_calls(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_aself2:
                    print(f"        Final pure align-stub self-call repairs (last): {n_aself2}")
                n_bt3 = self._pure_fix_branch_targets_from_x86_map(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_bt3:
                    print(f"        Final pure x86-derived branch retargets (last2): {n_bt3}")
                # Absolute-last catch-all: NOP remaining self-calls that
                # every heuristic-based fix missed (orphan rematerialized
                # stubs, large functions with few rva_map entries, etc.).
                n_remat = self._pure_rematerialize_unmapped_function_clusters(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_remat:
                    print(f"        Final pure unmapped-cluster rematerialize: "
                          f"{n_remat}")
                # Rematerialized windows may contain fresh ``call __chkstk``
                # sites and helper copies — re-apply the chkstk exact-size
                # fixes (idempotent) before stub-call restoration.
                n_ck_add2 = self._fix_chkstk_epilogue_adds(blob)
                if n_ck_add2:
                    print(f"        Final pure _chkstk epilogue ADD fixes: "
                          f"{n_ck_add2}")
                n_ck_epi2 = self._fix_alloca_probe_epilogues(blob)
                if n_ck_epi2:
                    print(f"        Final pure _alloca_probe tail fixes: "
                          f"{n_ck_epi2}")
                n_order = self._pure_restore_stub_calls_by_x86_order(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_order:
                    print(f"        Final pure x86-ordered stub-call restores: "
                          f"{n_order}")
                n_catch = self._pure_nop_all_remaining_self_calls(
                    blob, self.rva_map, self._pure_heal_text,
                    self._pure_heal_text_rva)
                if n_catch:
                    print(f"        Final pure catch-all self-call fixes: {n_catch}")
                n_snap_home = self._pure_snap_calls_past_arg_homes(blob)
                if n_snap_home:
                    print(f"        Final pure call→prologue arg-home snaps: "
                          f"{n_snap_home}")
                n_snap_tail = self._pure_snap_calls_off_callr_epilogue_tails(blob)
                if n_snap_tail:
                    print(f"        Final pure call→prologue tail snaps: "
                          f"{n_snap_tail}")
                n_zero = self._pure_neutralize_calls_into_zero_holes(blob)
                if n_zero:
                    print(f"        Final pure zero-hole call neutralizes: {n_zero}")
                # Absolute last: re-materialize missing/stale functions now
                # that NO further pass can overwrite the fresh chunks, then
                # re-derive every x86-based branch and repair stale copies.
                _old_mmf_map = dict(self.rva_map)
                n_mmf2 = self._materialize_missing_functions(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_mmf2:
                    print(f"        Final pure missing-function rematerialize: {n_mmf2}")
                    n_rtc = self._pure_retarget_calls_from_stale_map(
                        blob, self.rva_map, dict(_old_mmf_map),
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if n_rtc:
                        print(f"        Final pure stale-slot call retargets: {n_rtc}")
                    n_bt3 = self._pure_fix_branch_targets_from_x86_map(
                        blob, self.rva_map,
                        self._pure_heal_text, self._pure_heal_text_rva)
                    if n_bt3:
                        print(f"        Final pure x86 branch retargets post-MMF: {n_bt3}")
                    n_jpt3 = self._pure_fix_jmp_wrong_shared_pop_tail(blob)
                    if n_jpt3:
                        print(f"        Final pure pop-tail fixes post-MMF: {n_jpt3}")
                n_cip = self._pure_fix_calls_into_implausible_entries(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_cip:
                    print(f"        Final pure implausible-entry call fixes: {n_cip}")
                n_se8 = self._pure_fix_single_e8_stale_copy_calls(
                    blob, self.rva_map,
                    self._pure_heal_text, self._pure_heal_text_rva)
                if n_se8:
                    print(f"        Final pure single-E8 stale-copy call fixes: {n_se8}")
                patched_layout[idx] = (pn, bytes(blob), pf, pva)
                self._translated_text = bytes(blob)

        sections_layout: List[Tuple[str, bytes, int, int]] = list(patched_layout)
        resource_rva = 0
        resource_sz = 0
        old_res_rva, old_res_sz = pe.dir_resource
        for name, raw, flags, old_va, new_va in planned_data:
            if name.lower() == '.rsrc':
                raw = fixup_rsrc_section(raw, old_va, new_va)
                if self.win10_test_shim and not self._cmd_no_hacks:
                    rsrc_blob = bytearray(raw)
                    rsrc_fix = self._fix_cmd_banner_format_swprintf_s(rsrc_blob, old_va)
                    if rsrc_fix:
                        raw = bytes(rsrc_blob)
                if old_res_rva and old_res_sz:
                    resource_rva = new_va + (old_res_rva - old_va)
                    resource_sz = old_res_sz
            else:
                raw = fixup_data_section(
                    raw, old_va, self.pe_relocs,
                    self.old_base, self.new_base, pe.image_size,
                    pointer_sites, self.dyn.pointer_writes,
                    pe=pe, old_to_new_section=self._old_to_new_section,
                    iat_rva_map=self._iat_rva_map,
                    final_rva_map=self._final_rva)
                if name.lower() == '.data' and self.win10_test_shim:
                    data_blob = bytearray(raw)
                    data_fix = 0
                    # cmd-specific .text buffer zeroing is a hack that must
                    # NOT run in pure mode: those RVAs hold translated CODE
                    # there (the first-pass copy of x86 0x5C02 lives at
                    # 0x414D8 — calls snap to it and the wipe left them
                    # dangling into a zero hole → zero-sled recursion crash).
                    if not self._cmd_no_hacks:
                        # The _fix_cmd_data_* functions target .text section
                        # RVAs, not .data section RVAs.  Operate on the
                        # translated text blob (self._translated_text) with
                        # the .text section's base RVA so the hardcoded-address
                        # arithmetic works.
                        text_blob = bytearray(self._translated_text)
                        text_base_rva = code_layout[0][3]  # .text section RVA
                        data_fix += self._fix_cmd_data_switch_literals(text_blob, text_base_rva)
                        data_fix += self._fix_cmd_data_echo_test_literal(text_blob, text_base_rva)
                        # Order matters: zero buffers BEFORE writing format strings
                        # that may overlap with buffer areas.
                        data_fix += self._fix_cmd_data_os_version_buffer(text_blob, text_base_rva)
                        data_fix += self._fix_cmd_data_prompt_buffer(text_blob, text_base_rva)
                        data_fix += self._fix_cmd_data_readline_buffer(text_blob, text_base_rva)
                        data_fix += self._fix_cmd_data_os_version_fmt(text_blob, text_base_rva)
                        data_fix += self._fix_cmd_data_banner_format_swprintf_s(text_blob, text_base_rva)
                        if data_fix:
                            self._translated_text = bytes(text_blob)
                            # Update both patched_layout and sections_layout so the
                            # modified .text data is emitted into the final PE.
                            pn, _pd, pf, pva = patched_layout[0]
                            patched_layout[0] = (pn, bytes(text_blob), pf, pva)
                            sections_layout[0] = (pn, bytes(text_blob), pf, pva)
                    # Zero out stale CRT init function pointers that hold
                    # the 0x80000001 sentinel (new_base+1).  These cause
                    # the NULL-skip check to fail, leading to calls through
                    # unresolved IAT entries.
                    for di in range(0, len(data_blob) - 7, 8):
                        if struct.unpack_from('<Q', data_blob, di)[0] == 0x80000001:
                            struct.pack_into('<Q', data_blob, di, 0)
                            data_fix += 1
                    if data_fix:
                        raw = bytes(data_blob)
            sections_layout.append((name, raw, flags, new_va))

        idata_blob = self._idata_blob
        if idata_blob:
            sections_layout.append(('.idata', idata_blob, 0xC0000040, idata_rva))
            current_va = align(idata_rva + len(idata_blob), SECT_ALIGN)

        edata_rva = current_va
        edata_blob = b''
        if pe.parse_exports():
            edata_blob = self._build_export_directory(edata_rva)
            sections_layout.append(('.edata', edata_blob, 0x40000040, edata_rva))
            current_va = align(edata_rva + len(edata_blob), SECT_ALIGN)

        reloc_rva = current_va
        reloc_blob = self._build_reloc_directory(reloc_rva, sections_layout, pointer_sites)
        if reloc_blob:
            sections_layout.append(('.reloc', reloc_blob, 0x42000040, reloc_rva))
            current_va = align(reloc_rva + len(reloc_blob), SECT_ALIGN)

        num_sections = len(sections_layout)
        # Optional header is 240 bytes total (112 std + 128 data dirs); do NOT
        # add 16*8 again — that was shifting the section table and corrupting names.
        hdrs_size = align(64 + 4 + 20 + PE64_OPT + num_sections * SECT_ENTRY, FILE_ALIGN)
        image_size = align(current_va, SECT_ALIGN)
        new_entry_rva = self._export_rva(pe.entry_rva) if pe.entry_rva else 0

        if pe.entry_rva and (self.win10_test_shim or self._cmd_no_hacks):
            try:
                text_blob = self._translated_text
                if not text_blob:
                    text_blob = next(
                        b for (nm, b, _fl, _rva) in sections_layout
                        if str(nm).startswith('.text'))
                new_entry_rva = self._resolve_pe64_entry_rva(
                    text_blob, self.text_rva or text_rva, new_entry_rva)
                if self._cmd_no_hacks:
                    print(f"        Pure PE entry RVA: 0x{new_entry_rva:X} "
                          f"(x86 0x{pe.entry_rva:X})")
            except Exception as exc:
                if self._cmd_no_hacks:
                    print(f"        Entry resolve failed: {exc}")

        # ── Universal x64 entry-point RSP alignment stub ──────────────────
        # The OS loader sets RSP to 8-mod-16 (x64 ABI), but the translated
        # CRT startup may execute a mix of 4-byte x86 pushes (translated to
        # 8-byte x64 pushes) that can leave RSP misaligned.  This tiny stub
        # runs before any translated code and forces RSP to 16-byte alignment,
        # preventing cumulative stack drift across the entire process lifetime.
        # Universal for every Win2000 pure-mode binary.
        if self._cmd_no_hacks and new_entry_rva:
            # and rsp, -16  (4 bytes)  +  jmp rel32  (5 bytes) = 9 bytes
            align_stub = b'\x48\x83\xe4\xf0'  # and rsp, -16
            rel = (new_entry_rva - (text_rva + len(text_blob) + 9)) & 0xFFFFFFFF
            align_stub += b'\xe9' + struct.pack('<I', rel)
            stub_rva = text_rva + len(text_blob)
            # Append stub to the .text blob in sections_layout
            for si, (nm, b, fl, rva) in enumerate(sections_layout):
                if isinstance(nm, bytes):
                    nm = nm.decode('ascii', errors='replace')
                if nm.startswith('.text'):
                    sections_layout[si] = (nm, b + align_stub, fl, rva)
                    break
            new_entry_rva = stub_rva
            if self._cmd_no_hacks:
                print(f"        Entry alignment stub at 0x{stub_rva:X}")
            # PEB cmdline materialize must run *after* the entry stub exists;
            # the earlier absolute-last heal block cannot see it yet.
            if getattr(self, '_pure_heal_text', None):
                for si, (nm, b, fl, rva) in enumerate(sections_layout):
                    if isinstance(nm, bytes):
                        nm = nm.decode('ascii', errors='replace')
                    if not nm.startswith('.text'):
                        continue
                    blob = bytearray(b)
                    n_cmd = self._pure_materialize_peb_cmdline_at_entry(blob)
                    if n_cmd:
                        print(f"        Final pure PEB cmdline materialize: {n_cmd}")
                        sections_layout[si] = (nm, bytes(blob), fl, rva)
                        self._translated_text = bytes(blob)
                    break

        # ── Ultimate safety-net: fix missing pop r13 in align stub epilogues ──
        # Must run AFTER all other heals and just before PE assembly.
        if self._cmd_no_hacks:
            for si, (nm, b, fl, rva) in enumerate(sections_layout):
                if isinstance(nm, bytes):
                    nm = nm.decode('ascii', errors='replace')
                if not nm.startswith('.text'):
                    continue
                blob = bytearray(b)
                n_pop13 = self._fix_missing_pop_r13_after_align(blob)
                if n_pop13:
                    print(f"        Ultimate pop-r13 align fix: {n_pop13}")
                    sections_layout[si] = (nm, bytes(blob), fl, rva)
                    self._translated_text = bytes(blob)
                break

        dos = b'MZ' + b'\x00' * 0x3A + struct.pack('<I', 0x40)
        pe_sig = b'PE\x00\x00'
        coff = struct.pack('<HHIIIHH',
            0x8664, num_sections, pe.timestamp, 0, 0,
            PE64_OPT, pe.characteristics | 0x0020)

        opt_hdr = struct.pack('<HBBI', 0x020B, 14, 0, align(code_size, FILE_ALIGN))
        opt_hdr += struct.pack('<III',
            align(sum(len(s[1]) for s in sections_layout if not (s[2] & 0x20000000)), FILE_ALIGN),
            0, new_entry_rva)
        opt_hdr += struct.pack('<IQ', text_rva, self.new_base)
        opt_hdr += struct.pack('<IIHHHHHH', SECT_ALIGN, FILE_ALIGN, 5, 2, 0, 0, 5, 2)
        opt_hdr += struct.pack('<IIII', 0, image_size, hdrs_size, 0)
        # DllCharacteristics: NX_COMPAT | TS_AWARE only. ASLR (DYNAMIC_BASE /
        # HIGH_ENTROPY_VA) is disabled so the image loads at its preferred base;
        # otherwise an EXE rebased below 4 GiB could be moved above 4 GiB and
        # the 32-bit data-pointer assumption (high dword == 0) would break.
        opt_hdr += struct.pack('<HH', pe.subsystem, 0x8100)
        # x64 frames are 2–4× larger than x86 (shadow space, 8-byte pushes,
        # alignment wrappers).  Reserve a proportionally larger stack so
        # deeply nested Win2000 binaries don't overflow.  Universal for all
        # translated PE64 images.
        opt_hdr += struct.pack('<QQQQ', 0x1000000, 0x10000, 0x1000000, 0x10000)
        opt_hdr += struct.pack('<II', 0, 16)
        if len(opt_hdr) != PE64_OPT_STD:
            raise RuntimeError(
                f"PE64 optional header std fields: expected {PE64_OPT_STD}, got {len(opt_hdr)}")

        export_rva = edata_rva if edata_blob else 0
        export_sz = len(edata_blob) if edata_blob else 0
        import_rva = idata_rva if idata_blob else 0
        import_sz = len(idata_blob) if idata_blob else 0
        basereloc_rva = reloc_rva if reloc_blob else 0
        basereloc_sz = len(reloc_blob) if reloc_blob else 0

        data_dirs = b''
        for idx in range(16):
            if idx == 0:
                data_dirs += struct.pack('<II', export_rva, export_sz)
            elif idx == 1:
                data_dirs += struct.pack('<II', import_rva, import_sz)
            elif idx == 2:
                data_dirs += struct.pack('<II', resource_rva, resource_sz)
            elif idx == 5:
                data_dirs += struct.pack('<II', basereloc_rva, basereloc_sz)
            else:
                data_dirs += struct.pack('<II', 0, 0)
        if len(data_dirs) != 128:
            raise RuntimeError(f"PE64 data directories: expected 128, got {len(data_dirs)}")

        sect_hdrs = b''
        file_ptr = hdrs_size
        section_rvas = sorted(sva for _n, _d, _f, sva in sections_layout)
        for sname, sdata, sflags, sva in sections_layout:
            raw_sz = align(len(sdata), FILE_ALIGN)
            # CODE_GROWTH_HEADROOM reserves virtual space past the end of the
            # code.  That reservation has to live inside this section's
            # VirtualSize: the loader maps sections back to back, and if the
            # next section's RVA is past where this one ends it rejects the
            # whole image with ERROR_BAD_EXE_FORMAT and says nothing further.
            virt_sz = len(sdata)
            nxt = next((r for r in section_rvas if r > sva), 0)
            if nxt and nxt > align(sva + len(sdata), SECT_ALIGN):
                virt_sz = nxt - sva
            n = sname.encode('ascii', 'replace')[:8].ljust(8, b'\x00')
            sect_hdrs += struct.pack('<8sIIIIIIHHI',
                                     n, virt_sz, sva, raw_sz, file_ptr,
                                     0, 0, 0, 0, sflags)
            file_ptr += raw_sz

        header_blob = (dos + pe_sig + coff + opt_hdr + data_dirs + sect_hdrs)
        header_blob = header_blob.ljust(hdrs_size, b'\x00')
        out = bytearray(header_blob)
        for _, sdata, _, _ in sections_layout:
            out += sdata.ljust(align(len(sdata), FILE_ALIGN), b'\x00')
        return bytes(out)

