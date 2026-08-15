"""Translator methods not yet sorted into a domain module.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class MiscMixin:
    """See the module docstring."""

    _ALIGN_HEAD = b'\x41\x55\x49\x89\xe5'  # push r13; mov r13, rsp


    def _imm_to_old_rva(self, imm32: int) -> int:
        imm32 &= 0xFFFFFFFF
        if self.old_base <= imm32 < self.old_base + self.pe.image_size:
            return imm32 - self.old_base
        return imm32

    def _read_pe_dword(self, rva: int) -> int:
        sec = self.pe.section_for_rva(rva)
        if not sec:
            return 0
        data = self.pe.get_section_data(sec)
        off = rva - sec['vaddr']
        if off < 0 or off + 4 > len(data):
            return 0
        return struct.unpack_from('<I', data, off)[0]

    def _rcx_home_reload_needed(self, insns) -> bool:
        """Spill RCX at entry when mov ecx,[EBP+8] reloads the real arg0."""
        ebp8_stored = False
        for ins in insns:
            if ins.mnemonic != 'mov' or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if (dst.type == X86_OP_MEM and dst.mem.base == X86_REG_EBP
                    and dst.mem.disp == 8):
                ebp8_stored = True
            if (not ebp8_stored and src.type == X86_OP_MEM
                    and src.mem.base == X86_REG_EBP and src.mem.disp == 8
                    and dst.type == X86_OP_REG and dst.reg == X86_REG_ECX):
                return True
        return False

    def _maybe_spill_rcx_home(self, out: bytearray, rcx_home_reload: bool,
                              ebp_frame_active: bool, frame_args_spilled: bool,
                              dest_reg: str, src_reg: str) -> bool:
        """Save RCX to [RBP+0x10] before it is clobbered for a call argument."""
        if (rcx_home_reload and ebp_frame_active and not frame_args_spilled
                and dest_reg == 'rcx' and src_reg != 'rcx'):
            out += self._asm('mov qword ptr [rbp+0x10], rcx')
            return True
        return False

    def _flush_deferred_pushes(self, out: bytearray,
                               push_stack: List[Tuple[str, int]]) -> int:
        """Emit accumulated PUSH insns (callee-saves / SEH), not call arguments."""
        emitted = 0
        kept: List[Tuple[str, int]] = []
        for atype, aval in push_stack:
            if atype in ('ebp_arg', 'esp_fwd', 'ebp_local', 'ebp_slot', 'esp_mem'):
                kept.append((atype, aval))
                continue
            if atype == 'arg_home':
                kept.append((atype, aval))
                continue
            if atype == 'reg':
                r = W32_TO_W64_REG.get(aval, 'rax')
                out += self._asm(f'push {r}')
                emitted += 1
            elif atype == 'imm':
                imm = self._relocate_imm(aval & 0xFFFFFFFF, len(out), 0)
                self._emit_push_imm64(out, imm)
                emitted += 1
            elif atype == 'mem_abs':
                va = self._relocate_imm(aval & 0xFFFFFFFF, len(out), 0)
                out += self._encode_abs_load('rax', va)
                out += self._asm('push rax')
                emitted += 1
            elif atype == 'mem_base':
                base, disp = aval
                self._emit_mem_base_dword_load(out, 'rax', base, disp)
                out += self._asm('push rax')
                emitted += 1
            elif atype == 'mem':
                out += self._asm('push qword ptr [0]')  # rare; best effort
                emitted += 1
            else:
                out += self._asm('push 0')
                emitted += 1
        push_stack[:] = kept
        return emitted

    def _build_win10_echo_stub_parts(self, p1_rva: int, p2_rva: int, msg_rva: int,
                                     wcsstr_iat: int, wcslen_iat: int, getcl_iat: int,
                                     getstd: int, writefn: int, exit_iat: int) -> Tuple[bytes, bytes]:
        """Two-part echo stub: p1 finds text + length, p2 WriteConsoleW + _exit."""
        nb = self.new_base

        def va(rva: int) -> int:
            return nb + rva

        def ff15(at_rva: int, iat: int) -> bytes:
            return b'\xff\x15' + struct.pack('<i', iat - (va(at_rva) + 6))

        p1 = bytearray()

        def p1_at() -> int:
            return p1_rva + len(p1)

        def put1(*parts: bytes) -> None:
            for part in parts:
                p1.extend(part)

        put1(b'\x48\x83\xec\x28')
        gcl_call = p1_at()
        put1(ff15(gcl_call, getcl_iat))
        put1(b'\x48\x89\xc1')
        put1(b'\x48\x8d\x15')
        lea_disp = len(p1)
        put1(b'\x00\x00\x00\x00')
        wcs_call = p1_at()
        put1(ff15(wcs_call, wcsstr_iat))
        put1(b'\x48\x85\xc0', b'\x0f\x84')
        jz_fail = len(p1)
        put1(b'\x00\x00\x00\x00')
        put1(b'\x48\x8d\x70\x0a', b'\x48\x89\xf1')
        wcl_call = p1_at()
        put1(ff15(wcl_call, wcslen_iat))
        put1(b'\x89\xc3', b'\xc7\x04\x5e\x0d\x00\x0a\x00', b'\x83\xc3\x02')
        put1(b'\xe9')
        j_main = len(p1)
        put1(b'\x00\x00\x00\x00')

        lea_from = va(p1_rva + lea_disp + 4)
        struct.pack_into('<i', p1, lea_disp, va(msg_rva) - lea_from)
        fail_from = p1_rva + jz_fail + 4
        struct.pack_into('<i', p1, jz_fail, p2_rva - fail_from)

        p2 = bytearray()

        def put2(*parts: bytes) -> None:
            for part in parts:
                p2.extend(part)

        put2(b'\x31\xc9')
        ex0 = p2_rva + len(p2)
        put2(ff15(ex0, exit_iat))
        p2_main = p2_rva + len(p2)
        put2(b'\x41\x55', b'\x49\x89\xe5', b'\x48\x83\xec\x20', b'\x48\x83\xe4\xf0')
        put2(b'\xb9\xf5\xff\xff\xff')
        gs_call = p2_rva + len(p2)
        put2(ff15(gs_call, getstd))
        put2(b'\x48\x89\xc1', b'\x48\x89\xf2', b'\x01\xdb', b'\x41\x89\xd8')
        put2(b'\x4c\x8d\x4c\x24\x20', b'\x48\xc7\x44\x24\x18\x00\x00\x00\x00')
        wc_call = p2_rva + len(p2)
        put2(ff15(wc_call, writefn))
        put2(b'\x31\xc9')
        ex1 = p2_rva + len(p2)
        put2(ff15(ex1, exit_iat))

        main_from = p1_rva + j_main + 4
        struct.pack_into('<i', p1, j_main, p2_main - main_from)
        return bytes(p1), bytes(p2)

    def _build_win10_echo_stub_single(self, stub_rva: int, msg_rva: int,
                                      wcsstr_iat: int, wcslen_iat: int, getcl_iat: int,
                                      getstd: int, writefn: int, exit_iat: int) -> bytes:
        """One-part /c echo stub (<=93 bytes at RVA 0x8F6F)."""
        nb = self.new_base
        s = bytearray()

        def va(rva: int) -> int:
            return nb + rva

        def at() -> int:
            return stub_rva + len(s)

        def put(*parts: bytes) -> None:
            for part in parts:
                s.extend(part)

        def ff15(iat: int) -> bytes:
            a = at()
            return b'\xff\x15' + struct.pack('<i', iat - (va(a) + 6))

        put(b'\x48\x83\xec\x48')
        put(ff15(getcl_iat))
        put(b'\x48\x89\xc1')
        put(b'\x48\x8d\x15')
        lea1 = len(s)
        put(b'\x00\x00\x00\x00')
        put(ff15(wcsstr_iat))
        put(b'\x48\x85\xc0', b'\x0f\x84')
        jz = len(s)
        put(b'\x00\x00\x00\x00')
        put(b'\x48\x8d\x70\x0a', b'\x48\x89\xf1')
        put(ff15(wcslen_iat))
        put(b'\x89\xc3', b'\xc7\x04\x5e\x0d\x00\x0a\x00', b'\x83\xc3\x02')
        put(b'\xb9\xf5\xff\xff\xff')
        put(ff15(getstd))
        put(b'\x48\x89\xc1', b'\x48\x89\xf2', b'\x01\xdb', b'\x41\x89\xd8')
        put(b'\x4c\x8d\x4c\x24\x30', b'\x48\xc7\x44\x24\x28\x00\x00\x00\x00')
        put(ff15(writefn))
        put(b'\x31\xc9')
        put(ff15(exit_iat))
        ex = at()
        put(b'\x31\xc9')
        put(ff15(exit_iat))
        struct.pack_into('<i', s, lea1, va(msg_rva) - va(stub_rva + lea1 + 4))
        struct.pack_into('<i', s, jz, ex - (stub_rva + jz + 4))
        return bytes(s)

    def _build_win10_guard_compact_8fcc(self, slot_rva: int, echo_rva: int,
                                            interact_rva: int) -> Optional[bytes]:
        """GetCommandLineW; wcsstr(cmdline,L\"/c\"); /c -> echo_rva else jmp interact_rva."""
        wcsstr_iat = self._loader_iat_va('MSVCRT.dll', 'wcsstr')
        if not wcsstr_iat:
            wcsstr_iat = self._resolve_iat_slot_va(self.old_base + 0x12AC)
        getcl = self._loader_iat_va('KERNEL32.dll', 'GetCommandLineW')
        if not wcsstr_iat or not getcl:
            return None
        nb = self.new_base
        slash_c = nb + 0x41484
        body = bytearray()
        body += b'\x48\x83\xec\x28'
        gcl_at = slot_rva + len(body)
        body += b'\xff\x15' + struct.pack('<i', getcl - (nb + gcl_at + 6))
        body += b'\x48\x89\xc6'                      # mov rsi, rax (cmdline for wcsncpy)
        body += b'\x48\x89\xc1'                      # mov rcx, rax
        body += b'\x48\x8d\x15'
        lea_at = len(body)
        body += b'\x00\x00\x00\x00'
        wcs_at = slot_rva + len(body)
        body += b'\xff\x15' + struct.pack('<i', wcsstr_iat - (nb + wcs_at + 6))
        body += b'\x48\x83\xc4\x28'
        body += b'\x48\x85\xc0'
        jnz_pos = len(body)
        body += b'\x0f\x85\x00\x00\x00\x00'
        jmp_from = slot_rva + len(body)
        rel_inter = interact_rva - (jmp_from + 5)
        if not (-2147483648 <= rel_inter <= 2147483647):
            return None
        body += b'\xe9' + struct.pack('<i', rel_inter)
        lea_from = slot_rva + lea_at + 4
        struct.pack_into('<i', body, lea_at, slash_c - (nb + lea_from))
        jnz_from = slot_rva + jnz_pos + 6
        rel_echo = echo_rva - jnz_from
        if not (-2147483648 <= rel_echo <= 2147483647):
            return None
        struct.pack_into('<i', body, jnz_pos + 2, rel_echo)
        return bytes(body)

    def _build_win10_interactive_guard_body(self, slot_rva: int,
                                            cont_rva: int) -> Optional[bytes]:
        """GetCommandLineW + wcsstr(L\"/c\"); jne cont_rva else ExitProcess(0)."""
        wcsstr_iat = self._loader_iat_va('MSVCRT.dll', 'wcsstr')
        if not wcsstr_iat:
            wcsstr_iat = self._resolve_iat_slot_va(self.old_base + 0x12AC)
        exit_iat = self._loader_iat_va('KERNEL32.dll', 'ExitProcess')
        if not exit_iat:
            exit_iat = self._loader_iat_va('MSVCRT.dll', '_exit')
        if not exit_iat:
            exit_iat = self._loader_iat_va('MSVCRT.dll', 'exit')
        getcl = self._loader_iat_va('KERNEL32.dll', 'GetCommandLineW')
        if not wcsstr_iat or not exit_iat or not getcl:
            return None
        slash_c = self.new_base + 0x41484
        nb = self.new_base
        body = bytearray()
        body += b'\x48\x83\xec\x28'
        gcl_at = slot_rva + len(body)
        rel_gcl = getcl - (nb + gcl_at + 6)
        body += b'\xff\x15' + struct.pack('<i', rel_gcl)
        body += b'\x48\x89\xc1'
        body += b'\x48\x8d\x15'
        lea_at = len(body)
        body += b'\x00\x00\x00\x00'
        body += b'\x48\x83\xec\x20'
        ff_at = slot_rva + len(body)
        rel = wcsstr_iat - (nb + ff_at + 6)
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\x83\xc4\x20'
        body += b'\x48\x83\xc4\x28'
        body += b'\x48\x85\xc0'
        jnz_pos = len(body)
        body += b'\x0f\x85\x00\x00\x00\x00'
        body += b'\x31\xc9'
        ex_at = slot_rva + len(body)
        rel2 = exit_iat - (nb + ex_at + 6)
        body += b'\xff\x15' + struct.pack('<i', rel2)
        lea_from = slot_rva + lea_at + 4
        struct.pack_into('<i', body, lea_at, slash_c - (nb + lea_from))
        jnz_from = slot_rva + jnz_pos + 6
        struct.pack_into('<i', body, jnz_pos + 2, cont_rva - jnz_from)
        return bytes(body)

    def _outer_entry_before_align(self, out: bytearray, pos: int) -> Optional[int]:
        """If *pos* sits inside a call-align prologue, return the outer push entry."""
        if pos < 0 or pos >= len(out):
            return None
        for back in range(0, 32):
            p = pos - back
            if p < 0 or p + len(self._ALIGN_HEAD) > len(out):
                continue
            if out[p:p + len(self._ALIGN_HEAD)] != self._ALIGN_HEAD:
                continue
            align_end = p + len(self._ALIGN_WRAP)
            if pos < p or pos >= align_end + 8:
                continue
            ent = p
            while ent > 0 and out[ent - 1] in (0x53, 0x56, 0x57, 0x55):
                ent -= 1
            return ent
        return None

    def _shim_offset_for_x86_rva(self, x86_rva: int,
                                 rva_map: Dict[int, int]) -> Optional[int]:
        """Map an x86 .text RVA to the corresponding shim blob offset."""
        if not rva_map:
            return None
        if x86_rva in rva_map:
            return rva_map[x86_rva]
        fn_entries = self._fn_entry_rvas or set(rva_map.keys())
        candidates = [(rva_map[o], o) for o in fn_entries
                      if o <= x86_rva and o in rva_map]
        if not candidates:
            return None
        mapped_off, old_start = max(candidates, key=lambda x: x[1])
        return mapped_off + (x86_rva - old_start)

    def _locate_shim_entry_for_x86_fn(self, out: bytearray,
                                      x86_tgt_rva: int,
                                      rva_map: Optional[Dict[int, int]] = None) -> Optional[int]:
        """Fallback when rva_map points at the wrong blob cell for a small helper."""
        if not self.pe:
            return None
        sec = self.pe.section_for_rva(x86_tgt_rva)
        if not sec:
            return None
        x86_text = self.pe.get_section_data(sec)
        x86_off = x86_tgt_rva - sec['vaddr']
        if x86_off < 0 or x86_off + 4 > len(x86_text):
            return None
        head = x86_text[x86_off:x86_off + 4]
        if head == b'\x83\x7c\x24\x04':  # cmp dword ptr [esp+4], 0
            pos = 0
            while pos < len(out):
                j = out.find(b'\x48\x83\xf9\x00', pos)
                if j < 0:
                    break
                if self._is_wcsrchr_wrapper_entry(out, j):
                    return j
                pos = j + 1
        if (x86_off + 2 <= len(x86_text)
                and x86_text[x86_off:x86_off + 2] == b'\x56\x57'):  # push esi; push edi
            sig = b'\x57\x48\x8b\x7d\x10'
            hits: List[int] = []
            pos = 0
            while pos < len(out):
                j = out.find(sig, pos)
                if j < 0:
                    break
                ent = j
                for back in range(0, 40):
                    p = j - back
                    if p >= 0 and out[p:p + 3] == b'\x55\x48\x89':
                        ent = p
                        break
                win = out[j:j + 32]
                if b'\x66\x83\x3f' in win:
                    hits.append(ent)
                pos = j + 1
            if hits:
                if rva_map and x86_tgt_rva in rva_map:
                    hint = rva_map[x86_tgt_rva]
                    return min(hits, key=lambda h: abs(h - hint))
                return hits[0]
        return None

    def _build_compact_wide_stdout_write(self, cave_rva: int, wcslen_iat: int,
                                         getstd_iat: int, write_iat: int,
                                         use_console: bool = False) -> bytes:
        """Write wide string at RDX to stdout; clobbers caller-saved regs, returns 0."""
        nb = self.new_base
        s = bytearray()

        def pos() -> int:
            return cave_rva + len(s)

        def put(*parts: bytes) -> None:
            for part in parts:
                s.extend(part)

        def ff15(iat: int) -> None:
            at = pos()
            put(b'\xff\x15' + struct.pack('<i', iat - (nb + at + 6)))

        put(b'\x53', b'\x48\x89\xd3')              # push rbx; mov rbx, rdx
        put(b'\x48\x83\xec\x28', b'\x48\x89\xd9')  # sub rsp,28; mov rcx, rbx
        ff15(wcslen_iat)
        put(b'\x41\x89\xc0', b'\xb9\xf5\xff\xff\xff')  # mov r8d, eax (wchar count)
        ff15(getstd_iat)
        put(b'\x48\x89\xc1', b'\x48\x89\xda')      # mov rcx, rax; mov rdx, rbx
        if use_console:
            put(b'\x4c\x8d\x4c\x24\x20',
                b'\x48\xc7\x44\x24\x18\x00\x00\x00\x00')
        else:
            put(b'\x41\xd1\xe0', b'\x4c\x8d\x4c\x24\x30',  # shl r8d, 1 (bytes)
                b'\x48\xc7\x44\x24\x28\x00\x00\x00\x00')
        ff15(write_iat)
        put(b'\x48\x83\xc4\x28', b'\x5b', b'\x31\xc0', b'\xc3')
        return bytes(s)

    def _build_banner_print_write_stub(self, cave_rva: int, wcslen_iat: int,
                                       getstd_iat: int, write_iat: int,
                                       use_console: bool = False) -> bytes:
        """Write RDX (formatted buffer) or RCX via GetStdHandle + WriteConsoleW/WriteFile."""
        nb = self.new_base
        s = bytearray()

        def pos() -> int:
            return cave_rva + len(s)

        def put(*parts: bytes) -> None:
            for part in parts:
                s.extend(part)

        def ff15(iat: int) -> None:
            at = pos()
            put(b'\xff\x15' + struct.pack('<i', iat - (nb + at + 6)))

        put(b'\x4c\x8b\xc2', b'\x4d\x85\xc0', b'\x75\x03', b'\x4c\x8b\xc1')
        put(b'\x48\x83\xec\x28' + b'\x49\x8b\xc8')
        ff15(wcslen_iat)
        put(b'\x89\xc3', b'\xb9\xf5\xff\xff\xff')
        ff15(getstd_iat)
        put(b'\x48\x89\xc1', b'\x4c\x89\xc2')
        if use_console:
            put(b'\x41\x89\xd8', b'\x4c\x8d\x4c\x24\x20',
                b'\x48\xc7\x44\x24\x18\x00\x00\x00\x00')
        else:
            put(b'\x01\xdb', b'\x41\x89\xd8',
                b'\x4c\x8d\x4c\x24\x30', b'\x48\xc7\x44\x24\x28\x00\x00\x00\x00')
        ff15(write_iat)
        put(b'\x48\x83\xc4\x28' + b'\x31\xc0' + b'\xc3')
        return bytes(s)

    def _build_prompt_print_write_stub(self, cave_rva: int, prompt_rva: int,
                                       wcslen_iat: int, getstd_iat: int,
                                       write_iat: int, resume_rva: int) -> bytes:
        """Write wide prompt literal then jmp to ReadConsole helper."""
        nb = self.new_base
        s = bytearray()

        def pos() -> int:
            return cave_rva + len(s)

        def put(*parts: bytes) -> None:
            for part in parts:
                s.extend(part)

        def ff15(iat: int) -> None:
            at = pos()
            put(b'\xff\x15' + struct.pack('<i', iat - (nb + at + 6)))

        put(b'\x48\xb9' + struct.pack('<Q', nb + prompt_rva))
        put(b'\x48\x83\xec\x28' + b'\x48\x89\xc8')
        ff15(wcslen_iat)
        put(b'\x89\xc3', b'\xb9\xf5\xff\xff\xff')
        ff15(getstd_iat)
        put(b'\x48\x89\xc1', b'\x48\x89\xc8', b'\x41\x89\xd8',
            b'\x4c\x8d\x4c\x24\x20', b'\x48\xc7\x44\x24\x18\x00\x00\x00\x00')
        ff15(write_iat)
        put(b'\x48\x83\xc4\x28')
        if resume_rva:
            put(b'\xe9' + struct.pack('<i', resume_rva - (cave_rva + len(s) + 5)))
        return bytes(s)

    def _pe_va_for_old_rva(self, old_rva: int, rva_map: Optional[Dict[int, int]],
                           text_rva: int) -> int:
        """Best-effort map of an x86 code RVA to a PE64 VA in the output blob."""
        if rva_map:
            if old_rva in rva_map:
                return self.new_base + text_rva + rva_map[old_rva]
            candidates = [(off, rva) for rva, off in rva_map.items()
                          if off is not None and rva <= old_rva]
            if candidates:
                off, anchor = max(candidates, key=lambda x: x[1])
                return self.new_base + text_rva + off + (old_rva - anchor)
        return self.new_base + old_rva

    @staticmethod
    def _pe_rva_byte(pe_path: str, rva: int) -> Optional[int]:
        """Read one raw byte at PE RVA (None if unmapped). Uses raw section span."""
        chunk = MiscMixin._pe_rva_bytes(pe_path, rva, 1)
        return chunk[0] if chunk else None

    @staticmethod
    def _pe_rva_bytes(pe_path: str, rva: int, count: int) -> Optional[bytes]:
        """Read raw bytes at PE RVA (None if unmapped). Uses raw section span."""
        if count <= 0:
            return b''
        try:
            data = open(pe_path, 'rb').read()
        except OSError:
            return None
        pe = struct.unpack_from('<I', data, 0x3C)[0]
        opt_sz = struct.unpack_from('<H', data, pe + 20)[0]
        n = struct.unpack_from('<H', data, pe + 6)[0]
        sec = pe + 24 + opt_sz
        for i in range(n):
            o = sec + i * 40
            vs, va, rawsz, rawptr = struct.unpack_from('<IIII', data, o + 8)
            span = max(vs, rawsz)
            if va <= rva < va + span:
                off = rawptr + (rva - va)
                if off + count > len(data):
                    return None
                return data[off:off + count]
        return None

    @staticmethod
    def _eng_rva_bytes(eng: Any, rva: int, count: int) -> Optional[bytes]:
        """Read bytes at RVA from a loaded UBRT shift engine (post-mutation state)."""
        se = getattr(eng, 'shift_engine', None)
        if not se or count <= 0:
            return None
        off = se._rva_to_offset(rva)
        buf = getattr(se, 'buffer', None) or getattr(se, 'data', None)
        if off is None or buf is None or off + count > len(buf):
            return None
        return bytes(buf[off:off + count])

    @staticmethod
    def _rva_map_lookup(rva_map: Dict[int, int], rva: int) -> Optional[int]:
        """Map old RVA → new section offset (exact or floor of mapped insn)."""
        if rva in rva_map:
            return rva_map[rva]
        candidates = [(mapped, old) for old, mapped in rva_map.items() if old <= rva]
        if not candidates:
            return None
        return max(candidates, key=lambda x: x[1])[0]

    def _relocate_imm(self, imm32: int, code64_size: int = 0, data64_base: int = 0) -> int:
        """Map a Win2000 32-bit image VA to its Win64 equivalent."""
        imm32 &= 0xFFFFFFFF
        if (self.win10_test_shim and self._w2k_eh3_va
                and imm32 in self._seh_eh3_handler_old_vas):
            return self._w2k_eh3_va
        # Data / rsrc pointers must never go through code rva_map extrapolation
        # (would land in translated .text, e.g. push 0x22860 → main+0x1E860).
        if self.old_base <= imm32 < self.old_base + self.pe.image_size:
            old_rva = imm32 - self.old_base
            sec = self.pe.section_for_rva(old_rva)
            if sec and not (sec['flags'] & 0x20000000):
                if self._old_to_new_section:
                    return (self.new_base
                            + remap_section_rva(old_rva, self.pe,
                                                self._old_to_new_section))
                # Section layout not planned yet (still translating).  Keep the
                # original VA so ``_patch_abs_va_in_code`` can rewrite it once
                # ``_old_to_new_section`` exists.  ``new_base + old_rva`` would
                # land in the code-growth gap (cmd 0xB6B5 → 0x80020C00 AV/SO).
                return imm32
        if self._iat_rva_map or self._old_to_new_section or self._final_rva:
            return remap_image_va(imm32, self.pe, self.old_base, self.new_base,
                                  self._old_to_new_section, self._iat_rva_map,
                                  self._final_rva)
        old_base = self.old_base
        img_end  = old_base + self.pe.image_size
        if old_base <= imm32 < img_end:
            return self.new_base + (imm32 - old_base)
        if imm32 in self.dyn.pointer_values:
            return self.new_base + (imm32 - old_base)
        return imm32

    @staticmethod
    def _ptr_w64(reg_id: int) -> str:
        return W32_TO_W64_REG.get(reg_id, 'rax')

    @staticmethod
    def _ptr_taint_mark(ptr_taint: Set[str], reg_id: int) -> None:
        ptr_taint.add(W32_TO_W64_REG.get(reg_id, 'rax'))

    @staticmethod
    def _ptr_taint_clear(ptr_taint: Set[str], reg_id: int) -> None:
        ptr_taint.discard(W32_TO_W64_REG.get(reg_id, 'rax'))

    @staticmethod
    def _ptr_taint_propagate(ptr_taint: Set[str], dst_id: int, src_id: int) -> None:
        dst = W32_TO_W64_REG.get(dst_id, 'rax')
        src = W32_TO_W64_REG.get(src_id, 'rax')
        if src in ptr_taint:
            ptr_taint.add(dst)
        else:
            ptr_taint.discard(dst)

    @staticmethod
    def _teb_ptr_mark(teb_ptr_regs: Set[str], reg_id: int) -> None:
        teb_ptr_regs.add(W32_TO_W64_REG.get(reg_id, 'rax'))

    @staticmethod
    def _teb_ptr_clear(teb_ptr_regs: Set[str], reg_id: int) -> None:
        teb_ptr_regs.discard(W32_TO_W64_REG.get(reg_id, 'rax'))

    @staticmethod
    def _teb_ptr_propagate(teb_ptr_regs: Set[str], dst_id: int, src_id: int) -> None:
        dst = W32_TO_W64_REG.get(dst_id, 'rax')
        src = W32_TO_W64_REG.get(src_id, 'rax')
        if src in teb_ptr_regs:
            teb_ptr_regs.add(dst)
        else:
            teb_ptr_regs.discard(dst)

    @staticmethod
    def _teb_indirect_field_size(gs_disp: int) -> str:
        """x64 TEB pointer fields are QWORD; small metadata stays dword."""
        if gs_disp in (0x08, 0x10, 0x30, 0x60):
            return 'qword'
        return 'dword'

    @staticmethod
    def _reg_asm_for_op(op, op_str: str = '') -> str:
        """Keystone register name sized for the operand (al not eax for byte ops)."""
        if not HAS_CAPSTONE or op.type != X86_OP_REG:
            return 'eax'
        sz = getattr(op, 'size', 4) or 4
        if sz == 1:
            if op.reg in W32_BYTE_REG_ASM:
                return W32_BYTE_REG_ASM[op.reg]
            if op.reg in W32_TO_BYTE_REG:
                return W32_TO_BYTE_REG[op.reg]
        if op_str and ',' in op_str:
            tail = op_str.rsplit(',', 1)[-1].strip()
            if tail and tail[0] in 'abcdrs' and 'ptr' not in tail:
                return tail
        return W32_REG_ASM.get(op.reg, 'eax')

    @staticmethod
    def _mem_ptr_size(op_str: str) -> str:
        """Return 'byte'/'word'/'dword'/'qword' from a Capstone op_str."""
        s = op_str.lower()
        for sz in ('byte', 'dword', 'qword', 'word'):
            if f'{sz} ptr' in s:
                return sz
        return 'dword'

    def _word_reg_asm_for_op(self, op, op_str: str = '') -> str:
        if HAS_CAPSTONE and op.type == X86_OP_REG:
            if op.reg in W32_WORD_REG_ASM:
                return W32_WORD_REG_ASM[op.reg]
        r = self._reg_asm_for_op(op, op_str)
        return {'eax': 'ax', 'ecx': 'cx', 'edx': 'dx', 'ebx': 'bx',
                'esi': 'si', 'edi': 'di', 'ebp': 'bp', 'esp': 'sp'}.get(r, r)

    @staticmethod
    def _lookahead_matching_pop(reg_id: int, insn_idx: int, insns) -> bool:
        """push reg … pop reg save/restore (may include calls in between)."""
        for j in range(insn_idx + 1, len(insns)):
            nx = insns[j]
            nm = nx.mnemonic
            if nm in ('ret', 'retn'):
                break
            if nm == 'pop' and nx.operands and nx.operands[0].type == X86_OP_REG:
                if nx.operands[0].reg == reg_id:
                    return True
                continue
            if nm == 'mov' and len(nx.operands) == 2:
                if (nx.operands[0].type == X86_OP_REG
                        and nx.operands[0].reg == reg_id
                        and nx.operands[1].type == X86_OP_REG):
                    continue
        return False

    @staticmethod
    def _msvc_push_imm_pop_ecx_idiom(insn_idx: int, insns) -> bool:
        """push imm; xor eax,eax; pop ecx — 32-bit stack reservation after callee-save."""
        if insn_idx + 3 >= len(insns):
            return False
        n1, n2, n3 = insns[insn_idx + 1:insn_idx + 4]
        if n1.mnemonic != 'push' or not n1.operands:
            return False
        if n1.operands[0].type != X86_OP_IMM:
            return False
        if n2.mnemonic != 'xor' or len(n2.operands) != 2:
            return False
        if (n2.operands[0].type != X86_OP_REG
                or n2.operands[0].reg != X86_REG_EAX):
            return False
        if n3.mnemonic != 'pop' or not n3.operands:
            return False
        return (n3.operands[0].type == X86_OP_REG
                and n3.operands[0].reg == X86_REG_ECX)

    def _imm_is_pe64_idata_cell(self, imm: int) -> bool:
        """True when ``imm`` is a VA inside the merged PE64 .idata thunk table."""
        imm &= 0xFFFFFFFFFFFFFFFF
        if not (self.new_base <= imm < self.new_base + 0x200000):
            return False
        cell_rva = imm - self.new_base
        idata_rva = getattr(self, '_idata_rva', 0)
        idata = getattr(self, '_idata_blob', b'')
        if idata_rva and idata and idata_rva <= cell_rva < idata_rva + len(idata):
            return True
        if self._iat_rva_map and cell_rva in self._iat_rva_map.values():
            return True
        return False

    def _relocate_stale_linear_image_va(self, imm: int) -> int:
        """Fix linear ``new_base+old_rva`` that now lands inside inflated PE64 .text
        or in a data section that was shifted by the overlap guard.

        After translation the .text section is much larger than the x86 image, so
        unpatch movabs like ``0x80044c58`` (old .rsrc) read code bytes.  Already
        section-remapped VAs (e.g. new .data at ``0x45008``) sit past the .text
        tail and must not be touched — UNLESS a section-shift moved them further.
        """
        imm &= 0xFFFFFFFFFFFFFFFF
        new_lo = self.new_base
        if not (new_lo <= imm < new_lo + self.pe.image_size):
            return imm
        old_rva = imm - self.new_base
        # ── Section-shift guard: if data sections were moved, add shift ──
        shift_amt = getattr(self, '_section_shift_amount', 0)
        shift_lo = getattr(self, '_section_shift_base', 0xFFFFFFFF)
        if shift_amt and old_rva >= shift_lo:
            # Check that this isn't ALREADY a post-shift address
            # (post-shift RVAs are >= shift_lo + shift_amt for moved sections)
            if old_rva < shift_lo + shift_amt:
                return imm + shift_amt
        # ── Original logic: handle addresses that fell inside .text ──
        text_old = self.text_rva or 0x1000
        text_new = self._old_to_new_section.get(text_old, text_old)
        text_blob = self._translated_text or b''
        text_end = text_new + len(text_blob)
        if old_rva >= text_end:
            return imm
        sec = self.pe.section_for_rva(old_rva)
        if not sec or (sec['flags'] & 0x20000000):
            return imm
        sec_lo = sec['vaddr']
        sec_hi = sec_lo + max(sec['vsize'], sec['raw_sz'], 1)
        if not (sec_lo <= old_rva < sec_hi):
            return imm
        if not self._old_to_new_section:
            return imm
        new_rva = remap_section_rva(old_rva, self.pe, self._old_to_new_section)
        new_imm = self.new_base + new_rva
        return new_imm if new_imm != imm else imm

    def _patch_abs_va_in_code(self, code: bytes,
                              relocate_new_base: bool = True) -> Tuple[bytes, int]:
        """Patch movabs/call immediates that still point at old IAT / section RVAs.

        ``relocate_new_base`` controls whether immediates already rebased into the
        PE64 image range (``new_base``) are fed through section remapping.  The
        first pass over freshly-translated code must do this: emit time runs
        before ``_old_to_new_section`` is populated, so image pointers leave the
        translator merely rebased (``new_base + old_rva``) and need exactly one
        section remap here.  Any *later* pass must set this False — by then the
        new-base immediates are fully finalized PE64 VAs, and remapping them again
        double-applies the section delta whenever a relocated .data RVA collides
        with the old .rsrc/.data VA range (universal Win2000 hazard, e.g. cmd.exe
        locale table movabs 0x1d480 -> 0x44480 -> 0x6b480 landing in read-only
        .rsrc and faulting on ``rep stosd``).
        """
        out = bytearray(code)
        patched = 0
        i = 0
        new_lo = self.new_base
        new_hi = self.new_base + self.pe.image_size
        while i < len(out) - 10:
            if out[i] in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= out[i + 1] <= 0xBF:
                imm = struct.unpack_from('<Q', out, i + 2)[0]
                if not relocate_new_base and (new_lo <= imm < new_hi):
                    # Late passes: still fix stale ``new_base+old_rva`` slots that
                    # cmd post-fixups inserted after the first remap pass.
                    stale = self._relocate_stale_linear_image_va(imm)
                    if stale == imm:
                        i += 10
                        continue
                    struct.pack_into('<Q', out, i + 2, stale)
                    patched += 1
                    i += 10
                    continue
                new_imm = remap_image_va(
                    imm, self.pe, self.old_base, self.new_base,
                    self._old_to_new_section, self._iat_rva_map,
                    self._final_rva)
                # Prefer x86-side data/rsrc section remap (linear pre-patch VAs).
                if (self.old_base <= imm < self.old_base + self.pe.image_size):
                    cand = self._relocate_imm(imm & 0xFFFFFFFF, 0, 0)
                    if cand != imm:
                        new_imm = cand
                stale = self._relocate_stale_linear_image_va(new_imm)
                if stale != new_imm:
                    new_imm = stale
                if new_imm != imm:
                    struct.pack_into('<Q', out, i + 2, new_imm)
                    patched += 1
                i += 10
                continue
            i += 1
        return bytes(out), patched

    def _patch_disp32_image_vas_in_code(self, code: bytes) -> Tuple[bytes, int]:
        """Patch disp32 / DWORD slots that still embed x86 image VAs in x64 code.

        ``mov word ptr [edi+0x4AD1D060], imm`` and similar [reg+disp32] forms fall
        through the Keystone default path with the old base; movabs patching does
        not catch them.
        """
        out = bytearray(code)
        protected = bytearray(len(out))
        i = 0
        while i < len(out) - 9:
            if out[i] in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= out[i + 1] <= 0xBF:
                for j in range(i + 2, min(i + 10, len(out))):
                    protected[j] = 1
                i += 10
                continue
            i += 1
        i = 0
        while i < len(out) - 4:
            if out[i] in (0xE8, 0xE9):
                for j in range(i + 1, min(i + 5, len(out))):
                    protected[j] = 1
                i += 5
                continue
            if out[i] == 0x0F and i + 5 < len(out) and 0x80 <= out[i + 1] <= 0x8F:
                for j in range(i + 2, i + 6):
                    if j < len(out):
                        protected[j] = 1
                i += 6
                continue
            i += 1
        old_lo = self.old_base
        old_hi = self.old_base + self.pe.image_size
        patched = 0
        for off in range(len(out) - 3):
            if protected[off]:
                continue
            val = struct.unpack_from('<I', out, off)[0]
            if not (old_lo <= val < old_hi):
                continue
            # disp32 for [reg+disp] uses mod=10 (0x80..0xbf modrm) with the disp
            # in the following four bytes. Skip arbitrary DWORDs inside insns.
            if off < 1:
                continue
            modrm = out[off - 1]
            if (modrm & 0xC0) != 0x80:
                continue
            new_val = self._relocate_imm(val) & 0xFFFFFFFF
            if new_val != val and new_val < 0x80000000:
                struct.pack_into('<I', out, off, new_val)
                patched += 1
        return bytes(out), patched

    def _rewrite_imm32_image_va(self, val: int) -> int:
        """Map old-base or stale linear ``new_base+old_rva`` imm32 → section VA.

        Movabs patching rewrites qword slots; C7/81/B8 leave the pointer in a
        trailing imm32.  Emit / early heals can bake ``0x8001FBE2`` (linear
        remap of ``.data`` ``0x1FBE2``) into ``mov dword [rax], imm`` — that is
        past ``old_base`` so the old-VA-only path never touches it, and the
        cursor reset at cmd ``0xBC7D`` then poisons ``[fbc8]`` at runtime.
        """
        val &= 0xFFFFFFFF
        old_lo = self.old_base
        old_hi = self.old_base + self.pe.image_size
        if old_lo <= val < old_hi:
            return self._relocate_imm(val) & 0xFFFFFFFF
        new_lo = self.new_base
        new_hi = self.new_base + self.pe.image_size
        if new_lo <= val < new_hi:
            return self._relocate_stale_linear_image_va(val) & 0xFFFFFFFF
        return val

    def _patch_mov_rm_imm32_image_vas(self, code: bytes) -> Tuple[bytes, int]:
        """Patch ``mov r/m32|64, imm32`` (C7 /0) that still embed x86 image VAs.

        Emit-time ``_relocate_imm`` defers non-exec section remaps until
        ``_old_to_new_section`` exists, leaving old VAs in forms like
        ``mov dword ptr [rbp-0x38], 0x4AD20C00``.  Disp32 patching only
        catches ``[reg+disp32]`` slots, not the trailing C7 immediate.
        Also repairs stale linear ``new_base+old_rva`` imms (see
        ``_rewrite_imm32_image_va``).
        """
        out = bytearray(code)
        patched = 0
        i = 0
        n = len(out)
        while i < n - 6:
            op_i = i
            if 0x40 <= out[i] <= 0x4F:
                op_i = i + 1
                if op_i >= n:
                    break
            if out[op_i] != 0xC7:
                i += 1
                continue
            if op_i + 1 >= n:
                break
            modrm = out[op_i + 1]
            if (modrm & 0x38) != 0:  # not /0
                i += 1
                continue
            mod = modrm >> 6
            rm = modrm & 7
            pos = op_i + 2
            if mod != 3 and rm == 4:
                if pos >= n:
                    break
                sib = out[pos]
                pos += 1
                if mod == 0 and (sib & 7) == 5:
                    pos += 4
            if mod == 1:
                pos += 1
            elif mod == 2 or (mod == 0 and rm == 5):
                pos += 4
            if pos + 4 > n:
                i += 1
                continue
            val = struct.unpack_from('<I', out, pos)[0]
            new_val = self._rewrite_imm32_image_va(val)
            if new_val != val:
                # Register-dest form (mod=11) is Keystone's sign-extending
                # ``mov r64, imm32``.  Writing a bit-31 VA into that slot
                # makes the CPU sign-extend to 0xFFFFFFFF8xxxxxxx.  Leave
                # those for movabs emit + ``_patch_abs_va_in_code``.
                if mod == 3 and new_val > 0x7FFFFFFF:
                    i = pos + 4
                    continue
                struct.pack_into('<I', out, pos, new_val)
                patched += 1
            i = pos + 4
        return bytes(out), patched

    def _patch_alu_imm32_image_vas(self, code: bytes) -> Tuple[bytes, int]:
        """Patch ``add/sub/cmp/... r/m32, imm32`` (81 /r) that embed x86 image VAs.

        Forms like ``add rdi, 0x4AD1D480`` (table-base absolute) and
        ``cmp dword [r11], 0x4AD1FBE0`` (cmd 0xB1D2 cursor vs buffer-base)
        survive emit as unrebased immediates; C7/movabs patchers do not
        touch opcode 81.  Memory destinations must be patched too — the
        register-only path left ``cmp [fbc8], 0x4ad1fbe0`` live, so the
        unget helper always subtracted 2 from the cursor.
        """
        out = bytearray(code)
        patched = 0
        i = 0
        n = len(out)
        while i < n - 6:
            op_i = i
            if 0x40 <= out[i] <= 0x4F:
                op_i = i + 1
                if op_i >= n:
                    break
            if out[op_i] != 0x81:
                i += 1
                continue
            if op_i + 1 >= n:
                break
            modrm = out[op_i + 1]
            mod = modrm >> 6
            rm = modrm & 7
            pos = op_i + 2
            if mod != 3 and rm == 4:
                if pos >= n:
                    break
                sib = out[pos]
                pos += 1
                if mod == 0 and (sib & 7) == 5:
                    pos += 4
            if mod == 1:
                pos += 1
            elif mod == 2 or (mod == 0 and rm == 5):
                pos += 4
            if pos + 4 > n:
                i += 1
                continue
            val = struct.unpack_from('<I', out, pos)[0]
            new_val = self._rewrite_imm32_image_va(val)
            if new_val != val:
                # Opcode 81 into a *register* sign-extends imm32 into r64.
                # Remapped VAs with bit 31 set become 0xFFFFFFFF8xxxxxxx —
                # leave those for emit-time ``_emit_add_imm64`` (movabs+add).
                # Memory dword forms compare/add the imm32 as-is (no sext).
                if mod == 3 and new_val > 0x7FFFFFFF:
                    i = pos + 4
                    continue
                struct.pack_into('<I', out, pos, new_val)
                patched += 1
            i = pos + 4
        return bytes(out), patched

    def _patch_mov_reg32_imm32_image_vas(self, code: bytes) -> Tuple[bytes, int]:
        """Patch ``mov r32, imm32`` (B8+r) that still embed x86 image VAs.

        REX.W movabs forms are owned by ``_patch_abs_va_in_code``.  Plain
        ``mov eax, 0x4AD1…`` (cmd 0x1EF4 locale slot) survives when emit kept
        the 5-byte encoding; rewrite the imm in place (remapped VAs fit in
        low 32 bits under our PE64 image base).  Also repairs stale linear
        ``new_base+old_rva`` imms.
        """
        out = bytearray(code)
        patched = 0
        i = 0
        n = len(out)
        while i < n - 5:
            if 0xB8 <= out[i] <= 0xBF:
                if i > 0 and 0x40 <= out[i - 1] <= 0x4F:
                    i += 1
                    continue
                val = struct.unpack_from('<I', out, i + 1)[0]
                new_val = self._rewrite_imm32_image_va(val)
                if new_val != val:
                    struct.pack_into('<I', out, i + 1, new_val)
                    patched += 1
                i += 5
                continue
            i += 1
        return bytes(out), patched

    def _code_rva_to_pe64_va(self, va: int) -> int:
        """Map any x86 code VA (incl. mid-function) to its PE64 image VA."""
        va &= 0xFFFFFFFF
        img_end = self.old_base + self.pe.image_size
        if not (self.old_base <= va < img_end):
            return va
        old_rva = va - self.old_base
        sec = self.pe.section_for_rva(old_rva)
        if sec and not (sec['flags'] & 0x20000000):
            if self._old_to_new_section:
                return (self.new_base
                        + remap_section_rva(old_rva, self.pe,
                                            self._old_to_new_section))
            return self.new_base + old_rva
        if self._final_rva and old_rva in self._final_rva:
            return self.new_base + self._final_rva[old_rva]
        if self._iat_rva_map and old_rva in self._iat_rva_map:
            return self.new_base + self._iat_rva_map[old_rva]
        if self.rva_map:
            candidates = [(off, old) for old, off in self.rva_map.items() if old <= old_rva]
            if candidates:
                mapped_off, old_start = max(candidates, key=lambda x: x[1])
                old_sec = self._rva_section.get(old_start, self.text_rva)
                new_sec = self._old_to_new_section.get(old_sec, old_sec)
                return self.new_base + new_sec + mapped_off + (old_rva - old_start)
        return self.new_base + old_rva

    def _fn_blob_off_from_push(self, out: bytearray, push_off: int) -> int:
        """Blob offset of the x64 prologue for an SEH ``push -1; mov rax, scope`` site."""
        for back in range(0, 48):
            pos = push_off - back
            if pos >= 0 and pos + 4 <= len(out) and out[pos:pos + 4] == b'\x55\x48\x89\xe5':
                return pos
        return push_off

    def _patch_dword_vas_in_orphan_blobs(self, code: bytes) -> Tuple[bytes, int]:
        """Patch DWORD image VAs inside copied SEH/rodata blobs."""
        if not self._orphan_blob_out_ranges:
            return code, 0
        out = bytearray(code)
        patched = 0
        text = self.pe.sections[0]
        code_lo = self.old_base + text['vaddr']
        code_hi = code_lo + text.get('vsize', 0)
        if self._orphan_blob_out_ranges:
            tail = min(s for s, _ in self._orphan_blob_out_ranges)
            for off in range(tail, len(out) - 19):
                if not self._valid_scope_sentinel(out, off):
                    continue
                if not any(s <= off < s + sz
                           for s, sz in self._scope_table_out_ranges):
                    self._scope_table_out_ranges.append((off, 64))
        for start, size in self._orphan_blob_out_ranges:
            if start + 4 <= len(out) and out[start:start + 4] == b'\xff\xff\xff\xff':
                continue
            if self._orphan_byte_protected(start):
                continue
            end = min(start + size, len(out) - 3)
            for off in range(start, end, 4):
                if self._orphan_byte_protected(off):
                    continue
                val = struct.unpack_from('<I', out, off)[0]
                if (self.win10_test_shim and self._w2k_eh3_va
                        and val in self._seh_eh3_handler_old_vas):
                    new_val = self._w2k_eh3_va & 0xFFFFFFFF
                elif code_lo <= val < code_hi:
                    new_val = self._code_rva_to_pe64_va(val)
                else:
                    new_val = remap_image_va(
                        val, self.pe, self.old_base, self.new_base,
                        self._old_to_new_section, self._iat_rva_map,
                        self._final_rva)
                if new_val != val:
                    struct.pack_into('<I', out, off, new_val & 0xFFFFFFFF)
                    patched += 1
        for start, size in self._scope_table_out_ranges:
            patched += self._patch_scope_table_entries(out, start, size)
        if self._orphan_blob_out_ranges:
            tail = min(s for s, _ in self._orphan_blob_out_ranges)
            for off in range(tail, len(out) - 19):
                if not self._valid_scope_sentinel(out, off):
                    continue
                patched += self._patch_scope_table_entries(out, off, 64)
        return bytes(out), patched

    def _runtime_stub_end_rva(self, text_data: bytes, text_rva: int,
                              stub_rva: int) -> int:
        """End RVA of a tiny CRT tail helper ending in `jmp eax` (not tail ff25)."""
        sec = self.pe.section_for_rva(stub_rva)
        if not sec:
            return stub_rva + 0x20
        data = self.pe.get_section_data(sec)
        off = stub_rva - sec['vaddr']
        if off < 0:
            return stub_rva + 0x20
        limit = min(len(data), off + 0x40)
        for i in range(off, limit - 1):
            if data[i] == 0xFF and data[i + 1] == 0xE0:
                return stub_rva + (i - off) + 2
            if data[i] == 0xFF and data[i + 1] == 0x25:
                return stub_rva + (i - off)
        return stub_rva + 0x20

    def _orphan_byte_protected(self, pos: int) -> bool:
        for start, size in self._scope_table_out_ranges:
            if start <= pos < start + size:
                return True
        for start, end in self._code_span_ranges:
            if start <= pos < end:
                return True
        if self.rva_map:
            off = self.rva_map.get(getattr(self, '_pe_entry_old_rva', 0))
            if off is not None and off <= pos < off + 512:
                return True
        return False

    @staticmethod
    def _merge_embedded_ref_spans(refs: Set[int], text_data: bytes,
                                  text_rva: int) -> List[Tuple[int, int]]:
        spans: List[Tuple[int, int]] = []
        for r in sorted(refs):
            off = r - text_rva
            if off < 0 or off >= len(text_data):
                continue
            sz = _embedded_text_blob_size(text_data, off)
            spans.append((r, r + sz))
        if not spans:
            return []
        merged: List[Tuple[int, int]] = []
        for start, end in spans:
            if merged and start <= merged[-1][1] + _EMBEDDED_SPAN_MERGE_GAP:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def _build_epilogue_head_snap_map(self, rva_map: Dict[int, int],
                                       out: bytearray) -> Dict[int, int]:
        """Map any PE64 offset inside a pop/ret tail to the first pop of that tail."""
        cf = self._x86_cf
        if not cf or not cf.epilogue_labels:
            return {}
        by_tail: Dict[int, List[Tuple[int, int]]] = {}
        for ep_rva, ep_bytes in cf.epilogue_labels.items():
            if not ep_bytes:
                continue
            # rva_map is x86 RVA → blob offset into *out*.
            head = rva_map.get(ep_rva)
            if head is None and out:
                head = out.find(ep_bytes)
            if head is None or head < 0:
                continue
            by_tail.setdefault(head + len(ep_bytes) - 1, []).append(
                (head, head + len(ep_bytes)))
        snap: Dict[int, int] = {}
        for _tail, spans in by_tail.items():
            canon = min(h for h, _ in spans)
            end = max(e for _, e in spans)
            for pos in range(canon, end):
                snap[pos] = canon
        return snap

    def _abs_mem_disp_to_rva(self, disp: int) -> int:
        """PE32 absolute [disp32] → image RVA."""
        if disp >= self.old_base:
            return (disp - self.old_base) & 0xFFFFFFFF
        return disp & 0xFFFFFFFF

    def _x86_xor_eax_jmp_target(self, text_data: bytes, text_rva: int,
                                  target_rva: int) -> Optional[int]:
        """If *target_rva* is ``xor eax,eax; jmp X``, return x86 RVA of X."""
        off = target_rva - text_rva
        if off < 0 or off + 3 > len(text_data):
            return None
        b0, b1 = text_data[off], text_data[off + 1]
        if not ((b0 == 0x33 and b1 == 0xC0) or (b0 == 0x31 and b1 == 0xC0)):
            return None
        j = text_data[off + 2]
        if j == 0xEB and off + 4 <= len(text_data):
            rel = struct.unpack('<b', text_data[off + 3:off + 4])[0]
            return (target_rva + 4 + rel) & 0xFFFFFFFF
        if j == 0xE9 and off + 7 <= len(text_data):
            rel = struct.unpack('<i', text_data[off + 3:off + 7])[0]
            return (target_rva + 7 + rel) & 0xFFFFFFFF
        return None

    def _x86_is_xor_eax_jmp_epilogue(self, text_data: bytes, text_rva: int,
                                      target_rva: int) -> bool:
        """True when *target_rva* is MSVC ``xor eax,eax; jmp shared_epilogue``."""
        return self._x86_xor_eax_jmp_target(text_data, text_rva, target_rva) is not None

    def _find_xor_jmp_to_epilogue(self, out: bytearray, epi_off: int,
                                   prefer_near: Optional[int] = None) -> Optional[int]:
        """Locate ``xor eax/rax,eax; jmp`` whose rel32 lands on *epi_off* (or ±16)."""
        hits: List[int] = []
        for i in range(len(out) - 7):
            if out[i] == 0x48 and out[i + 1] == 0x31 and out[i + 2] == 0xC0:
                j = i + 3
            elif out[i] in (0x31, 0x33) and out[i + 1] == 0xC0:
                j = i + 2
            else:
                continue
            if j + 5 > len(out) or out[j] != 0xE9:
                continue
            rel = struct.unpack_from('<i', out, j + 1)[0]
            tgt = j + 5 + rel
            if abs(tgt - epi_off) <= 16:
                hits.append(i)
        if not hits:
            return None
        if prefer_near is not None:
            return min(hits, key=lambda h: abs(h - prefer_near))
        return hits[0]

    def _find_xor_eax_jmp_blob(self, out: bytearray,
                               prefer_near: Optional[int] = None) -> Optional[int]:
        """Locate translated ``xor eax/rax,eax; jmp rel32`` (return-0 + shared epi)."""
        hits: List[int] = []
        for i in range(len(out) - 7):
            if out[i] == 0x48 and out[i + 1] == 0x31 and out[i + 2] == 0xC0:
                j = i + 3
            elif out[i] in (0x31, 0x33) and out[i + 1] == 0xC0:
                j = i + 2
            else:
                continue
            if j + 5 <= len(out) and out[j] == 0xE9:
                hits.append(i)
        if not hits:
            return None
        if prefer_near is not None:
            return min(hits, key=lambda h: abs(h - prefer_near))
        return hits[0]

    def _resolve_jcc_target_off(self, out: bytearray, target_rva: int,
                                rva_map: Dict[int, int]) -> Optional[int]:
        """Map a Jcc destination RVA to a shim offset.

        Unlike CALL targets, Jcc destinations are frequently mid-function
        labels (``je`` to a shared cleanup block).  Those slots fail the
        prologue-quality gate used by ``_resolve_call_target_off``, which
        left ``0F 00 00 00 00 00`` placeholders unpatched (cmd 0xB719→0xB9C3).
        Trust ``rva_map`` for any in-range hit, then fall back to the call
        resolver for epilogue-label materialization.
        """
        # Prefer a freshly materialized stdcall/MSVC epilogue when the label
        # is known — avoids scrambled remnants (cmd 0x24DF → 0x2491).
        if self._x86_cf and target_rva in self._x86_cf.epilogue_labels:
            ep = self._materialize_epilogue_label(out, rva_map, target_rva)
            if ep is not None:
                return ep
        text_data = getattr(self, '_pure_heal_text', None)
        text_rva = getattr(self, '_pure_heal_text_rva', 0)
        jmp_epi = None
        if text_data is not None:
            jmp_epi = self._x86_xor_eax_jmp_target(text_data, text_rva, target_rva)
        if jmp_epi is not None:
            # Resolve the shared epilogue first, then the xor blob that jumps to it.
            epi_off = None
            if self._x86_cf and jmp_epi in self._x86_cf.epilogue_labels:
                epi_off = self._materialize_epilogue_label(out, rva_map, jmp_epi)
            if epi_off is None:
                epi_off = self._resolve_call_target_off(out, jmp_epi, rva_map)
            if epi_off is not None:
                # Prefer pop-edi head of the shared epilogue.
                if out[epi_off] not in (0x5F, 0x5E, 0x5B, 0x5D, 0xC9):
                    for d in range(0, 24):
                        if epi_off + d < len(out) and out[epi_off + d] == 0x5F:
                            epi_off = epi_off + d
                            break
                found = self._find_xor_jmp_to_epilogue(
                    out, epi_off, prefer_near=rva_map.get(target_rva))
                if found is not None:
                    rva_map[target_rva] = found
                    return found
                # Materialize: xor eax,eax; jmp epi
                base = len(out)
                out += b'\x48\x31\xc0\xe9\x00\x00\x00\x00'
                struct.pack_into('<i', out, base + 4, epi_off - (base + 8))
                out += b'\x90' * ((4 - len(out) % 4) % 4)
                rva_map[target_rva] = base
                self._note_code_span(base, 8)
                return base
        # Mid-function labels are often ``call callee`` (cmd ``f81b`` →
        # ``call 10005``).  Prefer the callee body / call-site mapping over
        # the prologue gate that leaves ``0F 00…`` placeholders.
        if text_data is not None:
            toff = target_rva - text_rva
            if (0 <= toff and toff + 5 <= len(text_data)
                    and text_data[toff] == 0xE8):
                rel_c = struct.unpack_from('<i', text_data, toff + 1)[0]
                callee = (target_rva + 5 + rel_c) & 0xFFFFFFFF
                for cand_rva in (callee, target_rva):
                    ct = rva_map.get(cand_rva)
                    if ct is not None and 0 <= ct < len(out) and out[ct] not in (0x00, 0xCC):
                        refined = self._refine_shim_target_off(out, cand_rva, ct)
                        if refined is not None and 0 <= refined < len(out):
                            if out[refined] not in (0x00, 0xCC):
                                return refined
                        return ct
                got = self._resolve_call_target_off(out, callee, rva_map)
                if got is not None:
                    return got
        tgt = rva_map.get(target_rva)
        if tgt is not None and 0 <= tgt < len(out):
            refined = self._refine_shim_target_off(out, target_rva, tgt)
            if refined is not None and 0 <= refined < len(out):
                if out[refined] not in (0x00, 0xCC):
                    return refined
            if out[tgt] not in (0x00, 0xCC):
                return tgt
        return self._resolve_call_target_off(out, target_rva, rva_map)

    def _resolve_deferred_branches(self, out: bytearray,
                                   rva_map: Dict[int, int],
                                   deferred: List[Tuple[int, int, str]]) -> int:
        """Second pass: patch CALL/JMP placeholders that target other functions."""
        JCC_MAP = {
            'jcc_jo': 0x80, 'jcc_jno': 0x81, 'jcc_jb': 0x82, 'jcc_jnb': 0x83,
            'jcc_jz': 0x84, 'jcc_jnz': 0x85, 'jcc_jbe': 0x86, 'jcc_ja': 0x87,
            'jcc_js': 0x88, 'jcc_jns': 0x89, 'jcc_jp': 0x8A, 'jcc_jnp': 0x8B,
            'jcc_jl': 0x8C, 'jcc_jge': 0x8D, 'jcc_jle': 0x8E, 'jcc_jg': 0x8F,
            'jcc_je': 0x84, 'jcc_jne': 0x85, 'jcc_jae': 0x83,
            'jcc_jnle': 0x8F, 'jcc_jng': 0x8E,
        }
        _dbg_res = os.environ.get('DEBUG_RESOLVE')
        _dbg_res_rva = int(_dbg_res, 16) if _dbg_res else None
        fixed = 0
        for patch_off, target_rva, ftype in deferred:
            if ftype.startswith('jcc_'):
                tgt = self._resolve_jcc_target_off(out, target_rva, rva_map)
            elif self._cmd_no_hacks:
                tgt = self._resolve_call_target_off(out, target_rva, rva_map)
            else:
                tgt = rva_map.get(target_rva)
            if _dbg_res_rva is not None and target_rva == _dbg_res_rva:
                print(f"[RESOLVE deferred] tgt_rva=0x{target_rva:X} "
                      f"resolved=0x{tgt:X} patch_off=0x{patch_off:X} ftype={ftype}"
                      if tgt is not None else
                      f"[RESOLVE deferred] tgt_rva=0x{target_rva:X} UNRESOLVED "
                      f"patch_off=0x{patch_off:X}")
            if tgt is None:
                continue
            # Anti-self-call: if the resolved target is the prologue of the
            # align wrapper that CONTAINS this call site, the snap created a
            # self-call.  Re-resolve using the raw rva_map (without snap).
            # patch_off points at the rel32 bytes (E8 at patch_off-1), so
            # the wrapper prologue starts 14 bytes before it.
            if ftype == 'rel32_call' and patch_off >= 14:
                pro_at = patch_off - 14
                if (pro_at + 13 <= len(out)
                        and out[pro_at:pro_at + 5] == self._ALIGN_HEAD
                        and tgt == pro_at):
                    # Self-call detected — use raw rva_map target
                    raw_tgt = rva_map.get(target_rva)
                    if raw_tgt is not None and raw_tgt != tgt:
                        tgt = raw_tgt
            if ftype in ('rel32_call', 'rel32_jmp'):
                after = patch_off + 4
                rel = tgt - after
                struct.pack_into('<i', out, patch_off, rel)
                fixed += 1
            elif ftype.startswith('jcc_'):
                if patch_off + 6 > len(out) or out[patch_off] != 0x0F:
                    continue
                cc_byte = JCC_MAP.get(ftype, 0x84)
                out[patch_off + 1] = cc_byte
                after = patch_off + 6
                rel = tgt - after
                struct.pack_into('<i', out, patch_off + 2, rel)
                fixed += 1
        return fixed

    def _pure_patch_jcc_placeholders(self, out: bytearray,
                                     rva_map: Dict[int, int],
                                     text_data: bytes, text_rva: int) -> int:
        """Fill leftover ``0F 00 00 00 00 00`` Jcc placeholders from x86 source.

        Deferred resolve can miss mid-function labels; later heals can also
        emit fresh placeholders.  Walk every x86 ``jcc``, locate the nearest
        placeholder forward of its rva_map slot, and patch condition + rel32.

        rva_map tips often sit on the preceding ``cmp``/``test`` rather than
        the Jcc itself — scan forward a few bytes for the real branch.  Also
        drive an x86-centric pass so sites whose tip lands slightly past the
        placeholder still get claimed.
        """
        if not self._cmd_no_hacks or not HAS_CAPSTONE or not text_data:
            return 0
        JCC_CC = {
            'jo': 0x80, 'jno': 0x81, 'jb': 0x82, 'jnae': 0x82, 'jc': 0x82,
            'jnb': 0x83, 'jae': 0x83, 'jnc': 0x83,
            'jz': 0x84, 'je': 0x84, 'jnz': 0x85, 'jne': 0x85,
            'jbe': 0x86, 'jna': 0x86, 'ja': 0x87, 'jnbe': 0x87,
            'js': 0x88, 'jns': 0x89, 'jp': 0x8A, 'jpe': 0x8A,
            'jnp': 0x8B, 'jpo': 0x8B,
            'jl': 0x8C, 'jnge': 0x8C, 'jge': 0x8D, 'jnl': 0x8D,
            'jle': 0x8E, 'jng': 0x8E, 'jg': 0x8F, 'jnle': 0x8F,
        }
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        fixed = 0
        placeholders = [
            i for i in range(len(out) - 5)
            if out[i:i + 6] == b'\x0f\x00\x00\x00\x00\x00'
        ]
        if not placeholders:
            return 0
        ph_set = set(placeholders)

        # rva_map values are blob offsets into *out* (same coordinate system as
        # placeholder indices).  Callers that pass PE-RVA dumps must convert
        # first (final_rva - text_rva).
        at_pe: Dict[int, List[int]] = {}
        for xrva, pe in rva_map.items():
            if 0 <= pe < len(out):
                at_pe.setdefault(pe, []).append(xrva)

        def _jcc_from_tip(xrva: int):
            """Return (jcc_xrva, cc, tgt_x86) from tip or a Jcc within 16 bytes."""
            for d in range(0, 16):
                jrva = (xrva + d) & 0xFFFFFFFF
                off = jrva - text_rva
                if off < 0 or off + 6 > len(text_data):
                    break
                b0 = text_data[off]
                if not (b0 == 0x0F or 0x70 <= b0 <= 0x7F):
                    # Allow flag producers between tip and Jcc; stop on CF.
                    if b0 in (0xE8, 0xE9, 0xC3, 0xC2, 0xC9):
                        break
                    if d == 0:
                        continue
                    # only skip short cmp/test/mov encodings
                    if b0 in (0x3B, 0x39, 0x3A, 0x38, 0x85, 0x84, 0x83, 0x81,
                              0x66, 0x0B, 0x0A, 0x33, 0x31, 0x8B, 0x89, 0x40,
                              0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                              0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                              0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                              0x90, 0xA1, 0xA3):
                        continue
                    break
                insns = list(md32.disasm(
                    bytes(text_data[off:off + 16]),
                    self.old_base + jrva, count=1))
                if not insns:
                    break
                insn = insns[0]
                mnem = insn.mnemonic
                if not mnem.startswith('j') or mnem == 'jmp':
                    break
                if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                    break
                cc = JCC_CC.get(mnem)
                if cc is None:
                    break
                tgt_x86 = (insn.operands[0].imm - self.old_base) & 0xFFFFFFFF
                return jrva, cc, tgt_x86
            return None

        used_xrva: Set[int] = set()
        used_ph: Set[int] = set()

        # Pass 1 — placeholder-centric (closest tip at/below the slot).
        for p_off in placeholders:
            best = None  # (gap, xrva, cc, tgt)
            for pe in range(max(0, p_off - 160), p_off + 1):
                for xrva in at_pe.get(pe, ()):
                    if xrva in used_xrva:
                        continue
                    info = _jcc_from_tip(xrva)
                    if info is None:
                        continue
                    jrva, cc, tgt_x86 = info
                    if jrva in used_xrva:
                        continue
                    tgt = self._resolve_jcc_target_off(out, tgt_x86, rva_map)
                    if tgt is None or not (0 <= tgt < len(out)):
                        continue
                    gap = p_off - pe
                    cand = (gap, jrva, cc, tgt)
                    if best is None or cand < best:
                        best = cand
            if best is None:
                continue
            _gap, jrva, cc, tgt = best
            out[p_off + 1] = cc
            struct.pack_into('<i', out, p_off + 2, tgt - (p_off + 6))
            used_xrva.add(jrva)
            used_ph.add(p_off)
            fixed += 1

        # Pass 2 — x86-centric: tip may land slightly past the placeholder
        # (rematerialized cmp) or the Jcc tip may be missing while the cmp tip
        # remains.  Claim any remaining ``0F 00…`` near the mapped site.
        n_td = len(text_data)
        for off in range(max(0, n_td - 6)):
            op = text_data[off]
            is_near = 0x70 <= op <= 0x7F
            is_far = (op == 0x0F and off + 5 < n_td
                      and 0x80 <= text_data[off + 1] <= 0x8F)
            if not (is_near or is_far):
                continue
            jrva = (text_rva + off) & 0xFFFFFFFF
            if jrva in used_xrva:
                continue
            info = _jcc_from_tip(jrva)
            if info is None:
                continue
            jrva, cc, tgt_x86 = info
            if jrva in used_xrva:
                continue
            # Site: direct tip, or any tip within 8 bytes before the Jcc
            # (cmp/test that the emitter mapped instead of the branch).
            sites: List[int] = []
            for back in range(0, 9):
                pe = rva_map.get((jrva - back) & 0xFFFFFFFF)
                if pe is not None and 0 <= pe < len(out):
                    sites.append(pe)
            if not sites:
                continue
            tgt = self._resolve_jcc_target_off(out, tgt_x86, rva_map)
            if tgt is None or not (0 <= tgt < len(out)):
                continue
            best_ph = None
            for pe in sites:
                for p_off in range(max(0, pe - 8), min(len(out) - 5, pe + 96)):
                    if p_off not in ph_set or p_off in used_ph:
                        continue
                    gap = abs(p_off - pe)
                    cand = (gap, p_off)
                    if best_ph is None or cand < best_ph:
                        best_ph = cand
            if best_ph is None:
                continue
            _gap, p_off = best_ph
            out[p_off + 1] = cc
            struct.pack_into('<i', out, p_off + 2, tgt - (p_off + 6))
            used_xrva.add(jrva)
            used_ph.add(p_off)
            fixed += 1
        return fixed

    def _crt_entry_quality_score(self, text_blob: bytes, off: int) -> int:
        """Score a translated MSVC CRT prologue (higher = healthier code)."""
        # Accept both the classic CRT prologue and the aligned variant
        # (and rsp,-16 inserted after mov rbp,rsp for x64 ABI compliance).
        crt_sig_old = b'\x55\x48\x89\xe5\x6a\xff'
        crt_sig_new = b'\x55\x48\x89\xe5\x48\x83\xe4\xf0\x6a\xff'
        if off < 0 or off + len(crt_sig_old) > len(text_blob):
            return -999
        if (text_blob[off:off + len(crt_sig_old)] == crt_sig_old
                or (off + len(crt_sig_new) <= len(text_blob)
                    and text_blob[off:off + len(crt_sig_new)] == crt_sig_new)):
            pass
        else:
            return -999
        score = 100
        if not HAS_CAPSTONE:
            return score
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        chunk = text_blob[off:off + 0x140]
        try:
            for ins in md.disasm(chunk, off):
                if ins.address - off > 0x120:
                    break
                try:
                    for op in ins.operands:
                        if op.type != X86_OP_MEM:
                            continue
                        disp = op.mem.disp
                        if disp > 0x7FFFFFFF:
                            disp -= 0x100000000
                        if disp < -0x1000 or disp > 0x1000:
                            score -= 40
                except CsError:
                    score -= 10
                if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
                    score += 5
                if (self._cmd_no_hacks and ins.mnemonic == 'sub'
                        and ins.op_str.startswith('rsp')):
                    try:
                        n = int(ins.op_str.split(',')[1].strip(), 0)
                        if n > 0x180:
                            score -= 60
                    except (ValueError, IndexError):
                        pass
        except CsError:
            score -= 20
        return score

    def _resolve_pe64_entry_rva(self, text_blob: bytes, text_rva: int,
                                mapped_entry: int) -> int:
        """Ensure the PE loader entry lands on a real translated prologue."""
        if not mapped_entry or mapped_entry < text_rva:
            return mapped_entry
        entry_off = mapped_entry - text_rva
        if entry_off < 0 or entry_off >= len(text_blob):
            return mapped_entry
        if self._cmd_no_hacks:
            # Prefer the direct rva_map anchor when it already looks like CRT startup.
            if (text_blob[entry_off:entry_off + 3] == b'\x55\x48\x89'
                    and text_blob[entry_off + 3] == 0xE5
                    and self._x64_entry_prologue_ok(text_blob, entry_off)):
                return mapped_entry
            # rva_map[pe.entry_rva] often lands mid-function; walk back to push-rbp.
            for back in range(0, 4096):
                pos = entry_off - back
                if pos < 0:
                    break
                if back > 0 and text_blob[pos] == 0xC3:
                    break
                if text_blob[pos:pos + 3] != b'\x55\x48\x89':
                    continue
                if text_blob[pos + 3] != 0xE5:  # mov rbp, rsp
                    continue
                return text_rva + pos
            nearest = self._find_nearest_crt_startup_off(text_blob, entry_off)
            if nearest is not None:
                return text_rva + nearest
        if (text_blob[entry_off:entry_off + 4] == b'\x55\x48\x89\xe5'
                and self._crt_entry_quality_score(text_blob, entry_off) >= 80):
            return mapped_entry
        crt_sig = b'\x55\x48\x89\xe5'  # push rbp; mov rbp, rsp
        # Also accept the aligned variant (and rsp,-16 inserted after mov rbp,rsp)
        crt_sig_old = b'\x55\x48\x89\xe5\x6a\xff'
        crt_sig_new = b'\x55\x48\x89\xe5\x48\x83\xe4\xf0\x6a\xff'
        eh3_imm = w2kshim_except_handler3_va()
        crt_hits: List[int] = []
        idx = 0
        while True:
            j = text_blob.find(crt_sig, idx)
            if j < 0:
                break
            # Accept both classic and aligned CRT prologue signatures
            if (text_blob[j:j + len(crt_sig_old)] == crt_sig_old
                    or (j + len(crt_sig_new) <= len(text_blob)
                        and text_blob[j:j + len(crt_sig_new)] == crt_sig_new)):
                crt_hits.append(j)
            idx = j + 1
        best_crt: Optional[int] = None
        best_score = -999
        best_dist = 0x7FFFFFFF
        for j in crt_hits:
            head = text_blob[j:j + 0x40]
            if self._cmd_no_hacks:
                if (b'\x48\xb8' not in head
                        or b'\x65\x48\x8b\x04\x25\x00\x00\x00\x00'
                        not in text_blob[j:j + 0x30]):
                    continue
            elif b'\x48\xb8' + struct.pack('<Q', eh3_imm) not in head:
                continue
            q = self._crt_entry_quality_score(text_blob, j)
            if self._cmd_no_hacks:
                dist = abs(j - entry_off)
                if q > best_score or (q == best_score and dist < best_dist):
                    best_score = q
                    best_dist = dist
                    best_crt = j
                elif q >= 80 and best_score < 80:
                    best_score = q
                    best_dist = dist
                    best_crt = j
            else:
                if q > best_score or (q == best_score and best_crt is not None
                                      and j < best_crt):
                    best_score = q
                    best_crt = j
                elif q > best_score:
                    best_score = q
                    best_crt = j
        if best_crt is None and crt_hits:
            best_crt = min(crt_hits)
        if best_crt is not None:
            return text_rva + best_crt
        ent = self._entry_for_x86_target(
            text_blob, self.pe.entry_rva, self.rva_map or {})
        if ent is not None and 0 <= ent < len(text_blob):
            if (text_blob[ent:ent + 4] == b'\x55\x48\x89\xe5'
                    or self._offset_is_mapped_entry(text_blob, ent)):
                return text_rva + ent
        for back in range(1, 256):
            pos = entry_off - back
            if pos < 0:
                break
            if text_blob[pos] == 0xC3:
                break
            if text_blob[pos:pos + 4] == b'\x55\x48\x89\xe5':
                return text_rva + pos
            if self._offset_is_wrapper_entry(text_blob, pos):
                return text_rva + pos
        if self.win10_test_shim:
            try:
                eh3_va = w2kshim_except_handler3_va()
                tail = (
                    b"\x50"
                    + b"\x48\xb8" + struct.pack("<Q", eh3_va)
                    + b"\x50"
                    + b"\x65\x48\x8b\x04\x25\x00\x00\x00\x00"
                    + b"\x50"
                    + b"\x65\x48\x89\x24\x25\x00\x00\x00\x00"
                )
                j = text_blob.find(tail)
                if j >= 0:
                    candidate = text_rva + max(0, j - (1 + 10 + 1 + 9 + 1 + 10 + 1))
                    off = candidate - text_rva
                    if (0 <= off < len(text_blob)
                            and text_blob[off:off + 4] == b'\x55\x48\x89\xe5'):
                        return candidate
            except Exception:
                pass
        return mapped_entry

    def _call_lands_in_epilogue_tail(self, out: bytearray, tgt: int) -> bool:
        """True when *tgt* points at ``add rsp, N`` / ``ret`` in a translated tail."""
        if tgt + 4 <= len(out) and out[tgt:tgt + 4] == b'\x48\x83\xc4\x58':
            return True
        if tgt + 3 <= len(out) and out[tgt:tgt + 3] == b'\x48\x83\xc4':
            return True
        if tgt + 7 <= len(out) and out[tgt:tgt + 3] == b'\x48\x81\xc4':
            return True
        if tgt + 1 <= len(out) and out[tgt] in (0x5F, 0x5E, 0x5B, 0x5D):  # pop reg
            return True
        if tgt + 3 <= len(out) and out[tgt:tgt + 3] == b'\x48\x89\xf0':
            return True
        return False

    def _extract_function_bytes(self, func_rva: int, text_data: bytes,
                                text_rva: int, limit: int = 65536,
                                bound_rva: Optional[int] = None) -> bytes:
        """Disassemble from func_rva until RET, IAT jmp thunk, bound, or limit."""
        func_off = func_rva - text_rva
        if func_off < 0 or func_off >= len(text_data):
            return b''
        code = text_data[func_off:func_off + limit]
        insns = list(self.md.disasm(code, self.old_base + func_rva, count=16384))
        if not insns:
            return b''
        end_off = insns[-1].address - self.old_base + insns[-1].size - func_rva
        for insn in insns:
            if insn.mnemonic == 'jmp' and insn.operands:
                op = insn.operands[0]
                if (op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0
                        and op.mem.segment == 0):
                    end_off = insn.address - self.old_base + insn.size - func_rva
                    break
            if insn.mnemonic in ('ret', 'retn'):
                end_off = insn.address - self.old_base + insn.size - func_rva
                if end_off > 0:
                    # Dual-exit predicates (cmd e846): ``xor al,al; ret`` /
                    # ``mov al,1; ret``.  Stopping at the first RET drops the
                    # success path and leaves forward Jccs unresolved (they
                    # bounce to the function entry → infinite loop).
                    end_off = self._extend_end_for_dual_exit(
                        code, end_off)
                    break
        if (self._cmd_no_hacks and bound_rva is not None
                and bound_rva > func_rva):
            bound_end = min(bound_rva - func_rva, len(text_data) - func_off)
            if bound_end > 0:
                end_off = min(end_off, bound_end)
        return code[:min(end_off, len(code))]

    @staticmethod
    def _extend_end_for_dual_exit(code: bytes, end_off: int,
                                  limit: int = 12) -> int:
        """Grow *end_off* past a trailing ``mov al/eax,imm; ret`` after an early RET."""
        post = code[end_off:end_off + limit]
        if len(post) >= 3 and post[0] == 0xB0 and post[2] == 0xC3:
            return end_off + 3  # mov al, imm8; ret
        if len(post) >= 6 and post[0] == 0xB8 and post[5] == 0xC3:
            return end_off + 6  # mov eax, imm32; ret
        if len(post) >= 4 and post[0:2] == b'\x31\xc0' and post[2] == 0xB0 and post[4] == 0xC3:
            return end_off + 5  # xor eax,eax; mov al,imm; ret (unlikely)
        # ``mov al,1; ret`` may be preceded by a short nop/int3 pad.
        for skip in range(0, min(4, len(post))):
            p = post[skip:]
            if len(p) >= 3 and p[0] == 0xB0 and p[2] == 0xC3:
                return end_off + skip + 3
        return end_off

    def _fill_missing_export_mappings(self) -> None:
        """Ensure every executable export has a translated code mapping."""
        if not self._code_layout:
            return
        layout_idx: Dict[int, int] = {}
        extras: Dict[int, bytearray] = {}
        for idx, (_name, _data, _flags, old_va) in enumerate(self._code_layout):
            layout_idx[old_va] = idx
            extras[old_va] = bytearray()

        patched = 0
        for exp in self.pe.parse_exports():
            rva = exp['rva']
            if rva in self.rva_map:
                continue
            sec = self.pe.section_for_rva(rva)
            if not sec or not (sec['flags'] & 0x20000000):
                continue
            sec_rva = sec['vaddr']
            if sec_rva not in layout_idx:
                continue
            sec_data = self.pe.get_section_data(sec)
            code = self._translate_export_at(rva, sec_data, sec_rva)
            if not code:
                continue
            extra = extras[sec_rva]
            pad = (4 - len(extra) % 4) % 4
            extra += b'\xCC' * pad
            idx = layout_idx[sec_rva]
            base_len = len(self._code_layout[idx][1]) + len(extra)
            self.rva_map[rva] = base_len
            self._rva_section[rva] = sec_rva
            extra += code
            patched += 1

        if patched:
            new_layout = []
            for name, data, flags, old_va in self._code_layout:
                blob = bytearray(data)
                if extras[old_va]:
                    blob += extras[old_va]
                new_layout.append((name, bytes(blob), flags, old_va))
            self._code_layout = new_layout
            print(f"        Patched {patched} missing export entry points")
