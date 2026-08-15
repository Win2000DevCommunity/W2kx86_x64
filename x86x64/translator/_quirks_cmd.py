"""Address-pinned repairs for a specific cmd.exe build.

Every method here keys off a hard-coded x86 RVA, so none of it generalises.
It is kept isolated -- and skipped entirely in ``--pure`` mode -- because the
relocation-based pipeline in :mod:`x86x64.core` is meant to make it
unnecessary rather than to grow it.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class CmdQuirksMixin:
    """See the module docstring."""

    def _cmd_builder_ebp_m4_is_ptr(self, old_va: int) -> bool:
        """In cmd's cmdline builder, [EBP-4] holds a context pointer, not an index."""
        if not self.win10_test_shim:
            return False
        rva = (old_va - self.old_base) & 0xFFFFFFFF
        return 0x1A217 <= rva <= 0x1A580

    def _cmd_builder_ebp_m8_is_ptr(self, old_va: int) -> bool:
        """In cmd's cmdline builder, [EBP-8] holds a parse cursor pointer."""
        if not self.win10_test_shim:
            return False
        rva = (old_va - self.old_base) & 0xFFFFFFFF
        return 0x1A217 <= rva <= 0x1A580

    def _cmd_heap_indexed_mem(self, mem) -> bool:
        """cmd builder/cmdline tables: [base+index] slot (shl 3 stride on Win10)."""
        return (mem.base and mem.index and not mem.disp
                and (mem.scale or 1) == 1)

    def _cmd_builder_struct_ptr_field(self, old_va: int, disp: int) -> bool:
        """Pointer fields in cmd's cmdline-builder context structs."""
        if not self.win10_test_shim:
            return False
        rva = (old_va - self.old_base) & 0xFFFFFFFF
        if not (0x1A217 <= rva <= 0x1A580):
            return False
        return (disp & 0xFFFFFFFF) == 0x1C

    def _cmd_builder_add_eax_edi_plus30(self, old_va: int) -> bool:
        """push 0x30; pop edi; add eax, edi — offset into cmd arg table (+0x30)."""
        if not self.win10_test_shim:
            return False
        rva = (old_va - self.old_base) & 0xFFFFFFFF
        return rva in (0x1A419, 0x1A436, 0x1A44E, 0x1A49F)

    def _cmd_fn6314_entry_off(self, out: bytearray) -> Optional[int]:
        """Blob offset of translated cmd helper originally at x86 RVA 0x6314."""
        glob = b'\x48\xba\x00\x9b\x04\x80\x00\x00\x00\x00'
        j = out.find(glob)
        if j >= 15 and out[j - 6:j - 4] == b'\x0f\x84':
            entry = j - 12
            if entry >= 0 and out[entry:entry + 3] == b'\x49\x89\xca':
                return entry
            if entry >= 0 and out[entry:entry + 2] == b'\x48\x31':
                return entry
        needle = b'\x0f\x84\x4d\x01\x00\x00\x48\xb9\x00\x7b\x04\x80'
        idx = out.find(needle)
        if idx >= 0:
            return idx - 9
        for sig in (b'\x49\x89\xca\x48\x31\xff\x48\x85\xc9',
                    b'\x49\x89\xca\x48\x85\xc9',
                    b'\x49\x89\xd1\x48\x85\xc9',
                    b'\x48\x31\xff\x48\x85\xc9',
                    b'\x48\x31\xff\x39\x7c\x24\x14',
                    b'\x48\x31\xff\x48\x85\xc9'):
            idx = out.find(sig)
            if idx >= 0:
                return idx
        return None

    def _cmd_fn6578_entry_off(self, out: bytearray) -> Optional[int]:
        """Blob offset of translated cmd helper originally at x86 RVA 0x6578."""
        for sig in (b'\x8b\x01\xc3', b'\x89\xc8\x8b\x00\xc3', b'\x8b\x02\xc3'):
            idx = out.find(sig)
            if idx >= 0:
                return idx
        return None

    def _restore_cmd_text_constants(self, out: bytearray) -> int:
        """Restore x86 .text constant pool clobbered by early translation (path/COPYCMD)."""
        if not self.win10_test_shim:
            return 0
        text_sec = next((s for s in self.pe.sections if s['name'].startswith('.text')), None)
        if text_sec is None:
            return 0
        raw = self.pe.get_section_data(text_sec)
        # cmd CRT/fn6314 path cells: RVAs 0x161c..0x1780 (.text+0x61c..0x780).
        lo, hi = 0x61c, 0x780
        if hi > len(raw) or hi > len(out):
            return 0
        if out[lo:hi] == raw[lo:hi]:
            return 0
        out[lo:hi] = raw[lo:hi]
        return 1

    def _fix_cmd_crt_wcslen_path(self, out: bytearray) -> int:
        """CRT path after fn6314: wcslen then lea rax,[rax+rax+2] before malloc (not mov rcx,rax)."""
        lea_off = 0x8A91 - self.text_rva
        jmp_off = 0x8A8C - self.text_rva
        if lea_off < 0 or jmp_off < 0:
            return 0
        if jmp_off + 5 > len(out) or out[jmp_off] != 0xE9:
            return 0
        lea = b'\x48\x8d\x44\x00\x02'  # lea rax, [rax+rax+2]
        if out[lea_off:lea_off + len(lea)] == lea and struct.unpack_from('<i', out, jmp_off + 1)[0] == lea_off - (jmp_off + 5):
            return 0
        struct.pack_into('<i', out, jmp_off + 1, lea_off - (jmp_off + 5))
        out[lea_off:lea_off + 8] = lea + b'\x90' * (8 - len(lea))
        return 1

    def _fix_cmd_crt_wcslen_helper_calls(self, out: bytearray) -> int:
        """Snap wcslen helper ``call`` sites off mid-instruction (0x2D1C2) to real entry."""
        if not self.text_rva:
            return 0
        bad = 0x2D1C2 - self.text_rva
        lo = 0x2D1A0 - self.text_rva
        hi = 0x2D200 - self.text_rva
        if bad < 0 or lo < 0 or hi > len(out):
            return 0
        prefix = b'\x48\x89\xf1\x41\x55\x49\x89\xe5\x48\x83\xec\x20'
        good = out.find(prefix, lo, hi)
        if good < 0:
            return 0
        tail = out[good + 12:good + 18]
        if tail not in (b'\x48\x83\xe4\xf0\xff\xd7',) and tail[:2] != b'\xff\x15':
            return 0
        fixed = 0
        for call_rva in (0x76A3, 0x8A44):
            off = call_rva - self.text_rva
            if off < 0 or off + 5 > len(out) or out[off] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, off + 1)[0]
            tgt = off + 5 + rel
            if tgt == good:
                continue
            if not (lo <= tgt < good + 8):
                continue
            struct.pack_into('<i', out, off + 1, good - (off + 5))
            fixed += 1
        for pad in range(lo, min(hi, len(out) - 2)):
            if out[pad:pad + 3] == b'\x00\x00\x00' and out[pad + 3:pad + 6] == b'\x48\x89\xf1':
                out[pad:pad + 3] = b'\x90\x90\x90'
                fixed += 1
                break
        dup = out.find(b'\x89\x45\xf8\x89\x45\xf8', lo, hi)
        if dup >= 0:
            out[dup + 3:dup + 6] = b'\x90\x90\x90'
            fixed += 1
        iat_off = good + 12
        if iat_off + 6 <= len(out) and out[iat_off:iat_off + 6] == b'\x48\x83\xe4\xf0\xff\xd7':
            ref_rva = 0x8A7B
            ref_off = ref_rva - self.text_rva
            if 0 <= ref_off + 6 <= len(out) and out[ref_off:ref_off + 2] == b'\xff\x15':
                ref_rel = struct.unpack_from('<i', out, ref_off + 2)[0]
                iat_rva = ref_rva + 6 + ref_rel
                rel = iat_rva - (self.text_rva + iat_off + 6)
                if -2147483648 <= rel <= 2147483647:
                    out[iat_off:iat_off + 6] = b'\xff\x15' + struct.pack('<i', rel)
                    fixed += 1
        elif iat_off + 6 <= len(out) and out[iat_off:iat_off + 2] == b'\xff\x15':
            ref_rva = 0x8A7B
            ref_off = ref_rva - self.text_rva
            if 0 <= ref_off + 6 <= len(out) and out[ref_off:ref_off + 2] == b'\xff\x15':
                ref_rel = struct.unpack_from('<i', out, ref_off + 2)[0]
                iat_rva = ref_rva + 6 + ref_rel
                rel = iat_rva - (self.text_rva + iat_off + 6)
                cur = struct.unpack_from('<i', out, iat_off + 2)[0]
                if cur != rel and -2147483648 <= rel <= 2147483647:
                    struct.pack_into('<i', out, iat_off + 2, rel)
                    fixed += 1
        thunk_lo = 0x29FE0 - self.text_rva
        thunk_hi = 0x2A010 - self.text_rva
        call_off = 0x2A846 - self.text_rva
        if 0 <= call_off + 5 <= len(out) and out[call_off] == 0xE8:
            rel = struct.unpack_from('<i', out, call_off + 1)[0]
            tgt = call_off + 5 + rel
            if thunk_lo <= tgt <= thunk_hi and tgt != good:
                struct.pack_into('<i', out, call_off + 1, good - (call_off + 5))
                fixed += 1
        arg_off = 0x2A836 - self.text_rva
        if 0 <= arg_off + 3 <= len(out):
            want = b'\x48\x89\xce'  # mov rsi, rcx — banner/print callers pass string in RCX
            cur = out[arg_off:arg_off + 3]
            if cur in (b'\x48\x31\xc9', b'\x48\x89\xf1') and out[arg_off + 3:arg_off + 5] == b'\x41\x55':
                if cur != want:
                    out[arg_off:arg_off + 3] = want
                    fixed += 1
        je_off = 0x2D1C3 - self.text_rva
        bad_je = b'\x0f\x84\x1f\x90\x90\x90'
        good_je = b'\x0f\x84\x1f\x00\x00\x00'
        if (0 <= je_off + len(bad_je) <= len(out) and out[je_off:je_off + len(bad_je)] == bad_je):
            out[je_off:je_off + len(good_je)] = good_je
            fixed += 1
        align_entry = 0x2A836 - self.text_rva
        wrong_entry = 0x2A83E - self.text_rva
        if align_entry >= 0 and wrong_entry >= 0:
            i = 0
            while i < len(out) - 5:
                if out[i] != 0xE8:
                    i += 1
                    continue
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt == wrong_entry:
                    struct.pack_into('<i', out, i + 1, align_entry - (i + 5))
                    fixed += 1
                i += 1
        return fixed

    def _fix_cmd_crt_wcslen_call_8a44(self, out: bytearray) -> int:
        """CRT fn6314 path: inline wcslen-only stub (0x8A44 must not fall into 0x2D1EB)."""
        if not self.text_rva:
            return 0
        fixed = 0
        ref_rva = 0x8A7B
        ref_off = ref_rva - self.text_rva
        if ref_off < 0 or ref_off + 6 > len(out) or out[ref_off:ref_off + 2] != b'\xff\x15':
            return 0
        iat_rva = ref_rva + 6 + struct.unpack_from('<i', out, ref_off + 2)[0]
        stub_rva = 0x3D4B
        stub_off = stub_rva - self.text_rva
        stub = (
            b'\x48\x89\xf1'                   # mov rcx, rsi
            b'\x41\x55\x49\x89\xe5'           # push r13; mov r13, rsp
            b'\x48\x83\xec\x20\x48\x83\xe4\xf0'
        )
        ff_off = len(stub)
        rel = iat_rva - (stub_rva + ff_off + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        stub += b'\xff\x15' + struct.pack('<i', rel)
        stub += b'\x4c\x89\xec\x41\x5d\xc3'  # mov rsp,r13; pop r13; ret
        if stub_off < 0 or stub_off + len(stub) > len(out):
            return 0
        run = out[stub_off:stub_off + len(stub)]
        if run != stub and not all(b == 0x90 for b in run):
            return 0
        if run != stub:
            out[stub_off:stub_off + len(stub)] = stub
            fixed += 1
        call_off = 0x8A44 - self.text_rva
        if 0 <= call_off + 5 <= len(out) and out[call_off] == 0xE8:
            want = stub_rva - (0x8A44 + 5)
            if struct.unpack_from('<i', out, call_off + 1)[0] != want:
                struct.pack_into('<i', out, call_off + 1, want)
                fixed += 1
        wrap_off = 0x8A37 - self.text_rva
        seed = b'\x48\x89\xce' + b'\x90' * 10  # mov rsi, rcx + pad to call
        if 0 <= wrap_off + len(seed) <= len(out):
            cur = out[wrap_off:wrap_off + len(seed)]
            if cur != seed and (cur.startswith(b'\x48\x89\xce') or cur.startswith(b'\x41\x55')
                                or all(b == 0x90 for b in cur[3:])):
                out[wrap_off:wrap_off + len(seed)] = seed
                fixed += 1
        epilogue_off = 0x8A49 - self.text_rva
        if 0 <= epilogue_off + 5 <= len(out):
            if out[epilogue_off:epilogue_off + 5] != b'\x90' * 5:
                out[epilogue_off:epilogue_off + 5] = b'\x90' * 5
                fixed += 1
        save_off = 0x8A4E - self.text_rva
        if 0 <= save_off + 3 <= len(out) and out[save_off:save_off + 3] != b'\x48\x89\xc6':
            if out[save_off:save_off + 3] == b'\x90\x90\x90':
                out[save_off:save_off + 3] = b'\x48\x89\xc6'
                fixed += 1
        return fixed

    def _fix_cmd_crt_second_wcslen_8a6b(self, out: bytearray) -> int:
        """RSI holds length after first wcslen; RCX still has the path string — drop mov rcx,rsi."""
        if not self.text_rva:
            return 0
        off = 0x8A6B - self.text_rva
        bad = b'\x48\x89\xf1'  # mov rcx, rsi
        good = b'\x90\x90\x90'
        if off < 0 or off + 3 > len(out) or out[off:off + 3] != bad:
            return 0
        if out[off:off + 3] == good:
            return 0
        out[off:off + 3] = good
        return 1

    def _fix_cmd_crt_wcslen_inline_2a805(self, out: bytearray) -> int:
        """Snap wcslen inline thunks off ``sub rsp,20`` at 0x2A80D to ``mov rcx,rax`` at 0x2A805."""
        if not self.text_rva:
            return 0
        bad = 0x2A80D - self.text_rva
        good = 0x2A805 - self.text_rva
        if bad < 0 or good < 0 or good + 3 > len(out):
            return 0
        if out[good:good + 3] != b'\x48\x89\xc1':
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 5:
            if out[i] != 0xE8:
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            if i + 5 + rel == bad:
                struct.pack_into('<i', out, i + 1, good - (i + 5))
                fixed += 1
            i += 1
        ret_off = 0x2A82D - self.text_rva
        if 0 <= ret_off + 5 <= len(out) and out[ret_off:ret_off + 5] == b'\xe9\x04\x00\x00\x00':
            out[ret_off:ret_off + 5] = b'\xc3' + b'\x90' * 4
            fixed += 1
        rdi_off = 0x2A850 - self.text_rva
        if 0 <= rdi_off + 3 <= len(out) and out[rdi_off:rdi_off + 3] == b'\x48\x89\xc7':
            out[rdi_off:rdi_off + 3] = b'\x48\x89\xf7'
            fixed += 1
        return fixed

    def _fix_cmd_crt_getmainargs_setup(self, out: bytearray) -> int:
        """CRT startup: keep ``lea rcx,[rbp+…]`` for ``__getmainargs``; don't clobber with ``mov rcx,rax``."""
        if not self.text_rva:
            return 0
        fixed = 0
        patches = (
            (0x8857, b'\x48\x89\xc1', b'\x90\x90\x90'),
            (0x88D6, b'\x48\x89\xc1', b'\x90\x90\x90'),
        )
        for rva, bad, good in patches:
            off = rva - self.text_rva
            if off < 0 or off + len(bad) > len(out):
                continue
            if out[off:off + len(bad)] == bad:
                out[off:off + len(bad)] = good
                fixed += 1
        return fixed

    def _inject_cmd_wcscpy_thunks(self, out: bytearray) -> Optional[tuple]:
        """Inject swap/direct wcscpy thunks for misrouted x86 0x6581 call sites."""
        tag = b'\x48\x87\xd1'  # xchg rcx, rdx (swap-thunk head)
        wcscpy_core = (
            b'\x48\xb8\xe9\xf3\x06\x80\x00\x00\x00\x00'
            b'\x48\x8b\x00\xff\xd0\xc3'
        )
        swap = tag + wcscpy_core
        pos = out.find(tag)
        if pos >= 0 and pos + len(swap) <= len(out) and out[pos + len(swap) - 1] == 0xC3:
            return (pos, pos + len(swap))
        sled = self._find_nop_run(out, len(swap) + len(wcscpy_core))
        if sled is None:
            return None
        direct = wcscpy_core
        if sled + len(swap) + len(direct) > len(out):
            return None
        out[sled:sled + len(swap)] = swap
        out[sled + len(swap):sled + len(swap) + len(direct)] = direct
        return (sled, sled + len(swap))

    def _fix_cmd_fn6581_call_sites(self, out: bytearray,
                                   rva_map: Optional[Dict[int, int]] = None) -> int:
        """Neutralize stale x86 0x6581 call sites that land in helper/wcscpy snippets."""
        copycmd = struct.pack('<Q', 0x800016E8)
        str_db = struct.pack('<Q', 0x800018DB)
        heap_load = b'\x8b\x95\x64\xff\xff\xff'
        align_pre = b'\x48\x83\xe4\xf0'
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            window = out[max(0, i - 32):i]
            use_swap = copycmd in window and heap_load in window
            use_direct = str_db in window and b'\x48\x89\xf9' in window
            if not use_swap and not use_direct:
                continue
            if align_pre not in out[max(0, i - 16):i]:
                continue
            if out[i:i + 5] == b'\x90' * 5:
                continue
            out[i:i + 5] = b'\x90' * 5
            fixed += 1
        fn6314 = self._cmd_fn6314_entry_off(out)
        fn6314_call = 0x8A41 - self.text_rva
        if (fn6314 is not None and 0 <= fn6314_call < len(out) - 5
                and out[fn6314_call] == 0xE8):
            rel = struct.unpack_from('<i', out, fn6314_call + 1)[0]
            if fn6314_call + 5 + rel != fn6314:
                struct.pack_into('<i', out, fn6314_call + 1,
                                 fn6314 - (fn6314_call + 5))
                fixed += 1
        if rva_map is not None and fn6314 is not None:
            rva_map[0x6581] = fn6314
        return fixed

    def _fix_cmd_crt_exit_branches(self, out: bytearray) -> int:
        """Snap CRT cleanup jmps that land at 0x2E048 instead of 0x2E042 (off-by-4)."""
        if not self.text_rva:
            return 0
        good = 0x2E042 - self.text_rva
        bad = 0x2E048 - self.text_rva
        if good < 0 or bad < 0 or good + 8 >= len(out):
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 6:
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if tgt == bad:
                    struct.pack_into('<i', out, i + 2, good - (i + 6))
                    fixed += 1
                i += 6
                continue
            if out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt == bad:
                    struct.pack_into('<i', out, i + 1, good - (i + 5))
                    fixed += 1
                i += 5
                continue
            i += 1
        return fixed

    def _fix_cmd_data_iat_pointer_cells(self, out: bytearray) -> int:
        """Replace broken ``movabs; mov [r]; call r`` IAT stubs with ``call [rip+disp]``."""
        # x86 ``call [IAT]`` became ``movabs r?, DATA; mov r?, [r?]; call r?`` but
        # several DATA cells under 0x42Fxx were never populated (loader skips them).
        # Retargeting movabs to the IAT VA still faults: use FF15 like _emit_iat_call.
        fixes = (
            (0x80042F38, 0x4AD010C0),  # CreateProcessW (CRT startup at ~0x8DFB)
            (0x80041F38, 0x4AD010C0),  # CreateProcessW (fn6314 setup at ~0x8DF1)
        )
        fixed = 0
        for bad_cell, old_iat_va in fixes:
            bad_pat = struct.pack('<Q', bad_cell)
            iat_va = self._resolve_iat_slot_va(old_iat_va)
            iat_pat = struct.pack('<Q', iat_va)
            pos = 0
            while True:
                j = out.find(bad_pat, pos)
                if j < 0:
                    j = out.find(iat_pat, pos)
                    if j < 0:
                        break
                if j < 2 or out[j - 2:j] != b'\x48\xb8':
                    pos = j + 1
                    continue
                k = j - 2
                if k + 15 > len(out):
                    pos = j + 1
                    continue
                if out[k + 10:k + 13] != b'\x48\x8b\x00' or out[k + 13:k + 15] != b'\xff\xd0':
                    pos = j + 1
                    continue
                call_rva = self.text_rva + k
                rel = iat_va - (self.new_base + call_rva + 6)
                if not (-2147483648 <= rel <= 2147483647):
                    pos = j + 1
                    continue
                patch = b'\xff\x15' + struct.pack('<i', rel) + b'\x90' * 9
                out[k:k + 15] = patch
                fixed += 1
                pos = k + 15
        return fixed

    def _fix_cmd_crt_cont_branches(self, out: bytearray) -> int:
        """Snap CRT continuation branches off mid-movabs (0x2D9A2..0x2D9AA) to 0x2D9A1."""
        if not self.text_rva:
            return 0
        good = 0x2D9A1 - self.text_rva
        bad_lo = 0x2D9A2 - self.text_rva
        bad_hi = 0x2D9AA - self.text_rva
        if good < 0 or bad_lo < 0 or bad_hi < bad_lo:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 6:
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if bad_lo <= tgt <= bad_hi:
                    struct.pack_into('<i', out, i + 2, good - (i + 6))
                    fixed += 1
                i += 6
                continue
            if out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if bad_lo <= tgt <= bad_hi:
                    struct.pack_into('<i', out, i + 1, good - (i + 5))
                    fixed += 1
                i += 5
                continue
            i += 1
        return fixed

    def _fix_cmd_crt_fail_path_branches(self, out: bytearray) -> int:
        """Retarget CRT fail-path merges from cleanup (0x2E042) to continuation (0x2D9A1)."""
        if not self.text_rva:
            return 0
        good = 0x2D9A1 - self.text_rva
        bads = {0x2E042 - self.text_rva, 0x2E048 - self.text_rva}
        lo = 0x8E20 - self.text_rva
        hi = 0x8E90 - self.text_rva
        if good < 0 or lo < 0 or hi > len(out):
            return 0
        fixed = 0
        i = lo
        while i < min(hi, len(out) - 6):
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if tgt in bads:
                    struct.pack_into('<i', out, i + 2, good - (i + 6))
                    fixed += 1
                i += 6
                continue
            if out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt in bads:
                    struct.pack_into('<i', out, i + 1, good - (i + 5))
                    fixed += 1
                i += 5
                continue
            i += 1
        return fixed

    def _fix_cmd_force_crt_reexec_fail(self, out: bytearray,
                                        text_rva: Optional[int] = None) -> int:
        """Force CreateProcessW to fail so CRT stays in-process (Win10 re-exec wait)."""
        if text_rva is None:
            text_rva = self.text_rva
        if not text_rva:
            return 0
        iat_va = self._resolve_iat_slot_va(0x4AD010C0)  # CreateProcessW
        patch = b'\x31\xc0' + b'\x90' * 4
        lo = max(0, 0x8C00 - text_rva)
        hi = min(len(out), 0x8E20 - text_rva)
        fixed = 0
        i = lo
        while i < hi - 5:
            if out[i:i + 2] != b'\xff\x15':
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = self.new_base + text_rva + i + 6 + rel
            if tgt == iat_va and out[i:i + len(patch)] != patch:
                out[i:i + len(patch)] = patch
                fixed += 1
            i += 6
        for cpw_rva in (0x8C2B, 0x8DEE):
            cpw_off = cpw_rva - text_rva
            if (0 <= cpw_off < len(out) - len(patch)
                    and out[cpw_off:cpw_off + 2] == b'\xff\x15'
                    and out[cpw_off:cpw_off + len(patch)] != patch):
                out[cpw_off:cpw_off + len(patch)] = patch
                fixed += 1
        # Stub any CRT ``ff15`` whose rip target missed the PE64 IAT (e.g. 0x8C2B→0x20C3).
        i = lo
        while i < hi - 5:
            if out[i:i + 2] != b'\xff\x15':
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            slot_rva = text_rva + i + 6 + rel
            if slot_rva < 0x6D000 or slot_rva >= 0x70000:
                if out[i:i + len(patch)] != patch:
                    out[i:i + len(patch)] = patch
                    fixed += 1
            i += 6
        return fixed

    def _fix_cmd_crt_createprocess_call_8df1(self, out: bytearray) -> int:
        """CRT fn6314: empty 0x41F38 indirect call → ``xor eax,eax`` (stay in-process)."""
        if not self.text_rva:
            return 0
        off = 0x8DF1 - self.text_rva
        bad = (b'\x48\xb8\x38\x1f\x04\x80\x00\x00\x00\x00'
               b'\x48\x8b\x00\xff\xd0')
        if off < 0 or off + len(bad) > len(out) or out[off:off + len(bad)] != bad:
            return 0
        out[off:off + len(bad)] = b'\x31\xc0' + b'\x90' * (len(bad) - 2)
        return 1

    def _fix_cmd_crt_divert_init_loops(self, out: bytearray) -> int:
        """Keep CRT on the in-process path: NOP branches into 0x2D9A9 / 0x2DCC7."""
        if not self.text_rva:
            return 0
        fixed = 0
        jne_off = 0x8D56 - self.text_rva
        loop = 0x2D9A9 - self.text_rva
        if (jne_off >= 0 and jne_off + 6 <= len(out)
                and out[jne_off:jne_off + 2] == b'\x0f\x85'):
            rel = struct.unpack_from('<i', out, jne_off + 2)[0]
            if jne_off + 6 + rel == loop:
                out[jne_off:jne_off + 6] = b'\x90' * 6
                fixed += 1
        je_off = 0x8D69 - self.text_rva
        bad = 0x2DCC7 - self.text_rva
        if (je_off >= 0 and je_off + 6 <= len(out)
                and out[je_off:je_off + 2] == b'\x0f\x84'):
            rel = struct.unpack_from('<i', out, je_off + 2)[0]
            if je_off + 6 + rel == bad:
                out[je_off:je_off + 6] = b'\x90' * 6
                fixed += 1
        return fixed

    def _fix_cmd_crt_restore_fn6314_calls(self, out: bytearray) -> int:
        """Restore CRT fn6314 calls NOP'd by ``_fix_cmd_fn6581_call_sites``."""
        if not self.text_rva:
            return 0
        fn6314 = self._cmd_fn6314_entry_off(out)
        if fn6314 is None:
            return 0
        fixed = 0
        copycmd = b'\x48\xb9\xe8\x16\x00\x80\x00\x00\x00\x00'
        heap_tags = (
            b'\x8b\x95\x64\xff\xff\xff',  # mov edx, [rbp-0x9c]
            b'\x89\x85\x64\xff\xff\xff',  # mov [rbp-0x9c], eax
        )
        sites = (
            (0x8CD4, 48),
            (0x8AF4, 0xD0),
        )
        for call_rva, win_sz in sites:
            call_off = call_rva - self.text_rva
            if call_off < 0 or call_off + 5 > len(out):
                continue
            if out[call_off:call_off + 5] != b'\x90' * 5:
                continue
            win = out[max(0, call_off - win_sz):call_off]
            if copycmd not in win or not any(tag in win for tag in heap_tags):
                continue
            rel = fn6314 - (call_off + 5)
            out[call_off] = 0xE8
            struct.pack_into('<i', out, call_off + 1, rel)
            fixed += 1
        return fixed

    def _fix_cmd_init_tail_int3(self, out: bytearray) -> int:
        """Drop stray INT3 in cmd init tail arg-setup (main+0x3FD72)."""
        if not self.text_rva:
            return 0
        off = 0x3FD72 - self.text_rva
        head = b'\x48\xb9\x00\x9b\x04\x80\x00\x00\x00\x00\x48\x89\xfa\x41\x89\xf0'
        if (off < 0 or off + 1 > len(out) or out[off] != 0xCC
                or off < len(head) or out[off - len(head):off] != head):
            return 0
        out[off] = 0x90
        return 1

    def _fix_cmd_crt_init_branches(self, out: bytearray) -> int:
        """Snap CRT init ``je`` at 0x2D9B3 off the ``xor/ret`` stub (0x2DC03) to fn6314."""
        if not self.text_rva:
            return 0
        je_off = 0x2D9B3 - self.text_rva
        good = 0x2DC0B - self.text_rva
        bad = {0x2DC0B - self.text_rva, 0x2DC03 - self.text_rva}
        if je_off < 0 or good < 0 or je_off + 6 > len(out):
            return 0
        if out[je_off:je_off + 2] != b'\x0f\x84':
            return 0
        rel = struct.unpack_from('<i', out, je_off + 2)[0]
        tgt = je_off + 6 + rel
        if tgt not in bad:
            return 0
        struct.pack_into('<i', out, je_off + 2, good - (je_off + 6))
        return 1

    def _fix_cmd_fn6314_zero_edi(self, out: bytearray, fn6314: int) -> int:
        """Undo a legacy patch that clobbered the fn6314 ``je`` after ``test rcx,rcx``."""
        if fn6314 + 8 > len(out):
            return 0
        if out[fn6314 + 6:fn6314 + 8] == b'\x90\x0f':
            return 0
        if out[fn6314 + 6:fn6314 + 8] == b'\x31\xff':
            out[fn6314 + 6:fn6314 + 8] = b'\x90\x0f'
            return 1
        return 0

    def _fix_cmd_heap_alloc_helper_2e37d(self, out: bytearray) -> int:
        """HeapAlloc stub at 0x2E357: GetProcessHeap then HeapAlloc(caller rdx=flags, r8=size)."""
        if not self.text_rva:
            return 0
        off = 0x2E357 - self.text_rva
        end = 0x2E39D - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        gph = (self.new_base + 0x6E408) & 0xFFFFFFFFFFFFFFFF
        hal = (self.new_base + 0x6E410) & 0xFFFFFFFFFFFFFFFF
        patch = (
            b'\x41\x55'              # push r13
            + b'\x49\x89\xe5'          # mov r13, rsp
            + b'\x48\x83\xec\x20'      # sub rsp, 0x20
            + b'\x48\x83\xe4\xf0'      # and rsp, 0x10
            + b'\x4d\x89\xc3'          # mov r11, r8 — save size
            + b'\x49\x89\xd2'          # mov r10, rdx — save flags
            + b'\x48\xb8' + struct.pack('<Q', gph)
            + b'\x48\x8b\x00'          # mov rax, [rax]
            + b'\xff\xd0'              # call GetProcessHeap
            + b'\x48\x89\xc1'          # mov rcx, rax
            + b'\x4c\x89\xd2'          # mov rdx, r10
            + b'\x4d\x89\xd8'          # mov r8, r11
            + b'\x48\xb8' + struct.pack('<Q', hal)
            + b'\x48\x8b\x00'          # mov rax, [rax]
            + b'\xff\xd0'              # call HeapAlloc
            + b'\x4c\x89\xec'          # mov rsp, r13
            + b'\x41\x5d'              # pop r13
            + b'\xc3'                  # ret
        )
        if len(patch) > end - off:
            return 0
        patch += b'\x90' * (end - off - len(patch))
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_heap_call_8fea(self, out: bytearray) -> int:
        """cmd main: heap helper call must land at 0x2E357 entry, not mid-body 0x2E33B."""
        if not self.text_rva:
            return 0
        call_off = 0x8FEA - self.text_rva
        good_tgt = 0x2E357 - self.text_rva
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        rel = good_tgt - (call_off + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        cur = struct.unpack_from('<i', out, call_off + 1)[0]
        if call_off + 5 + cur == good_tgt:
            return 0
        out[call_off + 1:call_off + 5] = struct.pack('<i', rel)
        return 1

    def _fix_cmd_fn6314_wcsrchr_null_skip(self, out: bytearray) -> int:
        """After wcsrchr, skip store when RAX==0 (do not rely on zeroed EDI)."""
        if not self.text_rva:
            return 0
        off = 0x2DCAB - self.text_rva
        if off < 0 or off + 8 > len(out):
            return 0
        good = (b'\x85\xc0' + b'\x74\x03' + b'\x90' * 4)  # test eax,eax; je +3; nop sled
        old = b'\x39\xf8' + b'\x0f\x84\x03\x00\x00\x00'
        broken = b'\x85\xc0\x90' + b'\x84\x03\x00\x00\x00'
        if out[off:off + 8] == good:
            return 0
        if out[off:off + 8] in (old, broken):
            out[off:off + 8] = good
            return 1
        return 0

    def _fix_cmd_fn6314_call_14412(self, out: bytearray, fn6314: int,
                                   rva_map: Optional[Dict[int, int]] = None) -> int:
        """fn6314 path-helper call (x86 0x6335→0x14412): restore real callee, not xor eax stub."""
        if not self.text_rva:
            return 0
        if rva_map is None:
            rva_map = self.rva_map or None
        if not rva_map:
            return 0
        entry = self._entry_for_x86_target(out, 0x14412, rva_map)
        if entry is None:
            return 0
        call_off = fn6314 + 0x4D
        if call_off + 5 > len(out):
            return 0
        fixed = 0
        rel = entry - (call_off + 5)
        call_patch = b'\xe8' + struct.pack('<i', rel)
        if out[call_off:call_off + 5] != call_patch:
            out[call_off:call_off + 5] = call_patch
            fixed += 1
        arg_off = fn6314 + 0x39
        if arg_off + 3 <= len(out) and out[arg_off:arg_off + 3] == b'\x41\x8b\x0a':
            out[arg_off:arg_off + 3] = b'\x4c\x89\xd1'  # mov rcx, r10
            fixed += 1
        rdx_off = fn6314 + 0x3D
        if rdx_off + 3 <= len(out) and out[rdx_off:rdx_off + 3] == b'\x48\x31\xd2':
            out[rdx_off:rdx_off + 3] = b'\x48\x89\xf2'  # mov rdx, rsi (x86 6578 result)
            fixed += 1
        fixed += self._snap_call_to_x86_target(out, 0x6335, 0x14412, rva_map)
        return fixed

    def _fix_cmd_init_env_rsi(self, out: bytearray) -> int:
        """Legacy hook: keep ``mov rsi, rax`` after env load."""
        return 0

    def _fix_cmd_crt_init_fail_jmp(self, out: bytearray) -> int:
        """CRT/fn6314 completion must enter cmd main (0x8EB9), not ``ret``/init loop."""
        if not self.text_rva:
            return 0
        main = 0x8EB9 - self.text_rva
        fixed = 0
        jmp35_off = 0x2DC35 - self.text_rva
        if (0 <= jmp35_off + 5 <= len(out) and out[jmp35_off] == 0xE9
                and jmp35_off + 5 + struct.unpack_from('<i', out, jmp35_off + 1)[0]
                == 0x2DC3D - self.text_rva):
            struct.pack_into('<i', out, jmp35_off + 1, main - (jmp35_off + 5))
            fixed += 1
        ret_off = 0x2DC41 - self.text_rva
        if 0 <= ret_off < len(out) and out[ret_off] == 0xC3:
            rel = main - (ret_off + 5)
            if -2147483648 <= rel <= 2147483647:
                out[ret_off:ret_off + 5] = b'\xe9' + struct.pack('<i', rel)
                fixed += 1
        return fixed

    def _fix_cmd_crt_reach_main(self, out: bytearray) -> int:
        """Retarget CRT startup jmps into the 0x2D9A9 loop to cmd main (0x8EB9)."""
        if not self.text_rva:
            return 0
        main = 0x8EB9 - self.text_rva
        loop_targets = {0x2D9A9 - self.text_rva, 0x2D9A1 - self.text_rva}
        fixed = 0
        for jmp_rva in (0x8E26, 0x8E49, 0x8E61, 0x8E74):
            off = jmp_rva - self.text_rva
            if off < 0 or off + 5 > len(out) or out[off] != 0xE9:
                continue
            rel = struct.unpack_from('<i', out, off + 1)[0]
            if off + 5 + rel not in loop_targets:
                continue
            struct.pack_into('<i', out, off + 1, main - (off + 5))
            fixed += 1
        return fixed

    def _fix_cmd_main_tail_scope_hole(self, out: bytearray,
                                      rva_map: Optional[Dict[int, int]] = None) -> int:
        """Relocate SEH scope clobbering 0x3FDA0 and translate the missing x86 tail."""
        if not self.text_rva or rva_map is None:
            return 0
        hole_rva = 0x3FDA0
        partial_rva = 0x3FD62
        partial_end_rva = 0x3FD9D
        hole_off = hole_rva - self.text_rva
        if hole_off < 0 or hole_off + 16 > len(out):
            return 0
        if out[hole_off:hole_off + 4] != b'\xff\xff\xff\xff':
            return 0
        sec = self.pe.section_for_rva(0xDBB0)
        if not sec:
            return 0
        text_data = self.pe.get_section_data(sec)
        x86_end = 0xDE99
        e_off = x86_end - sec['vaddr']
        if e_off > len(text_data):
            return 0
        partial_start_off = partial_rva - self.text_rva
        partial_end_off = partial_end_rva - self.text_rva
        inferred = None
        best_off = -1
        for old_r, off in rva_map.items():
            if (partial_start_off - 0x80 <= off <= partial_end_off
                    and off > best_off):
                best_off = off
                inferred = old_r + (partial_end_off - off)
        candidates: List[int] = []
        if inferred is not None:
            candidates.append(inferred)
        for c in (0xDDA3, 0xDD80, 0xDCEE,
                  0xDBB0 + (hole_rva - partial_rva)):
            if c not in candidates:
                candidates.append(c)
        chunk_out = b''
        chunk_map: Dict[int, int] = {}
        x86_tail = 0
        for try_tail in candidates:
            t_off = try_tail - sec['vaddr']
            if t_off < 0 or e_off <= t_off:
                continue
            blob = text_data[t_off:e_off]
            chunk_out, chunk_map = self._translate_function(
                try_tail, blob, False, 0, chunk_base=hole_off,
                section_rva=self.text_rva, global_rva_map=rva_map,
                deferred_branches=[])
            if chunk_out and len(chunk_out) <= 0x1000:
                x86_tail = try_tail
                break
        else:
            return 0
        scope_len = self._materialized_scope_byte_size(out, hole_off)
        scope_bytes = bytes(out[hole_off:hole_off + scope_len])
        sled = self._find_scope_reloc_sled(out, scope_len, hole_off)
        if sled is None:
            out.extend(b'\x00' * (scope_len + 0x40))
            sled = len(out) - scope_len
        out[sled:sled + scope_len] = scope_bytes
        for i, (start, size) in enumerate(self._scope_table_out_ranges):
            if start == hole_off:
                self._scope_table_out_ranges[i] = (sled, scope_len)
                break
        else:
            self._scope_table_out_ranges.append((sled, scope_len))
        if hole_off in self._scope_table_old_rva:
            self._scope_table_old_rva[sled] = self._scope_table_old_rva.pop(hole_off)
        old_imm = self.new_base + self.text_rva + hole_off
        new_imm = self.new_base + self.text_rva + sled
        for i in range(len(out) - 9):
            if out[i] in (0x48, 0x49) and 0xB8 <= out[i + 1] <= 0xBF:
                imm = struct.unpack_from('<Q', out, i + 2)[0]
                if imm == old_imm:
                    struct.pack_into('<Q', out, i + 2, new_imm)
        out[hole_off:hole_off + len(chunk_out)] = chunk_out
        if hole_off + len(chunk_out) < hole_off + scope_len:
            out[hole_off + len(chunk_out):hole_off + scope_len] = (
                b'\x90' * (scope_len - len(chunk_out)))
        rva_map[x86_tail] = hole_off
        for old_va, rel in chunk_map.items():
            old_r = old_va - self.old_base
            if old_r not in rva_map:
                rva_map[old_r] = hole_off + rel
        fn_off = self._fn_blob_off_from_push(out, sled)
        self._patch_scope_table_entries(out, sled, scope_len, None, fn_off)
        return 1

    def _fix_cmd_main_getcommandline_call(self, out: bytearray) -> int:
        """cmd main: ``call [GetCommandLineW]`` instead of broken aligned helper."""
        if not self.text_rva:
            return 0
        old_iat = self.old_base + 0x10A4  # KERNEL32!GetCommandLineW
        iat_va = self._resolve_iat_slot_va(old_iat)
        fixed = 0
        # Legacy stub head at 0x8EDE (push r13 …).
        stub_off = 0x8EDE - self.text_rva
        stub_end = 0x8EF8 - self.text_rva
        if (stub_off >= 0 and stub_end <= len(out) and out[stub_off:stub_off + 2] == b'\x41\x55'):
            call_rva = self.text_rva + stub_off
            rel = iat_va - (self.new_base + call_rva + 6)
            if -2147483648 <= rel <= 2147483647:
                span = stub_end - stub_off
                patch = (b'\xff\x15' + struct.pack('<i', rel)
                         + b'\x48\x89\xc3' + b'\x90' * (span - 9))
                if len(patch) == span and out[stub_off:stub_end] != patch:
                    out[stub_off:stub_end] = patch
                    fixed += 1
        # Current layout: bare ff15 at 0x8EE1 + NOP sled + mov rbx,rax at 0x8EF8.
        align_off = 0x8EE1 - self.text_rva
        mov_off = 0x8EF8 - self.text_rva
        je_off = 0x8EFD - self.text_rva
        if (align_off >= 0 and mov_off + 3 <= len(out)
                and out[align_off:align_off + 2] == b'\xff\x15'
                and out[mov_off:mov_off + 3] == b'\x48\x89\xc3'):
            call_rva = self.text_rva + align_off + 13  # ff15 after r13 align prologue
            rel = iat_va - (self.new_base + call_rva + 6)
            je_tgt = 0x8F2F
            pro = (
                b'\x41\x55\x49\x89\xe5'
                b'\x48\x83\xec\x20\x48\x83\xe4\xf0'
            )
            tail = b'\x4c\x89\xec\x41\x5d\x48\x89\xc3\x39\xfb'
            je_pos = align_off + len(pro) + 6 + len(tail)
            je_rel = je_tgt - (self.text_rva + je_pos + 6)
            if -2147483648 <= rel <= 2147483647 and -2147483648 <= je_rel <= 2147483647:
                patch = (
                    pro
                    + b'\xff\x15' + struct.pack('<i', rel)
                    + tail
                    + b'\x0f\x84' + struct.pack('<i', je_rel)
                )
                span_end = align_off + len(patch)
                if span_end <= len(out) and out[align_off:span_end] != patch:
                    out[align_off:span_end] = patch
                    fixed += 1
        # Win10 cmd main: GetCommandLineW (or PEB) + test/je + wcslen via CRT stub 0x3D4B.
        peb_off = 0x8EE1 - self.text_rva
        block_end_rva = 0x8F23
        block_end = block_end_rva - self.text_rva
        stub_rva = 0x3D4B
        cont_rva = 0x8F61
        if peb_off >= 0 and block_end <= len(out):
            if self.win10_test_shim:
                getcmd = self._loader_iat_va('KERNEL32.dll', 'GetCommandLineW')
                if not getcmd:
                    getcmd = self._resolve_iat_slot_va(self.old_base + 0x10A4)
                ff_rva = self.text_rva + peb_off
                ff_rel = getcmd - (self.new_base + ff_rva + 6)
                if not (-2147483648 <= ff_rel <= 2147483647):
                    return fixed
                block_head = (
                    b'\xff\x15' + struct.pack('<i', ff_rel)
                    + b'\x48\x89\xc3'
                    + b'\x48\x85\xdb'
                )
            else:
                block_head = (
                    b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00'
                    + b'\x48\x8b\x40\x20'
                    + b'\x48\x8b\x80\x78\x00\x00\x00'
                    + b'\x48\x89\xc3'
                    + b'\x48\x85\xdb'
                )
            je_from_rva = self.text_rva + peb_off + len(block_head)
            je_rel = 0x8F2F - (je_from_rva + 6)
            call_from_rva = je_from_rva + 6 + 3 + 3   # after je, mov rcx, mov rsi
            if self.win10_test_shim:
                block_tail = (
                    b'\x48\x89\xd9'
                    + b'\x48\x89\xce'
                    + b'\x31\xc0'
                    + b'\x89\x45\x10'
                )
            else:
                call_rel = stub_rva - (call_from_rva + 5)
                if not (-2147483648 <= call_rel <= 2147483647):
                    return fixed
                block_tail = (
                    b'\x48\x89\xd9'
                    + b'\x48\x89\xce'
                    + b'\xe8' + struct.pack('<i', call_rel)
                    + b'\x89\x45\x10'
                )
            jmp_from_rva = self.text_rva + peb_off + len(block_head) + 6 + len(block_tail)
            null_jmp_rel = cont_rva - (0x8F32 + 5)
            outer_jmp_rel = cont_rva - (jmp_from_rva + 5)
            if not (-2147483648 <= je_rel <= 2147483647
                    and -2147483648 <= null_jmp_rel <= 2147483647
                    and -2147483648 <= outer_jmp_rel <= 2147483647):
                return fixed
            block = (
                block_head
                + b'\x0f\x84' + struct.pack('<i', je_rel)
                + block_tail
                + b'\xe9' + struct.pack('<i', outer_jmp_rel)
            )
            pad_len = (block_end - peb_off) - len(block)
            if pad_len < 0:
                return fixed
            if pad_len > 0:
                block += b'\x90' * pad_len
            if len(block) == block_end - peb_off and out[peb_off:block_end] != block:
                out[peb_off:block_end] = block
                fixed += 1
            null_off = 0x8F2F - self.text_rva
            pad_off = block_end
            if null_off + 8 <= len(out):
                if pad_off < null_off:
                    out[pad_off:null_off] = b'\x90' * (null_off - pad_off)
                null_tail = b'\x89\x7d\x10' + b'\xe9' + struct.pack('<i', null_jmp_rel)
                if out[null_off:null_off + 8] != null_tail:
                    out[null_off:null_off + 8] = null_tail
                    fixed += 1
        return fixed

    def _fix_cmd_main_post_cmdline_overlap(self, out: bytearray) -> int:
        """NOP stale wcslen-tail shards at 0x8F37..0x8F60; cmp [r11] -> cmp [rbx],0."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        fixed = 0
        slab_off = 0x8F37 - self.text_rva
        slab_end = 0x8F61 - self.text_rva
        if slab_off >= 0 and slab_end <= len(out):
            want = b'\x90' * (slab_end - slab_off)
            if out[slab_off:slab_end] != want:
                out[slab_off:slab_end] = want
                fixed += 1
        cmp_off = 0x8F61 - self.text_rva
        if cmp_off + 4 <= len(out) and out[cmp_off:cmp_off + 4] == b'\x41\x80\x3b\x00':
            if out[cmp_off:cmp_off + 4] != b'\x80\x3b\x00\x90':
                out[cmp_off:cmp_off + 4] = b'\x80\x3b\x00\x90'
                fixed += 1
        return fixed

    def _fix_cmd_main_peb_wcslen_stub_call(self, out: bytearray) -> int:
        """Re-snap PEB-block ``call`` to wcslen stub 0x3D4B after late blob fixups."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        call_off = -1
        scan_end = min(len(out), peb_off + 0x45)
        for i in range(peb_off, scan_end - 5):
            if out[i] == 0xE8 and i >= 3 and out[i - 3:i] == b'\x48\x89\xce':
                call_off = i
                break
        if call_off < 0:
            return 0
        call_rva = self.text_rva + call_off
        want = 0x3D4B - (call_rva + 5)
        if struct.unpack_from('<i', out, call_off + 1)[0] == want:
            return 0
        struct.pack_into('<i', out, call_off + 1, want)
        return 1

    def _fix_cmd_main_early_dispatch_8f61(self, out: bytearray) -> int:
        """Restore /c probe + wcsncmp path at 0x8F61 (overlap-safe, no r13 align)."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        stub_off = 0x8F61 - self.text_rva
        stub_end = 0x8FCC - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        ncmp_iat = self._resolve_iat_slot_va(self.old_base + 0x1288)
        slash_c_va = struct.pack('<Q', self.new_base + 0x41484)
        comspec_va = struct.pack('<Q', self.new_base + 0x41608)
        patch_head = (
            b'\x80\x3b\x00'
            + b'\x0f\x84' + struct.pack('<i', stub_end - (stub_off + 3 + 6))
            + b'\x48\x89\xd9'
            + b'\x48\xba' + slash_c_va
            + b'\x49\xc7\xc0\x04\x00\x00\x00'
            + b'\x48\x83\xec\x28'
        )
        ncmp_call_rva = self.text_rva + stub_off + len(patch_head)
        ncmp_rel = ncmp_iat - (self.new_base + ncmp_call_rva + 6)
        patch_mid = (
            b'\xff\x15' + struct.pack('<i', ncmp_rel)
            + b'\x48\x83\xc4\x28'
            + b'\x85\xc0'
            + b'\x0f\x85' + struct.pack('<i', stub_end - (stub_off + len(patch_head) + 6 + 4 + 2 + 6))
            + b'\x48\xb9' + comspec_va
            + b'\x48\x83\xec\x28'
        )
        helper_call_rva = self.text_rva + stub_off + len(patch_head) + len(patch_mid)
        helper_rel = 0x2CF0B - (helper_call_rva + 5)
        patch = (
            patch_head
            + patch_mid
            + b'\xe8' + struct.pack('<i', helper_rel)
            + b'\x48\x83\xc4\x28'
            + b'\x48\x89\xc3'
        )
        if not all(-2147483648 <= v <= 2147483647
                   for v in (ncmp_rel, helper_rel)):
            return 0
        pad = stub_end - stub_off - len(patch)
        if pad < 0:
            return 0
        patch += b'\x90' * pad
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_main_win10_cmdline_gate_8f61(self, out: bytearray) -> int:
        """Win10: cmp/je + jmp to 0x8FCC; leaves echo cave at 0x8F6F intact."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        head_off = 0x8F61 - self.text_rva
        head_end = 0x8F6F - self.text_rva
        token_rva = 0x8FCC
        if head_off < 0 or head_end <= head_off or head_end > len(out):
            return 0
        je_from = 0x8F61 + 3
        jmp_from = 0x8F6A
        je_rel = token_rva - (je_from + 6)
        jmp_rel = token_rva - (jmp_from + 5)
        if not (-2147483648 <= je_rel <= 2147483647
                and -2147483648 <= jmp_rel <= 2147483647):
            return 0
        patch = (
            b'\x80\x3b\x00'
            + b'\x0f\x84' + struct.pack('<i', je_rel)
            + b'\xe9' + struct.pack('<i', jmp_rel)
        )
        if len(patch) != head_end - head_off:
            return 0
        if out[head_off:head_end] == patch:
            return 0
        out[head_off:head_end] = patch
        return 1

    def _fix_cmd_main_wcslen_tail_8f0c(self, out: bytearray) -> int:
        """After main ``ff15`` wcslen at 0x8F06, drop tail garbage and orphan align epilogue."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off >= 0 and out[peb_off:peb_off + 2] in (b'\x65\x48', b'\xff\x15'):
            return 0  # cmdline block owns main+0x8EE1..0x8F27
        mov_off = 0x8F0C - self.text_rva
        call_off = 0x8F20 - self.text_rva
        epi_off = 0x8F22 - self.text_rva
        wc_off = 0x8F06 - self.text_rva
        fixed = 0
        if (wc_off >= 0 and wc_off + 2 <= len(out) and out[wc_off:wc_off + 2] == b'\xff\x15'):
            old_iat = self.old_base + 0x11D8  # MSVCRT!wcslen
            iat_va = self._resolve_iat_slot_va(old_iat)
            call_rva = self.text_rva + wc_off
            rel = iat_va - (self.new_base + call_rva + 6)
            if -2147483648 <= rel <= 2147483647:
                want = struct.pack('<i', rel)
                if out[wc_off + 2:wc_off + 6] != want:
                    out[wc_off + 2:wc_off + 6] = want
                    fixed += 1
        if mov_off >= 0 and mov_off + 3 <= len(out) and out[mov_off:mov_off + 3] == b'\x48\x89\xc3':
            out[mov_off:mov_off + 3] = b'\x90\x90\x90'
            fixed += 1
        if call_off >= 0 and call_off + 2 <= len(out) and out[call_off:call_off + 2] == b'\xff\xd0':
            out[call_off:call_off + 2] = b'\x90\x90'
            fixed += 1
        if (epi_off >= 0 and epi_off + 5 <= len(out)
                and out[epi_off:epi_off + 5] == b'\x4c\x89\xec\x41\x5d'):
            out[epi_off:epi_off + 5] = b'\x90' * 5
            fixed += 1
        return fixed

    def _fix_cmd_main_wcslen_call(self, out: bytearray) -> int:
        """Restore cmd main wcslen ``FF15`` (aligned stub or direct call at 0x8F06)."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off >= 0 and out[peb_off:peb_off + 2] in (b'\x65\x48', b'\xff\x15'):
            return 0
        old_iat = self.old_base + 0x11D8  # MSVCRT!wcslen
        iat_va = self._resolve_iat_slot_va(old_iat)
        fixed = 0
        # Direct ``mov rcx,rbx; ff15`` at 0x8F03 (current layout).
        direct_off = 0x8F06 - self.text_rva
        head_off = 0x8F03 - self.text_rva
        if (head_off >= 0 and direct_off + 6 <= len(out)
                and out[head_off:head_off + 3] == b'\x48\x89\xd9'
                and out[direct_off:direct_off + 2] == b'\xff\x15'):
            call_rva = self.text_rva + direct_off
            rel = iat_va - (self.new_base + call_rva + 6)
            if -2147483648 <= rel <= 2147483647:
                want = struct.pack('<i', rel)
                if out[direct_off + 2:direct_off + 6] != want:
                    out[direct_off + 2:direct_off + 6] = want
                    fixed += 1
        # Legacy aligned stub at 0x8F03 with ``ff15`` at 0x8F10.
        stub_off = 0x8F03 - self.text_rva
        call_off = 0x8F10 - self.text_rva
        stub_end = 0x8F24 - self.text_rva
        pre_off = 0x8F00 - self.text_rva
        if (stub_off >= 0 and call_off >= 0 and stub_end <= len(out)
                and pre_off >= 0 and pre_off + 3 <= len(out)
                and out[pre_off:pre_off + 3] == b'\x48\x89\xd9'
                and out[stub_off:stub_off + 2] == b'\x41\x55'):
            rel = iat_va - (self.new_base + self.text_rva + call_off + 6)
            if -2147483648 <= rel <= 2147483647:
                span = stub_end - stub_off
                patch = (b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'
                         + b'\xff\x15' + struct.pack('<i', rel)
                         + b'\x90' * 9 + b'\x4c\x89\xec\x41\x5d')
                if len(patch) == span and out[stub_off:stub_end] != patch:
                    out[stub_off:stub_end] = patch
                    fixed += 1
        return fixed

    def _fix_cmd_main_token_parse_call(self, out: bytearray) -> int:
        """cmd main: call translated token parser (x86 0x89FF @ 0xB5C3), copy to stack buf."""
        if not self.text_rva:
            return 0
        stub_off = 0x8FC9 - self.text_rva
        stub_end = 0x9038 - self.text_rva
        parse_off = 0xB5C3 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out) or parse_off < 0:
            return 0
        head_mov = b'\x48\x89\xd9'
        head_lea = b'\x48\x8d\x85\xd8\xfd\xff\xff'
        call_off = 0x8FEA - self.text_rva
        applicable = out[stub_off:stub_off + len(head_mov)] == head_mov
        if not applicable:
            applicable = out[stub_off:stub_off + len(head_lea)] == head_lea
        if not applicable and call_off + 5 <= len(out) and out[call_off] == 0xE8:
            rel = struct.unpack_from('<i', out, call_off + 1)[0]
            tgt = call_off + 5 + rel
            applicable = tgt in (
                0x2E3F5 - self.text_rva,
                0x2E357 - self.text_rva,
                0x2E33B - self.text_rva,
            )
        if not applicable:
            return 0
        old_iat = self.old_base + 0x121C  # MSVCRT!wcsncpy
        iat_va = self._resolve_iat_slot_va(old_iat)
        rel1 = parse_off - (stub_off + 12)
        call2_rva = self.text_rva + stub_off + 36
        rel2 = iat_va - (self.new_base + call2_rva + 6)
        if not (-2147483648 <= rel1 <= 2147483647
                and -2147483648 <= rel2 <= 2147483647):
            return 0
        span = stub_end - stub_off
        patch = (
            b'\x48\x89\xd9'                              # mov rcx, rbx
            + b'\x48\x8d\x55\xdc'                        # lea rdx, [rbp-0x24]
            + b'\xe8' + struct.pack('<i', rel1)          # call parse_fn
            + b'\x48\x8d\x8d\xd8\xfd\xff\xff'            # lea rcx, [rbp-0x228]
            + b'\x48\xba\xc8\x16\x00\x80\x00\x00\x00\x00'  # movabs rdx, global token
            + b'\x41\xc7\xc0\x04\x01\x00\x00'            # mov r8d, 0x104
            + b'\xff\x15' + struct.pack('<i', rel2)     # call wcsncpy
        )
        if len(patch) > span:
            return 0
        patch += b'\x90' * (span - len(patch))
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_main_token_parse_8fcc(self, out: bytearray) -> int:
        """Snap token parse at 0x8FCC off mid-body 0x2E35C to parser 0xB5C6 + wcsncpy."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        stub_off = 0x8FCC - self.text_rva
        stub_end = 0x9038 - self.text_rva
        parse_off = 0xB5C6 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out) or parse_off < 0:
            return 0
        head = out[stub_off:stub_off + 3]
        if not (head in (b'\x48\x8d\x85', b'\x48\x89\xd9', b'\x49\x89\xfb', b'\x53',
                         b'\x48\x83\xec')
                or head[:2] == b'\xc7\x05'):
            return 0
        old_iat = self.old_base + 0x121C  # MSVCRT!wcsncpy
        wcsncpy_iat = self._loader_iat_va('MSVCRT.dll', 'wcsncpy')
        if not wcsncpy_iat:
            wcsncpy_iat = self._resolve_iat_slot_va(old_iat)
        patch_head = b''
        if self.win10_test_shim:
            flag_rva = 0x41F58
            mov_at = 0x8FCC
            mov_end = mov_at + 10
            patch_head += (
                b'\xc7\x05' + struct.pack('<i', flag_rva - mov_end) + b'\x01\x00\x00\x00'
            )
        patch_head += (
            b'\x53'                                      # push rbx
            + b'\x48\x8d\x8d\xd8\xfd\xff\xff'           # lea rcx, [rbp-0x228]
            + b'\x48\x89\xf2'                         # mov rdx, rsi (cmdline)
        )
        call2_rva = 0x8FCC + len(patch_head) + 10       # after xor r8d + mov r8d,0x104
        pop_rva = call2_rva + 6
        jmp_from = pop_rva + 1
        rel2 = wcsncpy_iat - (self.new_base + call2_rva + 6)
        jmp_rel = (0x9072 if self.win10_test_shim else 0x9040) - (jmp_from + 5)
        if not (-2147483648 <= rel2 <= 2147483647
                and -2147483648 <= jmp_rel <= 2147483647):
            return 0
        patch = (
            patch_head
            + b'\x45\x31\xc0'                        # xor r8d, r8d
            + b'\x41\xc7\xc0\x04\x01\x00\x00'        # mov r8d, 0x104
            + b'\xff\x15' + struct.pack('<i', rel2)
            + b'\x5b'                                      # pop rbx
            + b'\xe9' + struct.pack('<i', jmp_rel)
        )
        pad = stub_end - stub_off - len(patch)
        if pad < 0:
            return 0
        patch += b'\x90' * pad
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_skip_wcsncpy_jmp_drive_8fd6(self, out: bytearray) -> int:
        """Route 0x8FD6: /c -> echo stub; else RBX cmdline -> drive scan (skip bad [rbp-0x228] wcsncpy)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        check_rva = 0x9045
        echo_rva = 0x8F6F
        drive_rva = 0x9072
        stub_rva = 0x8FD6
        stub_end = 0x8FF2
        check_end = 0x9072
        stub_off = stub_rva - self.text_rva
        end_off = stub_end - self.text_rva
        check_off = check_rva - self.text_rva
        check_end_off = check_end - self.text_rva
        if stub_off < 0 or end_off > len(out) or check_off < 0 or check_end_off > len(out):
            return 0
        chk = bytearray()
        # Inline scan for L"/c" in RBX (no wcsstr — AV on interactive SEH path).
        chk.extend(
            b'\x48\x89\xde'              # mov rsi, rbx
            + b'\x0f\xb7\x06'            # movzx eax, word [rsi]
            + b'\x66\x85\xc0'            # test ax, ax
            + b'\x74'                    # jz drive
        )
        jz_drive = len(chk)
        chk.append(0x00)
        chk.extend(
            b'\x66\x3d\x2f\x00'          # cmp ax, '/'
            + b'\x75'                    # jne adv
        )
        jne_adv = len(chk)
        chk.append(0x00)
        chk.extend(
            b'\x66\x81\x7e\x02\x63\x00'  # cmp word [rsi+2], 'c'
            + b'\x75'                    # jne adv
        )
        jne_adv2 = len(chk)
        chk.append(0x00)
        chk.extend(
            b'\xe9'                      # jmp echo
        )
        jmp_echo_at = len(chk)
        chk.extend(b'\x00\x00\x00\x00')
        adv_rva = check_rva + len(chk)
        chk.extend(
            b'\x48\x83\xc6\x02'          # add rsi, 2
            + b'\xeb'                    # jmp scan
        )
        jmp_scan_at = len(chk)
        chk.append(0x00)
        drive_rva_off = check_rva + len(chk)
        chk.extend(
            b'\x48\x89\xde'              # mov rsi, rbx
            + b'\xe9'                    # jmp drive
        )
        jmp_drive_at = len(chk)
        chk.extend(b'\x00\x00\x00\x00')
        scan_loop = check_rva + 3
        chk[jz_drive] = (drive_rva_off - (check_rva + jz_drive + 1)) & 0xFF
        chk[jne_adv] = (adv_rva - (check_rva + jne_adv + 1)) & 0xFF
        chk[jne_adv2] = (adv_rva - (check_rva + jne_adv2 + 1)) & 0xFF
        struct.pack_into('<i', chk, jmp_echo_at, echo_rva - (check_rva + jmp_echo_at + 4))
        chk[jmp_scan_at] = (scan_loop - (check_rva + jmp_scan_at + 1)) & 0xFF
        struct.pack_into('<i', chk, jmp_drive_at, drive_rva - (check_rva + jmp_drive_at + 4))
        if check_off + len(chk) > check_end_off:
            return 0
        entry_rel = check_rva - (stub_rva + 5)
        if not (-2147483648 <= entry_rel <= 2147483647):
            return 0
        entry = b'\xe9' + struct.pack('<i', entry_rel)
        span = stub_end - stub_rva
        if len(entry) > span:
            return 0
        head = entry + b'\x90' * (span - len(entry))
        fixed = 0
        if out[stub_off:end_off] != head:
            out[stub_off:end_off] = head
            fixed += 1
        pad = check_end_off - check_off - len(chk)
        body = bytes(chk) + (b'\x90' * pad if pad > 0 else b'')
        if out[check_off:check_end_off] != body:
            out[check_off:check_end_off] = body
            fixed += 1
        return fixed

    def _fix_cmd_main_skip_spurious_parse_calls(self, out: bytearray) -> int:
        """NOP broken aligned-call stub before drive-letter parse (malloc tail call)."""
        if not self.text_rva:
            return 0
        stub_off = 0x905B - self.text_rva
        stub_end = 0x9072 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        patch = b'\x90' * (stub_end - stub_off)
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_main_drive_letter_path(self, out: bytearray) -> int:
        """Build L\"X:\\\" at [rbp-0x20] from copied cmdline at [rbp-0x228] (0x9072)."""
        if not self.text_rva:
            return 0
        stub_off = 0x9072 - self.text_rva
        stub_end = 0x90BF - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        body = (
            b'\x48\x8d\xb5\xd8\xfd\xff\xff'           # lea rsi, [rbp-0x228]
            + b'\x0f\xb7\x06'                         # movzx eax, word [rsi]
            + b'\x66\x83\xf8\x22'                     # cmp ax, '"'
            + b'\x75\x04'                             # jne skip_quote
            + b'\x48\x83\xc6\x02'                     # add rsi, 2
            + b'\x0f\xb7\x06'                         # movzx eax, word [rsi]
            + b'\x66\x89\x45\xe0'                     # mov [rbp-0x20], ax
            + b'\x66\xc7\x45\xe2\x3a\x00'             # mov word [rbp-0x1e], ':'
            + b'\x66\xc7\x45\xe4\x5c\x00'             # mov word [rbp-0x1c], '\\'
            + b'\x66\xc7\x45\xe6\x00\x00'             # mov word [rbp-0x1a], 0
        )
        jmp_off = 0x90BA - self.text_rva
        jmp_rel = 0x90E9 - (0x90BA + 5)
        if not (-2147483648 <= jmp_rel <= 2147483647):
            return 0
        pad = jmp_off - (stub_off + len(body))
        if pad < 0:
            return 0
        tail = b'\x90' * pad + b'\xe9' + struct.pack('<i', jmp_rel)
        patch = body + tail
        if len(patch) != stub_end - stub_off:
            return 0
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_drive_prompt_slot_copy_90c0(self, out: bytearray) -> int:
        """Copy L\"X:\\\" to 0x414B0+L\"> \" then jmp interactive startup cave (skip batch/switch)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        jmp_off = 0x90BA - self.text_rva
        cave_off = 0x90C0 - self.text_rva
        cave_end = 0x90E9 - self.text_rva
        gate_off = 0x91B5 - self.text_rva
        if jmp_off < 0 or cave_end <= cave_off or cave_end > len(out):
            return 0
        slot = self.new_base + 0x414B0
        body = bytearray()
        body += b'\x48\x8d\x75\xe0'
        body += b'\x48\xbf' + struct.pack('<Q', slot)
        body += b'\x48\x8b\x06'
        body += b'\x48\x89\x07'
        body += b'\xc7\x47\x06\x3e\x00\x20\x00'
        jmp_from = 0x90C0 + len(body)
        startup = self._cmd_interactive_startup_rva or 0x90E9
        body += b'\xe9' + struct.pack('<i', startup - (jmp_from + 5))
        if len(body) > cave_end - cave_off:
            return 0
        jmp_rel = 0x90C0 - (0x90BA + 5)
        if not (-2147483648 <= jmp_rel <= 2147483647):
            return 0
        fixed = 0
        patch = body + b'\x90' * (cave_end - cave_off - len(body))
        if out[cave_off:cave_end] != patch:
            out[cave_off:cave_end] = patch
            fixed += 1
        want_jmp = b'\xe9' + struct.pack('<i', jmp_rel)
        if out[jmp_off:jmp_off + 5] != want_jmp:
            out[jmp_off:jmp_off + 5] = want_jmp
            fixed += 1
        return fixed

    def _fix_cmd_main_batch_arg_mov(self, out: bytearray) -> int:
        """Before batch setup call (0x2B3E9), pass cmdline in RDX not stale RAX."""
        if not self.text_rva:
            return 0
        off = 0x90E9 - self.text_rva
        if off < 0 or off + 3 > len(out):
            return 0
        patch = b'\x48\x89\xda'  # mov rdx, rbx
        if out[off:off + 3] == patch:
            return 0
        if out[off:off + 3] != b'\x48\x89\xc2':
            return 0
        out[off:off + 3] = patch
        return 1

    def _fix_cmd_main_skip_batch_setup_call(self, out: bytearray) -> int:
        """Skip misrouted batch helper call (0x2B3E9 mid-body); continue colon scan."""
        if not self.text_rva:
            return 0
        call_off = 0x90F9 - self.text_rva
        bad_off = 0x2B3E9 - self.text_rva
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        rel = struct.unpack_from('<i', out, call_off + 1)[0]
        if call_off + 5 + rel != bad_off:
            if out[call_off:call_off + 2] == b'\x31\xc0':
                return 0
            return 0
        patch = b'\x31\xc0' + b'\x90' * 3  # xor eax, eax; fall through with 0
        if out[call_off:call_off + 5] == patch:
            return 0
        out[call_off:call_off + 5] = patch
        return 1

    def _fix_cmd_main_batch_call_90fc(self, out: bytearray) -> int:
        """Batch helper call at 0x90FC must enter 0x2B3E8, not mid-body 0x2B3DE."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        mov_off = 0x90EC - self.text_rva
        call_off = 0x90FC - self.text_rva
        entry_rva = 0x2B3E8
        fixed = 0
        if mov_off >= 0 and mov_off + 3 <= len(out) and out[mov_off:mov_off + 3] == b'\x48\x89\xc2':
            out[mov_off:mov_off + 3] = b'\x48\x89\xda'
            fixed += 1
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return fixed
        want = entry_rva - (0x90FC + 5)
        if struct.unpack_from('<i', out, call_off + 1)[0] == want:
            return fixed
        if -2147483648 <= want <= 2147483647:
            struct.pack_into('<i', out, call_off + 1, want)
            fixed += 1
        return fixed

    def _fix_cmd_main_skip_batch_path_90ef(self, out: bytearray) -> int:
        """Skip broken batch helper frame at 0x90EF; do not clobber RBX before switch scan."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        stub_off = 0x90EF - self.text_rva
        stub_end = 0x9111 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        if out[stub_off:stub_off + 2] not in (b'\x41\x55', b'\x31\xc0'):
            return 0
        jmp_off = stub_end - 5
        jmp_rel = 0x9111 - ((self.text_rva + jmp_off) + 5)
        patch = (
            b'\x31\xc0'
            + b'\x90' * (jmp_off - stub_off - 2)
            + b'\xe9' + struct.pack('<i', jmp_rel)
        )
        if len(patch) != stub_end - stub_off:
            return 0
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_main_save_cmdline_ptr_8eea(self, out: bytearray) -> int:
        """Persist GetCommandLineW result at [rbp-0x228] for later token scan."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        off = 0x8EEA - self.text_rva
        if off < 0 or off + 10 > len(out) or out[off:off + 3] != b'\x48\x85\xdb':
            return 0
        patch = b'\x48\x89\x9d\xd8\xfd\xff\xff' + b'\x48\x85\xdb'
        if out[off:off + 10] == patch:
            return 0
        out[off:off + 10] = patch
        return 1

    def _fix_cmd_main_skip_to_switch_slash(self, out: bytearray) -> int:
        """Scan cmdline for first L'/' — RBX already holds GetCommandLineW from 0x8EE7."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        stub_rva = 0x9111
        loop_rva = 0x9118
        done_rva = 0x913B
        stub_end_rva = 0x913B
        stub_off = stub_rva - self.text_rva
        stub_end = stub_end_rva - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        je0 = done_rva - (0x911E + 2)
        je1 = done_rva - (0x9124 + 2)
        jloop = loop_rva - (0x912A + 2)
        if not all(-128 <= x <= 127 for x in (je0, je1, jloop)):
            return 0
        head = b'\x90' * 7 if self.win10_test_shim else b'\x48\x8d\x9d\xd8\xfd\xff\xff'
        body = (
            head
            + b'\x0f\xb7\x03'
            + b'\x66\x85\xc0'
            + b'\x74' + struct.pack('b', je0)
            + b'\x66\x3d\x2f\x00'
            + b'\x74' + struct.pack('b', je1)
            + b'\x48\x83\xc3\x02'
            + b'\xeb' + struct.pack('b', jloop)
        )
        pad = stub_end - stub_off - len(body)
        if pad < 0:
            return 0
        patch = body + b'\x90' * pad
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_data_switch_literals(self, out: bytearray, sect_rva: int) -> int:
        """Ensure L\"/c\" exists beside L\"/?\" in .data (RVA 0x4147c)."""
        slash_c_rva = 0x41484
        off = slash_c_rva - sect_rva
        if off < 0 or off + 6 > len(out):
            return 0
        want = b'/\x00c\x00\x00\x00'
        if out[off:off + 6] == want:
            return 0
        out[off:off + 6] = want
        return 1

    def _fix_cmd_data_echo_test_literal(self, out: bytearray, sect_rva: int) -> int:
        """Wide L\"echo \" needle for win10 dynamic echo stub (RVA 0x41490)."""
        msg_rva = 0x41490
        off = msg_rva - sect_rva
        pad = 32
        if off < 0 or off + pad > len(out):
            return 0
        want = 'echo '.encode('utf-16-le') + b'\x00\x00' + b'\x00' * (pad - 12)
        if out[off:off + pad] == want:
            return 0
        out[off:off + pad] = want
        return 1

    def _fix_cmd_data_interactive_banner_line(self, out: bytearray, sect_rva: int) -> int:
        """Wide version banner line for interactive startup (RVA 0x414E0)."""
        msg_rva = 0x414E0
        off = msg_rva - sect_rva
        text = 'Microsoft Windows 2000 [Version 5.00]\r\n'
        want = text.encode('utf-16-le') + b'\x00\x00'
        pad = 96
        if off < 0 or off + pad > len(out):
            return 0
        if len(want) > pad:
            return 0
        body = want + b'\x00' * (pad - len(want))
        if out[off:off + pad] == body:
            return 0
        out[off:off + pad] = body
        return 1

    def _fix_cmd_data_interactive_prompt_literal(self, out: bytearray, sect_rva: int) -> int:
        """Wide L\"C:\\> \" for interactive prompt stub (RVA 0x414B0)."""
        msg_rva = 0x414B0
        off = msg_rva - sect_rva
        want = 'C:\\> '.encode('utf-16-le') + b'\x00\x00'
        if off < 0 or off + len(want) > len(out):
            return 0
        if out[off:off + len(want)] == want:
            return 0
        out[off:off + len(want)] = want
        return 1

    def _fix_cmd_win10_echo_writeconsole(self, out: bytearray) -> int:
        """Win10-test: dynamic /c echo <text> via split stub + jmp from 0x92E7."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        msg_rva = 0x41490
        wcsstr_iat = self._loader_iat_va('MSVCRT.dll', 'wcsstr')
        wcslen_iat = self._loader_iat_va('MSVCRT.dll', 'wcslen')
        if not wcsstr_iat:
            wcsstr_iat = self._resolve_iat_slot_va(self.old_base + 0x12AC)
        if not wcslen_iat:
            wcslen_iat = self._resolve_iat_slot_va(self.old_base + 0x129C)
        getstd = self._loader_iat_va('KERNEL32.dll', 'GetStdHandle')
        writefn = self._loader_iat_va('KERNEL32.dll', 'WriteFile')
        if not writefn:
            writefn = self._loader_iat_va('KERNEL32.dll', 'WriteConsoleW')
        exit_iat = self._loader_iat_va('KERNEL32.dll', 'ExitProcess')
        if not exit_iat:
            exit_iat = self._loader_iat_va('MSVCRT.dll', '_exit')
        if not exit_iat:
            exit_iat = self._loader_iat_va('MSVCRT.dll', 'exit')
        getcl = self._loader_iat_va('KERNEL32.dll', 'GetCommandLineW')
        if not wcsstr_iat or not wcslen_iat or not getcl or not getstd or not writefn or not exit_iat:
            return 0
        if self.win10_test_shim:
            p1_rva = 0x8F6F
            p1_off = p1_rva - self.text_rva
            probe_p1, probe_p2 = self._build_win10_echo_stub_parts(
                p1_rva, 0x8FED, msg_rva, wcsstr_iat, wcslen_iat, getcl,
                getstd, writefn, exit_iat)
            echo_avoid: List[Tuple[int, int]] = [
                (0x8F61, 0x9040),
            ]
            c2 = self._find_text_nop_cave(out, len(probe_p2), avoid=echo_avoid)
            if c2 is not None:
                p2_rva = self.text_rva + c2
                p2_off = c2
            else:
                p2_rva = 0x9330
                p2_off = p2_rva - self.text_rva
            if p1_off < 0 or p2_off < 0 or p2_off + len(probe_p2) > len(out):
                return 0
            if p1_off + len(probe_p1) > (0x8FCC - self.text_rva):
                return 0
            p1, p2 = self._build_win10_echo_stub_parts(
                p1_rva, p2_rva, msg_rva, wcsstr_iat, wcslen_iat, getcl,
                getstd, writefn, exit_iat)
            jmp_off = 0x92E7 - self.text_rva
            if jmp_off < 0 or jmp_off + 5 > len(out):
                return 0
            rel_entry = p1_rva - (0x92E7 + 5)
            if not (-2147483648 <= rel_entry <= 2147483647):
                return 0
            entry = b'\xe9' + struct.pack('<i', rel_entry)
            if (out[p1_off:p1_off + len(p1)] == p1 and out[p2_off:p2_off + len(p2)] == p2
                    and out[jmp_off:jmp_off + 5] == entry):
                return 0
            out[p1_off:p1_off + len(p1)] = p1
            out[p2_off:p2_off + len(p2)] = p2
            out[jmp_off:jmp_off + 5] = entry
            return 1
        probe_p1, probe_p2 = self._build_win10_echo_stub_parts(
            0x50000, 0x50200, msg_rva, wcsstr_iat, wcslen_iat, getcl,
            getstd, writefn, exit_iat)
        if self.win10_test_shim:
            p1_rva = 0x8F6F
            p2_rva = 0x8FED
            p1_off = p1_rva - self.text_rva
            p2_off = p2_rva - self.text_rva
            if p1_off < 0 or p2_off < 0:
                return 0
            if p1_off + len(probe_p1) > (0x8FCC - self.text_rva):
                return 0
            if p2_off + len(probe_p2) > (0x9038 - self.text_rva):
                return 0
        else:
            echo_avoid: List[Tuple[int, int]] = [
                (0x9200, 0x9400),
                (0x8FCC, 0x9040),
            ]
            c1 = self._find_text_nop_cave(out, len(probe_p1), avoid=echo_avoid)
            if c1 is None:
                return 0
            p1_rva = self.text_rva + c1
            avoid2: List[Tuple[int, int]] = echo_avoid + [
                (p1_rva, p1_rva + len(probe_p1)),
            ]
            c2 = self._find_text_nop_cave(out, len(probe_p2), avoid=avoid2)
            if c2 is None:
                return 0
            p2_rva = self.text_rva + c2
            p1_off = c1
            p2_off = c2
        p1, p2 = self._build_win10_echo_stub_parts(
            p1_rva, p2_rva, msg_rva, wcsstr_iat, wcslen_iat, getcl,
            getstd, writefn, exit_iat)
        if len(p1) != len(probe_p1) or len(p2) != len(probe_p2):
            return 0
        if p1_off + len(p1) > len(out) or p2_off + len(p2) > len(out):
            return 0
        jmp_off = 0x92E7 - self.text_rva
        if jmp_off < 0 or jmp_off + 5 > len(out):
            return 0
        rel_entry = p1_rva - (0x92E7 + 5)
        if not (-2147483648 <= rel_entry <= 2147483647):
            return 0
        entry = b'\xe9' + struct.pack('<i', rel_entry)
        if (out[p1_off:p1_off + len(p1)] == p1 and out[p2_off:p2_off + len(p2)] == p2
                and out[jmp_off:jmp_off + 5] == entry):
            return 0
        out[p1_off:p1_off + len(p1)] = p1
        out[p2_off:p2_off + len(p2)] = p2
        out[jmp_off:jmp_off + 5] = entry
        return 1

    def _fix_cmd_win10_interactive_guard_9040(self, out: bytearray) -> int:
        """0x9040: 5-byte jmp to drive-letter path 0x9072 (scanner lives at 0x9045+)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        guard_off = 0x9040 - self.text_rva
        if guard_off < 0 or guard_off + 5 > len(out):
            return 0
        rel = 0x9072 - (0x9040 + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body = b'\xe9' + struct.pack('<i', rel)
        if out[guard_off:guard_off + 5] == body:
            return 0
        out[guard_off:guard_off + 5] = body
        return 1

    def _fix_cmd_main_exec_success_jmp(self, out: bytearray) -> int:
        """After switch handler success (eax!=0), jmp to 0x932F not corrupted 0x92B5 tail."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x92B3 - self.text_rva
        end = 0x92CC - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        rel = (0x932F - self.text_rva) - (off + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (end - off - 5)
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_wcschr_iat_9111(self, out: bytearray) -> int:
        """Replace broken wcschr E8→0x29E3E at 0x9133 with direct FF15 IAT call."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        stub_off = 0x9126 - self.text_rva
        stub_end = 0x913B - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        if out[0x9118 - self.text_rva:0x9118 - self.text_rva + 7] != b'\x48\x8d\x8d\xd8\xfd\xff\xff':
            return 0
        old_iat = self.old_base + 0x1208  # MSVCRT!wcschr
        iat_va = self._resolve_iat_slot_va(old_iat)
        ff_rva = 0x912A
        rel = iat_va - (self.new_base + ff_rva + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = (
            b'\x48\x83\xec\x28'
            + b'\xff\x15' + struct.pack('<i', rel)
            + b'\x48\x83\xc4\x28'
        )
        pad = stub_end - stub_off - len(patch)
        if pad < 0:
            return 0
        patch += b'\x90' * pad
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_switch_handler_entry_1deb4(self, out: bytearray) -> int:
        """NOP stray epilogue bytes at 0x1DEB4; snap E8 targets to real entry 0x1DEB7."""
        if not self.text_rva:
            return 0
        fixed = 0
        junk_off = 0x1DEB4 - self.text_rva
        entry_off = 0x1DEB7 - self.text_rva
        if 0 <= junk_off + 3 <= len(out) and out[junk_off:junk_off + 3] == b'\xec\x5d\xc3':
            out[junk_off:junk_off + 3] = b'\x90\x90\x90'
            fixed += 1
        bad_tgt = 0x1DEB4 - self.text_rva
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            if i + 5 + rel == bad_tgt:
                struct.pack_into('<i', out, i + 1, entry_off - (i + 5))
                fixed += 1
        return fixed

    def _fix_cmd_fn6314_fn6578_call(self, out: bytearray, fn6314: int) -> int:
        """fn6314 loads a global then calls fn6578 (x86 0x6578): RCX arg, not RDX."""
        fn6578 = self._cmd_fn6578_entry_off(out)
        if fn6314 < 0 or fn6578 is None:
            return 0
        fixed = 0
        glob_off = fn6314 + 0x0D
        if (glob_off + 10 <= len(out)
                and out[glob_off:glob_off + 2] == b'\x48\xba'):
            out[glob_off:glob_off + 2] = b'\x48\xb9'  # movabs rcx, imm
            fixed += 1
        call_off = fn6314 + 0x24
        if call_off + 5 <= len(out) and out[call_off] == 0xE8:
            rel = struct.unpack_from('<i', out, call_off + 1)[0]
            if call_off + 5 + rel != fn6578:
                struct.pack_into('<i', out, call_off + 1,
                                 fn6578 - (call_off + 5))
                fixed += 1
        return fixed

    def _fix_cmd_fn6314_helper_calls(self, out: bytearray,
                                     rva_map: Optional[Dict[int, int]] = None) -> int:
        """Snap fn6314 internal helpers via x86↔shim rva_map correspondence."""
        if not self.text_rva:
            return 0
        if rva_map is None:
            rva_map = self.rva_map or None
        if not rva_map:
            return 0
        fn6314 = self._cmd_fn6314_entry_off(out)
        fixed = 0
        if fn6314 is not None:
            fixed += self._fix_cmd_fn6314_fn6578_call(out, fn6314)
        fixed += self._snap_call_to_x86_target(out, 0x633F, 0x195F0, rva_map)
        # fn6314 wcsrchr call (shim RVA 0x2DCA1) — linear map drifts after expansion
        call_off = 0x2DCA1 - self.text_rva
        good = self._entry_for_x86_target(out, 0x195F0, rva_map)
        if (call_off >= 0 and good is not None and call_off + 5 <= len(out)
                and out[call_off] == 0xE8):
            rel = struct.unpack_from('<i', out, call_off + 1)[0]
            if call_off + 5 + rel != good:
                struct.pack_into('<i', out, call_off + 1, good - (call_off + 5))
                fixed += 1
        return fixed

    def _fix_cmd_main_batch_copy_call_args(self, out: bytearray) -> int:
        """Before batch copy call (0x2B056), pass token ptr in RCX and global in RDX."""
        if not self.text_rva:
            return 0
        off = 0x93A6 - self.text_rva
        if off < 0 or off + 6 > len(out):
            return 0
        # mov rcx, rbx; mov rdx, rax — token buffer + cmd global table
        patch = b'\x48\x89\xd9' + b'\x48\x89\xc2'
        if out[off:off + 6] == patch:
            return 0
        if out[off:off + 6] not in (b'\x48\x89\xd9' + b'\x48\x89\xc2',
                                    b'\x48\x89\xc1' + b'\x48\x89\xda'):
            return 0
        out[off:off + 6] = patch
        return 1

    def _fix_cmd_batch_helper_x64_ptr_load(self, out: bytearray) -> int:
        """Batch helper (0x2B056): use qword RDX arg, not dword [rbp+0x18]."""
        if not self.text_rva:
            return 0
        off = 0x2B06E - self.text_rva
        if off < 0 or off + 8 > len(out):
            return 0
        patch = b'\x48\x8b\x55\x18' + b'\x8b\x0a' + b'\x31\xff'
        old = b'\x8b\x55\x18' + b'\x8b\x0a' + b'\x48\x31\xff'
        if out[off:off + 8] == patch:
            return 0
        if out[off:off + 8] != old:
            return 0
        out[off:off + 8] = patch
        return 1

    def _fix_cmd_main_wcschr_call(self, out: bytearray) -> int:
        """Restore cmd main wcschr FF15 at 0x9130 (was call into 0x29E85 mid-body)."""
        if not self.text_rva:
            return 0
        stub_off = 0x9123 - self.text_rva
        call_off = 0x9130 - self.text_rva
        stub_end = 0x913B - self.text_rva
        bad_off = 0x29E85 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        if out[call_off] == 0xE8:
            rel = struct.unpack_from('<i', out, call_off + 1)[0]
            if call_off + 5 + rel != bad_off:
                return 0
        elif out[call_off:call_off + 2] != b'\xff\x15':
            return 0
        old_iat = self.old_base + 0x1208  # MSVCRT!wcschr
        iat_va = self._resolve_iat_slot_va(old_iat)
        rel = iat_va - (self.new_base + self.text_rva + call_off + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        span = stub_end - stub_off
        patch = (b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'
                 + b'\xff\x15' + struct.pack('<i', rel)
                 + b'\x4c\x89\xec\x41\x5d')
        if len(patch) != span:
            return 0
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_main_wcschr_null_fallback(self, out: bytearray) -> int:
        """After token scan: reload RBX from saved cmdline at [rbp-0x228] on null."""
        if not self.text_rva:
            return 0
        off = 0x913B - self.text_rva
        end = 0x9150 - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        patch = (
            b'\x48\x85\xc0'
            + b'\x75\x09'
            + b'\x48\x8b\x9d\xd8\xfd\xff\xff'
            + b'\xeb\x07'
            + b'\x90' * 7
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_interactive_skip_wcscmp_slashq_917a(self, out: bytearray) -> int:
        """Win10: wcscmp call at 0x917A AVs — force no-match and fall through to banner jne."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        off = 0x917A - self.text_rva
        if off < 0 or off + 6 > len(out):
            return 0
        patch = b'\xb8\x01\x00\x00\x00\x90'  # mov eax, 1; nop
        if out[off:off + 6] == patch:
            return 0
        if out[off] != 0xFF or out[off + 1] != 0x15:
            return 0
        out[off:off + 6] = patch
        return 1

    def _fix_cmd_main_token_scan_null_exit_911e(self, out: bytearray) -> int:
        """Token scan loop: null terminator must exit (0x913B), not jmp back to 0x911A."""
        if not self.text_rva:
            return 0
        off = 0x911E - self.text_rva
        if off < 0 or off + 2 > len(out) or out[off] != 0x74:
            return 0
        want = 0x913B - (0x911E + 2)
        if not (-128 <= want <= 127):
            return 0
        if out[off + 1] == want & 0xFF:
            return 0
        out[off + 1] = want & 0xFF
        return 1

    def _fix_cmd_main_empty_token_cmp(self, out: bytearray) -> int:
        """Restore empty-token cmp/je (0x9150) before /? /c switch dispatch."""
        if not self.text_rva:
            return 0
        off = 0x9150 - self.text_rva
        end = 0x9159 - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        exit_off = 0x2E4BE - self.text_rva
        banner_off = 0x2E4B2 - self.text_rva
        je = banner_off - (0x9153 - self.text_rva + 6)
        patch = b'\x80\x3b\x00' + b'\x0f\x84' + struct.pack('<i', je)
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_skip_empty_token_exit(self, out: bytearray) -> int:
        """NOP empty-token je at 0x9153 — exit target chain is still broken for /c echo."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        je_off = 0x9153 - self.text_rva
        if je_off < 0 or je_off + 6 > len(out) or out[je_off:je_off + 2] != b'\x0f\x84':
            return 0
        if out[je_off:je_off + 6] == b'\x90' * 6:
            return 0
        out[je_off:je_off + 6] = b'\x90' * 6
        return 1

    def _fix_cmd_main_c_switch_jne(self, out: bytearray) -> int:
        """Second /c wcscmp branch: jne to exit (keep fall-through on match)."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x91B5 - self.text_rva
        if off < 0 or off + 2 > len(out) or out[off:off + 2] != b'\x0f\x84':
            return 0
        if out[off:off + 2] == b'\x0f\x85':
            return 0
        out[off:off + 2] = b'\x0f\x85'
        return 1

    def _fix_cmd_main_wcsncmp_c_second(self, out: bytearray) -> int:
        """Second switch compare: wcsncmp(rbx, L\"/c\", 2) so tail stays intact."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x9192 - self.text_rva
        end = 0x91B3 - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        lea_rva = 0x9195
        r8_rva = 0x919C
        sub_rva = 0x91A2
        ff_rva = 0x91A6
        add_rva = 0x91AC
        rel_str = 0x41484 - (lea_rva + 7)
        rel_iat = 0x6E529 - (ff_rva + 6)
        if not (-2147483648 <= rel_str <= 2147483647
                and -2147483648 <= rel_iat <= 2147483647):
            return 0
        patch = (
            b'\x48\x89\xd9'
            + b'\x48\x8d\x15' + struct.pack('<i', rel_str)
            + b'\x41\xb8\x02\x00\x00\x00'
            + b'\x48\x83\xec\x28'
            + b'\xff\x15' + struct.pack('<i', rel_iat)
            + b'\x48\x83\xc4\x28'
            + b'\x90' * 3
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_echo_tail_rcx(self, out: bytearray) -> int:
        """Echo tail: pass command text (skip L\"/c \") in RCX for wcslen helper."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x935E - self.text_rva
        if off < 0 or off + 4 > len(out):
            return 0
        want = b'\x48\x8d\x4b\x06'  # lea rcx, [rbx+6]  past L"/c "
        if out[off:off + 4] == want:
            return 0
        if out[off:off + 4] != b'\x48\x8b\x4d\x10':
            return 0
        out[off:off + 4] = want
        return 1

    def _fix_cmd_exec_helper_kernel_iat(self, out: bytearray) -> int:
        """Exec helper ~0x130E3: retarget ADVAPI32 IAT cells to KERNEL32 APIs."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        fixes = (
            (0x13142, 0x8006E10F, self.new_base + 0x6D4D8),  # CreateProcessW
            (0x131A1, 0x8006E0C7, self.new_base + 0x6D638),  # WaitForSingleObject
            (0x131C6, 0x8006E0F7, self.new_base + 0x6D518),  # CloseHandle
        )
        fixed = 0
        for mov_rva, bad_cell, good_iat in fixes:
            off = mov_rva - self.text_rva
            if off < 0 or off + 10 > len(out) or out[off:off + 2] != b'\x48\xb8':
                continue
            cur = struct.unpack_from('<Q', out, off + 2)[0]
            if cur == good_iat:
                continue
            if cur != bad_cell:
                continue
            struct.pack_into('<Q', out, off + 2, good_iat)
            fixed += 1
        return fixed

    def _fix_cmd_exec_success_via_rbx_setup(self, out: bytearray) -> int:
        """After /c switch handler, rescan for L'/' in [rbp-0x228] (not buffer base)."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        fixed = 0
        off_b3 = 0x92B3 - self.text_rva
        if off_b3 >= 0 and off_b3 + 5 <= len(out) and out[off_b3] == 0xE9:
            want_tgt = 0x92CC - self.text_rva
            rel = want_tgt - (off_b3 + 5)
            if struct.unpack_from('<i', out, off_b3 + 1)[0] != rel:
                if -2147483648 <= rel <= 2147483647:
                    struct.pack_into('<i', out, off_b3 + 1, rel)
                    fixed += 1
        scan_off = 0x92CC - self.text_rva
        scan_end = 0x92EC - self.text_rva
        if scan_off < 0 or scan_end <= scan_off or scan_end > len(out):
            return fixed
        loop = scan_off + 7
        done = scan_off + 27
        je0 = done - (scan_off + 15)
        je1 = done - (scan_off + 21)
        jloop = loop - (scan_off + 27)
        rel_jmp = ((0x8F6F if self.win10_test_shim else 0x932F) - self.text_rva) - (done + 5)
        if not (-2147483648 <= rel_jmp <= 2147483647):
            return fixed
        body = (
            b'\x48\x8d\x9d\xd8\xfd\xff\xff'   # lea rbx, [rbp-0x228]
            + b'\x0f\xb7\x03'                   # movzx eax, word [rbx]
            + b'\x66\x85\xc0'                   # test ax, ax
            + b'\x74' + bytes([je0 & 0xFF])
            + b'\x66\x3d\x2f\x00'               # cmp ax, '/'
            + b'\x74' + bytes([je1 & 0xFF])
            + b'\x48\x83\xc3\x02'               # add rbx, 2
            + b'\xeb' + bytes([jloop & 0xFF])
            + b'\xe9' + struct.pack('<i', rel_jmp)
        )
        pad = scan_end - scan_off - len(body)
        if pad < 0:
            return fixed
        patch = body + b'\x90' * pad
        if out[scan_off:scan_end] != patch:
            out[scan_off:scan_end] = patch
            fixed += 1
        return fixed

    def _fix_cmd_skip_createprocess_helper_938f(self, out: bytearray) -> int:
        """Echo tail: skip CreateProcess helper; pass L\"echo…\" ptr in RAX to batch runner."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        call_off = 0x938F - self.text_rva
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        patch = b'\x48\x8d\x43\x06\x90'  # lea rax, [rbx+6]; nop
        if out[call_off:call_off + 5] == patch:
            return 0
        out[call_off:call_off + 5] = patch
        return 1

    def _fix_cmd_echo_batch_call_93bc(self, out: bytearray) -> int:
        """Echo tail batch call at 0x93BC must enter helper prologue 0x2B3E8."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        call_off = 0x93BC - self.text_rva
        entry_rva = 0x2B3E8
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        want = entry_rva - (0x93BC + 5)
        if struct.unpack_from('<i', out, call_off + 1)[0] == want:
            return 0
        if -2147483648 <= want <= 2147483647:
            struct.pack_into('<i', out, call_off + 1, want)
            return 1
        return 0

    def _fix_cmd_echo_dispatch_call_2b3f5(self, out: bytearray) -> int:
        """Batch echo runner: snap mid-body calls to dispatch helpers 0x49F3 / 0x487F."""
        if not self.text_rva:
            return 0
        fixed = 0
        snaps = (
            (0x2B3F5, 0x49F3),
            (0x2B417, 0x487F),
        )
        for call_rva, entry_rva in snaps:
            call_off = call_rva - self.text_rva
            if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
                continue
            want = entry_rva - (call_rva + 5)
            if struct.unpack_from('<i', out, call_off + 1)[0] == want:
                continue
            if -2147483648 <= want <= 2147483647:
                struct.pack_into('<i', out, call_off + 1, want)
                fixed += 1
        return fixed

    def _fix_cmd_echo_batch_second_arg(self, out: bytearray) -> int:
        """Second dispatch phase must keep command-line ptr (RCX=RBX), not xor rcx,rcx."""
        if not self.text_rva:
            return 0
        off = 0x2B407 - self.text_rva
        if off < 0 or off + 3 > len(out):
            return 0
        want = b'\x48\x89\xd9'  # mov rcx, rbx
        if out[off:off + 3] == want:
            return 0
        if out[off:off + 3] != b'\x48\x31\xc9':
            return 0
        out[off:off + 3] = want
        return 1

    def _fix_cmd_movabs_iat_calls_in_range(self, out: bytearray,
                                           lo_rva: int, hi_rva: int) -> int:
        """Replace ``movabs; mov rax,[cell]; call rax`` with ``call [IAT]`` in RVA span."""
        if not self.text_rva or not self.win10_test_shim:
            return 0
        lo = max(0, lo_rva - self.text_rva)
        hi = min(len(out), hi_rva - self.text_rva)
        fixed = 0
        i = lo
        while i < hi - 14:
            if out[i:i + 2] == b'\x48\xb8' and out[i + 10:i + 15] == b'\x48\x8b\x00\xff\xd0':
                cell_va = struct.unpack_from('<Q', out, i + 2)[0]
                old_iat = self._pure_old_iat_for_imm(cell_va)
                if old_iat is None:
                    old_iat = self._old_iat_va_for_idata_cell(cell_va)
                if old_iat and self._emit_ff15_iat_call(out, i, old_iat, 15):
                    fixed += 1
                i += 15
                continue
            i += 1
        return fixed

    def _fix_cmd_batch_helper_iat_region(self, out: bytearray) -> int:
        """Interactive/batch helpers: movabs+IAT in 0x1C000–0x2200 (e.g. 0x1D371)."""
        fixed = self._fix_cmd_movabs_iat_calls_in_range(out, 0x1C000, 0x2200)
        # Explicit: GetVolumeInformationW at main+0x1D364 (cell 0x6D540).
        off = 0x1D364 - self.text_rva
        if (off >= 0 and off + 15 <= len(out)
                and out[off:off + 2] == b'\x48\xb8'
                and out[off + 10:off + 15] == b'\x48\x8b\x00\xff\xd0'):
            old_iat = self.old_base + 0x10F8
            if self._emit_ff15_iat_call(out, off, old_iat, 15):
                fixed += 1
        return fixed

    def _fix_cmd_echo_dispatch_iat_region(self, out: bytearray) -> int:
        """Convert movabs+IAT indirections in echo dispatch helpers (0x487F–0x5300)."""
        if not self.text_rva or not self.win10_test_shim:
            return 0
        lo = max(0, 0x487F - self.text_rva)
        hi = min(len(out), 0x5300 - self.text_rva)
        fixed = 0
        i = lo
        while i < hi - 14:
            if out[i:i + 2] == b'\x48\xb8' and out[i + 10:i + 15] == b'\x48\x8b\x00\xff\xd0':
                cell_va = struct.unpack_from('<Q', out, i + 2)[0]
                old_iat = self._old_iat_va_for_idata_cell(cell_va)
                if not old_iat and self.new_base <= cell_va < self.new_base + 0x80000:
                    slot_rva = cell_va - self.new_base
                    for old_rva, new_rva in (self._iat_rva_map or {}).items():
                        if new_rva == slot_rva:
                            old_iat = self.old_base + old_rva
                            break
                    # Direct PE64 IAT slot → x86 IAT (movabs points at IAT VA).
                    _slot_x86 = {
                        0x6D3F8: 0x1050, 0x6D420: 0x1064, 0x6D438: 0x1070,
                        0x6D690: 0x119C, 0x6E409: 0x11D4,
                    }
                    if old_iat is None and slot_rva in _slot_x86:
                        old_iat = self.old_base + _slot_x86[slot_rva]
                if old_iat and self._emit_ff15_iat_call(out, i, old_iat, 15):
                    fixed += 1
                i += 15
                continue
            i += 1
        return fixed

    def _fix_cmd_echo_tail_wcsncpy_stub(self, out: bytearray) -> int:
        """Echo tail wcsncpy stub — skipped when WriteConsole shortcut owns 0x92EC."""
        if not self.text_rva:
            return 0
        if self.win10_test_shim:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        jmp_off = 0x9337 - self.text_rva
        if jmp_off < 0 or jmp_off + 2 > len(out):
            return 0
        if out[jmp_off:jmp_off + 2] not in (b'\x48\x89', b'\xe9'):
            return 0
        stub_rva = 0x92E0
        stub_off = stub_rva - self.text_rva
        resume_rva = 0x9351
        iat_va = self._resolve_iat_slot_va(self.old_base + 0x1204)  # wcsncpy
        ff_rva = stub_rva + 0x13
        rel_iat = iat_va - (self.new_base + ff_rva + 6)
        jmp_from = 0x9337
        rel_stub = stub_rva - (jmp_from + 5)
        body = (
            b'\x48\x89\xf9'                   # mov rcx, rdi
            + b'\x48\x89\xda'                 # mov rdx, rbx
            + b'\x41\x55'                     # push r13
            + b'\x49\x89\xe5'                 # mov r13, rsp
            + b'\x48\x83\xec\x20'             # sub rsp, 0x20
            + b'\x48\x83\xe4\xf0'             # and rsp, -16
            + b'\xff\x15' + struct.pack('<i', rel_iat)
            + b'\x4c\x89\xec'                 # mov rsp, r13
            + b'\x41\x5d'                     # pop r13
        )
        rel_resume = resume_rva - (stub_rva + len(body) + 5)
        if not all(-2147483648 <= r <= 2147483647
                   for r in (rel_iat, rel_stub, rel_resume)):
            return 0
        stub = body + b'\xe9' + struct.pack('<i', rel_resume)
        pad = (0x932F - stub_rva) - len(stub)
        if pad < 0:
            return 0
        stub += b'\x90' * pad
        if out[stub_off:stub_off + len(stub)] == stub:
            pad2 = resume_rva - (jmp_from + 5)
            want_jmp = b'\xe9' + struct.pack('<i', rel_stub) + b'\x90' * pad2
            if out[jmp_off:jmp_off + len(want_jmp)] == want_jmp:
                return 0
        out[stub_off:stub_off + len(stub)] = stub
        pad2 = resume_rva - (jmp_from + 5)
        out[jmp_off:jmp_off + 5] = b'\xe9' + struct.pack('<i', rel_stub)
        if pad2 > 0:
            out[jmp_off + 5:jmp_off + 5 + pad2] = b'\x90' * pad2
        return 1

    def _fix_cmd_main_skip_parse_to_exec(self, out: bytearray) -> int:
        """Skip wcscpy/parse block when [rbp+0x18] is unset; go straight to /c exec tail."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x91E4 - self.text_rva
        end = 0x91EE - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        rel = 0x925F - (0x91E4 + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (end - off - 5)
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_exit_helper_call_2e4cb(self, out: bytearray) -> int:
        """Snap exit-wrapper call at 0x2E4CB off 0x1D357 mid-body to entry 0x1D343."""
        if not self.text_rva:
            return 0
        call_off = 0x2E4CB - self.text_rva
        entry_off = 0x1D343 - self.text_rva
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        want = entry_off - (call_off + 5)
        if struct.unpack_from('<i', out, call_off + 1)[0] == want:
            return 0
        if -2147483648 <= want <= 2147483647:
            struct.pack_into('<i', out, call_off + 1, want)
            return 1
        return 0

    def _fix_cmd_crt_force_banner_bad_path_8ac8(self, out: bytearray) -> int:
        """Always skip CRT banner heap path (0x8ACE); good path malloc+wcsncpy AVs on no-args."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x8AC8 - self.text_rva
        end = 0x8ACE - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        rel = 0x8AF4 - (0x8AC8 + 5)
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (end - off - 5)
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_crt_fn6314_call_target_8af4(self, out: bytearray) -> int:
        """CRT fn6314 calls must land on mov rax,rsi at 0x2DC32 (not 0x2DC33)."""
        if not self.text_rva:
            return 0
        fixed = 0
        want = 0x2DC32
        for call_rva in (0x8AF4, 0x8CD4):
            call_off = call_rva - self.text_rva
            if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
                continue
            rel = want - (call_rva + 5)
            if struct.unpack_from('<i', out, call_off + 1)[0] != rel:
                struct.pack_into('<i', out, call_off + 1, rel)
                fixed += 1
        return fixed

    def _fix_cmd_crt_fn6314_tailcall_pop_ret_2dc32(self, out: bytearray) -> int:
        """fn6314 thunk at 0x2DC32: skip main re-entry once token parse is done."""
        if not self.text_rva:
            return 0
        off = 0x2DC32 - self.text_rva
        end = 0x2DC44 - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        flag_rva = 0x41F58
        thunk_rva = 0x2DC32
        cmp_end = thunk_rva + 7
        jne_next = thunk_rva + 9
        ret_pos = thunk_rva + 17
        main_rel = 0x8EB9 - (thunk_rva + 17)
        jne_rel = ret_pos - jne_next
        if not (-128 <= jne_rel <= 127
                and -2147483648 <= main_rel <= 2147483647):
            return 0
        body = (
            b'\x83\x3d' + struct.pack('<i', flag_rva - cmp_end) + b'\x00'
            + b'\x75' + struct.pack('b', jne_rel)
            + b'\x48\x89\xf0'
            + b'\xe9' + struct.pack('<i', main_rel)
            + b'\xc3'
        )
        if len(body) > end - off:
            return 0
        body += b'\x90' * (end - off - len(body))
        if out[off:end] == body:
            return 0
        out[off:end] = body
        return 1

    def _fix_cmd_crt_banner_fn6314_jne_2d9d7(self, out: bytearray) -> int:
        """CRT banner path: jne into fn6314 thunk is a jmp (no ret addr) — continue at 0x2D9DD."""
        if not self.text_rva:
            return 0
        off = 0x2D9D7 - self.text_rva
        if off < 0 or off + 6 > len(out) or out[off:off + 2] != b'\x0f\x85':
            return 0
        rel = struct.unpack_from('<i', out, off + 2)[0]
        if off + 6 + rel != 0x2DC32 - self.text_rva:
            return 0
        cont = 0x2D9DD
        jmp_from = 0x2D9D7 + 5
        patch = b'\xe9' + struct.pack('<i', cont - jmp_from) + b'\x90'
        if out[off:off + 6] == patch:
            return 0
        out[off:off + 6] = patch
        return 1

    def _fix_cmd_crt_banner_fn6314_je_2d9ea(self, out: bytearray) -> int:
        """CRT banner resume: je into fn6314 thunk has no ret addr — continue at 0x2D9F0."""
        if not self.text_rva:
            return 0
        site_rva = 0x2D9EA
        off = site_rva - self.text_rva
        if off < 0 or off + 6 > len(out) or out[off:off + 2] != b'\x0f\x84':
            return 0
        rel = struct.unpack_from('<i', out, off + 2)[0]
        if site_rva + 6 + rel != 0x2DC32:
            return 0
        cont = 0x2D9F0
        jmp_from = site_rva + 5
        patch = b'\xe9' + struct.pack('<i', cont - jmp_from) + b'\x90'
        if out[off:off + 6] == patch:
            return 0
        out[off:off + 6] = patch
        return 1

    def _fix_cmd_crt_fn6314_jmp_not_call_2dc32(self, out: bytearray) -> int:
        """Jmp (not call) into fn6314 thunk leaves no ret addr — continue CRT at 0x2D9DD."""
        if not self.text_rva:
            return 0
        thunk = 0x2DC32
        cont = 0x2D9DD
        fixed = 0
        for jmp_rva in (0x2DA43, 0x2DBB2):
            off = jmp_rva - self.text_rva
            if off < 0 or off + 5 > len(out) or out[off] != 0xE9:
                continue
            rel = struct.unpack_from('<i', out, off + 1)[0]
            if jmp_rva + 5 + rel != thunk:
                continue
            new_rel = cont - (jmp_rva + 5)
            if struct.unpack_from('<i', out, off + 1)[0] != new_rel:
                struct.pack_into('<i', out, off + 1, new_rel)
                fixed += 1
        i = 0
        while i < len(out) - 5:
            if out[i] != 0xE9:
                i += 1
                continue
            src = self.text_rva + i
            rel = struct.unpack_from('<i', out, i + 1)[0]
            if src + 5 + rel != thunk:
                i += 1
                continue
            if src in (0x2DA43, 0x2DBB2):
                i += 5
                continue
            new_rel = cont - (src + 5)
            if struct.unpack_from('<i', out, i + 1)[0] != new_rel:
                struct.pack_into('<i', out, i + 1, new_rel)
                fixed += 1
            i += 5
        return fixed

    def _fix_cmd_crt_fn6314_mid_thunk_branches(self, out: bytearray) -> int:
        """Retarget jmps into the fn6314 thunk body (0x2DC33..0x2DC42) to 0x2DC32."""
        if not self.text_rva:
            return 0
        good = 0x2DC32
        bad_lo = 0x2DC33
        bad_hi = 0x2DC42
        fixed = 0
        for site_rva in (0x2D9EA, 0x2DBDA):
            off = site_rva - self.text_rva
            if off < 0 or off + 6 > len(out) or out[off:off + 2] not in (b'\x0f\x84', b'\x0f\x85'):
                continue
            rel = struct.unpack_from('<i', out, off + 2)[0]
            if site_rva + 6 + rel not in range(bad_lo, bad_hi + 1):
                continue
            want = good - (site_rva + 6)
            if struct.unpack_from('<i', out, off + 2)[0] != want:
                struct.pack_into('<i', out, off + 2, want)
                fixed += 1
        jmp_off = 0x2DAFF - self.text_rva
        if (0 <= jmp_off + 5 <= len(out) and out[jmp_off] == 0xE9):
            rel = struct.unpack_from('<i', out, jmp_off + 1)[0]
            if 0x2DAFF + 5 + rel in range(bad_lo, bad_hi + 1):
                want = good - (0x2DAFF + 5)
                if struct.unpack_from('<i', out, jmp_off + 1)[0] != want:
                    struct.pack_into('<i', out, jmp_off + 1, want)
                    fixed += 1
        good_off = good - self.text_rva
        bad_lo_off = bad_lo - self.text_rva
        bad_hi_off = bad_hi - self.text_rva
        if bad_lo_off < 0 or bad_hi_off < bad_lo_off:
            return fixed
        i = 0
        while i < len(out) - 6:
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if bad_lo_off <= tgt <= bad_hi_off:
                    struct.pack_into('<i', out, i + 2, good_off - (i + 6))
                    fixed += 1
                i += 6
                continue
            if out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if bad_lo_off <= tgt <= bad_hi_off:
                    struct.pack_into('<i', out, i + 1, good_off - (i + 5))
                    fixed += 1
                i += 5
                continue
            i += 1
        return fixed

    def _fix_cmd_crt_stub_iat_call_rax(self, out: bytearray) -> int:
        """CRT ``call rax`` through unresolved IAT cells — return 0 instead of AV."""
        if not self.text_rva:
            return 0
        fixed = 0
        for call_rva in (0x2D92A, 0x2D9CE, 0x2DAF8, 0x2DBFA, 0x2DC2B, 0x2DCED):
            call_off = call_rva - self.text_rva
            mov_off = call_off - 3
            if mov_off < 0 or call_off + 2 > len(out):
                continue
            if out[mov_off:mov_off + 3] != b'\x48\x8b\x00' or out[call_off:call_off + 2] != b'\xff\xd0':
                continue
            if out[mov_off:call_off + 2] == b'\x48\x8b\x00\x31\xc0':
                continue
            out[mov_off:mov_off + 3] = b'\x90\x90\x90'
            out[call_off:call_off + 2] = b'\x31\xc0'
            fixed += 1
        return fixed

    def _fix_cmd_main_save_rbp_slot(self, out: bytearray) -> int:
        """Save cmd main RBP at 0x41F50; resume stub restores it after CRT detour."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        slot_rva = 0x41F50
        save_rva = 0x8F03
        save_off = save_rva - self.text_rva
        save_end = save_off + 12
        if save_end > len(out):
            return 0
        rip_at = save_rva + 7
        slot_rel = slot_rva - rip_at
        if not (-2147483648 <= slot_rel <= 2147483647):
            return 0
        save_body = (
            b'\x48\x89\x2d' + struct.pack('<i', slot_rel)
            + b'\x48\x89\x4d\x10'
            + b'\xc3'
        )
        call_off = 0x8EBD - self.text_rva
        if call_off < 0 or call_off + 5 > len(out):
            return 0
        call_rel = save_rva - (0x8EBD + 5)
        if not (-2147483648 <= call_rel <= 2147483647):
            return 0
        fixed = 0
        if out[save_off:save_off + len(save_body)] != save_body:
            out[save_off:save_off + len(save_body)] = save_body
            fixed += 1
        want_call = b'\xe8' + struct.pack('<i', call_rel)
        if out[call_off:call_off + 5] != want_call:
            if out[call_off:call_off + 2] in (b'\xe8\x00', b'\x48\x89') or out[call_off] == 0xE8:
                out[call_off:call_off + 5] = want_call
                fixed += 1
        return fixed

    def _fix_cmd_print_tls_je_2d458(self, out: bytearray) -> int:
        """JE at 0x2D458 must skip past GS TLS mov (9 bytes), not land at 0x2D464."""
        if not self.text_rva:
            return 0
        off = 0x2D458 - self.text_rva
        if off < 0 or off + 2 > len(out):
            return 0
        if out[off:off + 2] != b'\x74\x0a':
            return 0
        out[off + 1] = 0x0C
        return 1

    def _ensure_cmd_wide_stdout_print_stub(self, out: bytearray) -> int:
        """Place compact stdout writer once; hook 0x2D813 banner helper entry."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        entry_rva = 0x2D813
        entry_off = entry_rva - self.text_rva
        if entry_off < 0 or entry_off + 5 > len(out):
            return 0
        if self._cmd_stdout_print_rva:
            jmp = b'\xe9' + struct.pack('<i', self._cmd_stdout_print_rva - (entry_rva + 5))
            if out[entry_off:entry_off + 5] == jmp:
                return 0
            out[entry_off:entry_off + 5] = jmp
            return 1
        wcslen_iat = self._loader_iat_va('MSVCRT.dll', 'wcslen')
        if not wcslen_iat:
            wcslen_iat = self._resolve_iat_slot_va(self.old_base + 0x11D8)
        getstd = self._loader_iat_va('KERNEL32.dll', 'GetStdHandle')
        writefn = self._loader_iat_va('KERNEL32.dll', 'WriteConsoleW')
        use_console = bool(writefn)
        if not writefn:
            writefn = self._loader_iat_va('KERNEL32.dll', 'WriteFile')
            use_console = False
        if not wcslen_iat or not getstd or not writefn:
            return 0
        sel = b'\x48\x85\xd2\x75\x03\x48\x89\xca'
        body = sel + self._build_compact_wide_stdout_write(
            0, wcslen_iat, getstd, writefn, use_console)
        cave_rva = 0x8FF7
        cave_end = 0x9040
        cave_off = cave_rva - self.text_rva
        if cave_off < 0 or len(body) > cave_end - cave_rva:
            need = len(body)
            avoid = [(0x8000, 0x9200), (0x2E490, 0x2E520)]
            cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
            if cave_off is None:
                return 0
            cave_rva = self.text_rva + cave_off
        body = sel + self._build_compact_wide_stdout_write(
            cave_rva + len(sel), wcslen_iat, getstd, writefn, use_console)
        cave_sz = len(body)
        if cave_off < 0 or cave_off + cave_sz > len(out):
            return 0
        jmp = b'\xe9' + struct.pack('<i', cave_rva - (entry_rva + 5))
        fixed = 0
        if out[cave_off:cave_off + cave_sz] != body:
            out[cave_off:cave_off + cave_sz] = body
            fixed += 1
        if out[entry_off:entry_off + 5] != jmp:
            out[entry_off:entry_off + 5] = jmp
            fixed += 1
        self._cmd_stdout_print_rva = cave_rva
        return fixed

    def _fix_cmd_banner_print_stub_2d813(self, out: bytearray) -> int:
        """Banner print helper: WriteConsoleW/WriteFile wide string at RCX or RDX to stdout."""
        if not self.text_rva:
            return 0
        if not self.win10_test_shim:
            off = 0x2D813 - self.text_rva
            if off < 0 or off + 3 > len(out):
                return 0
            patch = b'\x31\xc0\xc3\x90'
            if out[off:off + 3] == patch:
                return 0
            out[off:off + 3] = patch
            return 1
        return self._ensure_cmd_wide_stdout_print_stub(out)

    def _fix_cmd_banner_print_call_sites(self, out: bytearray) -> int:
        """Snap every ``call`` into the 0x2D813 print helper (±8) to the jmp entry."""
        if not self.text_rva:
            return 0
        target = 0x2D813
        lo_rva, hi_rva = target - 8, target + 8
        fixed = 0
        i = 0
        while i < len(out) - 5:
            call_at = None
            if out[i] == 0xF0 and i + 6 <= len(out) and out[i + 1] == 0xE8:
                call_at = i + 1
            elif out[i] == 0xE8:
                call_at = i
            if call_at is not None:
                call_rva = self.text_rva + call_at
                rel = struct.unpack_from('<i', out, call_at + 1)[0]
                tgt = call_rva + 5 + rel
                if lo_rva <= tgt <= hi_rva and tgt != target:
                    want = target - (call_rva + 5)
                    if struct.unpack_from('<i', out, call_at + 1)[0] != want:
                        struct.pack_into('<i', out, call_at + 1, want)
                        fixed += 1
                i = call_at + 5
            else:
                i += 1
        return fixed

    def _fix_cmd_banner_setup_call_3cf7b(self, out: bytearray) -> int:
        """Snap every ``call`` into the 0x3CF7A banner-setup stub (±8) to its entry."""
        if not self.text_rva:
            return 0
        target = 0x3CF7A
        lo_rva, hi_rva = target - 8, target + 8
        fixed = 0
        i = 0
        while i < len(out) - 5:
            call_at = None
            if out[i] == 0xF0 and i + 6 <= len(out) and out[i + 1] == 0xE8:
                call_at = i + 1
            elif out[i] == 0xE8:
                call_at = i
            if call_at is not None:
                call_rva = self.text_rva + call_at
                rel = struct.unpack_from('<i', out, call_at + 1)[0]
                tgt = call_rva + 5 + rel
                if lo_rva <= tgt <= hi_rva and tgt != target:
                    want = target - (call_rva + 5)
                    if struct.unpack_from('<i', out, call_at + 1)[0] != want:
                        struct.pack_into('<i', out, call_at + 1, want)
                        fixed += 1
                i = call_at + 5
            else:
                i += 1
        return fixed

    def _fix_cmd_banner_setup_stub_3cf7a(self, out: bytearray) -> int:
        """Banner setup helper: return success without CRT volume chain re-entry."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        stub_rva = 0x3CF7A
        stub_end = 0x3CF9D
        off = stub_rva - self.text_rva
        end = stub_end - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        body = b'\xb8\x01\x00\x00\x00\xc3' + b'\x90' * (end - off - 6)
        if out[off:end] == body:
            return 0
        out[off:end] = body
        return 1

    def _fix_cmd_crt_seh_banner_resume_8f56(self, out: bytearray) -> int:
        """SEH guard 0x8F56: jmp ret at 0x2DC44 pops garbage — resume banner after setup."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        jmp_off = 0x8F58 - self.text_rva
        resume_rva = 0x2E5E7
        if jmp_off < 0 or jmp_off + 5 > len(out) or out[jmp_off] != 0xE9:
            return 0
        want = resume_rva - (0x8F58 + 5)
        if struct.unpack_from('<i', out, jmp_off + 1)[0] == want:
            return 0
        struct.pack_into('<i', out, jmp_off + 1, want)
        return 1

    def _fix_cmd_crt_seh_route_8f32_to_guard(self, out: bytearray) -> int:
        """SEH site 0x8F32: use 0x8F40 flag guard instead of cmdline dispatch."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        site_rva = 0x8F32
        guard_rva = 0x8F40
        off = site_rva - self.text_rva
        if off < 0 or off + 5 > len(out) or out[off] != 0xE9:
            return 0
        rel = guard_rva - (site_rva + 5)
        patch = b'\xe9' + struct.pack('<i', rel)
        if out[off:off + 5] == patch:
            return 0
        out[off:off + 5] = patch
        return 1

    def _fix_cmd_readconsole_prompt_helper_calls(self, out: bytearray) -> int:
        """ReadConsole helper calls prompt printer at 0x200E8 (mid-instruction) — use 0x200E5."""
        if not self.text_rva:
            return 0
        good = 0x200E5
        bad = (0x200E8, 0x200E9, 0x200EA, 0x200EB, 0x200EC, 0x200ED, 0x200EE, 0x200EF,
               0x200F0, 0x200F1, 0x200F2)
        fixed = 0
        for call_rva in (0x3D1A0, 0x3D1D0, 0x3D213):
            off = call_rva - self.text_rva
            if off < 0 or off + 5 > len(out) or out[off] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, off + 1)[0]
            if call_rva + 5 + rel not in bad:
                continue
            want = good - (call_rva + 5)
            if struct.unpack_from('<i', out, off + 1)[0] != want:
                struct.pack_into('<i', out, off + 1, want)
                fixed += 1
        return fixed

    def _fix_cmd_banner_helper_call_200f0(self, out: bytearray) -> int:
        """Snap every ``call`` into prompt helper 0x200E5..0x200FF to entry 0x200E5."""
        if not self.text_rva:
            return 0
        good = 0x200E5
        lo_rva, hi_rva = good, good + 0x18
        fixed = 0
        i = 0
        while i < len(out) - 5:
            call_at = None
            if out[i] == 0xF0 and i + 6 <= len(out) and out[i + 1] == 0xE8:
                call_at = i + 1
            elif out[i] == 0xE8:
                call_at = i
            if call_at is not None:
                call_rva = self.text_rva + call_at
                rel = struct.unpack_from('<i', out, call_at + 1)[0]
                tgt = call_rva + 5 + rel
                if lo_rva <= tgt <= hi_rva and tgt != good:
                    want = good - (call_rva + 5)
                    if struct.unpack_from('<i', out, call_at + 1)[0] != want:
                        struct.pack_into('<i', out, call_at + 1, want)
                        fixed += 1
                i = call_at + 5
            else:
                i += 1
        return fixed

    def _fix_cmd_crt_exit_jmp_8770(self, out: bytearray) -> int:
        """CRT init must not land in getmainargs epilogue (0x8769/0x8770).

        Success jmps are redirected to 0x8699.  Malloc-fail ``je`` branches that
        used to enter the epilogue without a matching frame are neutralized to
        fall through (rel32=0) so nested CRT re-entry during the banner cannot
        ``ret`` into RIP=0.
        """
        if not self.text_rva:
            return 0
        good = 0x8699
        bad = (0x8769, 0x8770)
        fixed = 0
        lo = 0x8500 - self.text_rva
        hi = 0x8800 - self.text_rva
        if lo < 0:
            lo = 0
        i = lo
        while i < min(hi, len(out) - 5):
            if out[i] != 0xE9:
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            site = self.text_rva + i
            tgt = site + 5 + rel
            if tgt not in bad:
                i += 1
                continue
            want = good - (site + 5)
            if struct.unpack_from('<i', out, i + 1)[0] != want:
                struct.pack_into('<i', out, i + 1, want)
                fixed += 1
            i += 5
        i = lo
        while i < min(hi, len(out) - 6):
            if out[i] != 0x0F or out[i + 1] not in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                i += 1
                continue
            site = self.text_rva + i
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = site + 6 + rel
            if tgt not in bad:
                i += 1
                continue
            # je/jcc to epilogue -> fall through (next insn) instead of unwinding
            if rel != 0:
                struct.pack_into('<i', out, i + 2, 0)
                fixed += 1
            i += 6
        return fixed

    def _fix_cmd_banner_volume_call_chain(self, out: bytearray) -> int:
        """Snap banner GetVolumeInformation call chain to aligned helper entries."""
        if not self.text_rva:
            return 0
        snaps = (
            (0x200F2, 0x1D7F0, range(0x1D7F1, 0x1D800)),
            (0x1D7FD, 0x375B0, range(0x375AF, 0x375C0)),
            (0x375C7, 0x1CA48, range(0x1CA49, 0x1CA58)),
        )
        fixed = 0
        for site_rva, good, bad in snaps:
            off = site_rva - self.text_rva
            if off < 0 or off + 6 > len(out):
                continue
            call_at = off
            if out[off] == 0xF0 and out[off + 1] == 0xE8:
                call_at = off + 1
            elif out[off] != 0xE8:
                continue
            call_rva = self.text_rva + call_at
            rel = struct.unpack_from('<i', out, call_at + 1)[0]
            if call_rva + 5 + rel not in bad:
                continue
            want = good - (call_rva + 5)
            if struct.unpack_from('<i', out, call_at + 1)[0] != want:
                struct.pack_into('<i', out, call_at + 1, want)
                fixed += 1
        return fixed

    def _fix_cmd_crt_banner_resume_skip_8af9(self, out: bytearray) -> int:
        """CRT return 0x8AF9: jmp banner stub; noop-ret when main parse flag is set."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        flag_rva = 0x41F58
        guard_off = 0x8F40 - self.text_rva
        guard_end = 0x8F60 - self.text_rva
        banner_off = 0x8AFE - self.text_rva
        banner_end = 0x8B23 - self.text_rva
        done_rva = 0x8B1C
        if (guard_off < 0 or guard_end <= guard_off or banner_off < 0
                or banner_end <= banner_off or banner_end > len(out)):
            return 0
        cmp_end = 0x8AFE + 7
        jne_from = 0x8B05
        je_from = 0x8B0E
        jmp_from = 0x8B16
        if not (-2147483648 <= (done_rva - (jne_from + 6)) <= 2147483647
                and -2147483648 <= (0x8B23 - (je_from + 6)) <= 2147483647
                and -128 <= (0x8B20 - jmp_from) <= 127
                and -2147483648 <= (0x8F61 - (0x8F51 + 5)) <= 2147483647):
            return 0
        banner = (
            b'\x83\x3d' + struct.pack('<i', flag_rva - cmp_end) + b'\x00'
            + b'\x0f\x85' + struct.pack('<i', done_rva - (jne_from + 6))
            + b'\x48\x85\xc0'
            + b'\x0f\x84' + struct.pack('<i', 0x8B23 - (je_from + 6))
            + b'\xeb' + struct.pack('b', 0x8B20 - jmp_from)
            + b'\x90' * (done_rva - 0x8AFE - 24)
            + b'\x31\xc0'
            + b'\xe9' + struct.pack('<i', 0x2DC44 - (done_rva + 7))
        )
        if len(banner) != banner_end - banner_off:
            return 0
        off = 0x8AF9 - self.text_rva
        end = 0x8AFE - self.text_rva
        patch = b'\xe9' + struct.pack('<i', 0x8AFE - (0x8AF9 + 5))
        guard = bytearray()
        cmp_g = 0x8F40 + 7
        guard += b'\x83\x3d' + struct.pack('<i', flag_rva - cmp_g) + b'\x00'
        guard += b'\x0f\x85' + struct.pack('<i', 0x8F56 - (0x8F47 + 6))
        guard += b'\x48\x83\xc4\x08'
        guard += b'\xe9' + struct.pack('<i', 0x8F61 - (0x8F51 + 5))
        guard += b'\x31\xc0' + b'\xe9' + struct.pack('<i', 0x2DC44 - (0x8F56 + 7))
        guard += b'\x90' * (guard_end - guard_off - len(guard))
        if len(guard) > guard_end - guard_off:
            return 0
        fixed = 0
        if out[guard_off:guard_end] != bytes(guard):
            out[guard_off:guard_end] = bytes(guard)
            fixed += 1
        if out[banner_off:banner_end] != banner:
            out[banner_off:banner_end] = banner
            fixed += 1
        if len(patch) == end - off and out[off:end] != patch:
            out[off:end] = patch
            fixed += 1
        return fixed

    def _fix_cmd_crt_banner_wcsncpy_or_skip_8afc(self, out: bytearray) -> int:
        """0x8AFE: skip broken CRT banner wcsncpy (must not overlap 0x8AF9 jmp)."""
        if not self.text_rva:
            return 0
        stub_off = 0x8AFE - self.text_rva
        stub_end = 0x8B23 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        jmp_from = 0x8B09
        if not (-128 <= (0x8B20 - jmp_from) <= 127):
            return 0
        body = (
            b'\x48\x85\xc0'
            + b'\x0f\x84' + struct.pack('<i', 0x8B23 - 0x8B07)
            + b'\xeb' + struct.pack('b', 0x8B20 - jmp_from)
        )
        if len(body) > stub_end - stub_off:
            return 0
        patch = body + b'\x90' * (stub_end - stub_off - len(body))
        if out[stub_off:stub_end] == patch:
            return 0
        out[stub_off:stub_end] = patch
        return 1

    def _fix_cmd_crt_skip_banner_print_8b74(self, out: bytearray) -> int:
        """Neutralize broken banner-print helper; return 0 so je 0x8BE0 skips it."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x8B74 - self.text_rva
        if off < 0 or off + 5 > len(out) or out[off] != 0xE8:
            return 0
        patch = b'\x31\xc0' + b'\x90' * 3
        if out[off:off + 5] == patch:
            return 0
        out[off:off + 5] = patch
        return 1

    def _fix_cmd_crt_banner_epilogue_pop_rbp_8b22(self, out: bytearray) -> int:
        """Translated orphan ``pop rbp`` at 0x8B22 corrupts stack on CRT resume."""
        if not self.text_rva:
            return 0
        off = 0x8B22 - self.text_rva
        if off < 0 or off >= len(out) or out[off] == 0x90:
            return 0
        if out[off] != 0x5D:
            return 0
        out[off] = 0x90
        return 1

    def _fix_cmd_banner_jne_2e4ac(self, out: bytearray) -> int:
        """Banner gate jne at 0x2E4AC: rel32 corrupted (target 0xC892E5EC) — fall through."""
        if not self.text_rva:
            return 0
        site_rva = 0x2E4AC
        off = site_rva - self.text_rva
        if off < 0 or off + 6 > len(out) or out[off:off + 2] != b'\x0f\x85':
            return 0
        rel = struct.unpack_from('<i', out, off + 2)[0]
        tgt = site_rva + 6 + rel
        if 0x80010000 <= tgt <= 0x80100000:
            return 0
        struct.pack_into('<i', out, off + 2, 0)
        return 1

    def _fix_cmd_version_banner_root_2e4bb(self, out: bytearray) -> int:
        """Startup banner: pass L\"X:\\\" stack root in RCX/RSI before GetVolumeInformationW."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x2E4B2 - self.text_rva
        end = 0x2E4BF - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        patch = (
            b'\x48\x8d\x4d\xe0'
            + b'\x48\x89\xce'
            + b'\x90' * (end - off - 7)
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_gvi_helper_force_success_1d3b6(self, out: bytearray) -> int:
        """Legacy no-op: epilogue fixed in _fix_cmd_gvi_helper_1d343."""
        return 0

    def _fix_cmd_version_banner_branch_2e4b1(self, out: bytearray) -> int:
        """/c wcscmp miss: jne to banner root 0x2E4B2 (after 6-byte jne at 0x2E4AC)."""
        if not self.text_rva:
            return 0
        rel_off = 0x91B7 - self.text_rva
        if rel_off < 0 or rel_off + 4 > len(out):
            return 0
        if out[0x91B5 - self.text_rva:0x91B5 - self.text_rva + 2] != b'\x0f\x85':
            return 0
        want = 0x2E4B2 - (0x91B5 + 6)
        if struct.unpack_from('<i', out, rel_off)[0] == want:
            return 0
        struct.pack_into('<i', out, rel_off, want)
        return 1

    def _fix_cmd_crt_getmainargs_fallthrough_8769(self, out: bytearray) -> int:
        """CRT switch tail at 0x875F falls into orphan epilogue at 0x8769 — use 0x8699."""
        if not self.text_rva:
            return 0
        site_rva = 0x8769
        good = 0x8699
        off = site_rva - self.text_rva
        if off < 0 or off + 5 > len(out):
            return 0
        if out[off:off + 3] != b'\x48\xc7\xc0':
            return 0
        rel = good - (site_rva + 5)
        patch = b'\xe9' + struct.pack('<i', rel)
        if out[off:off + 5] == patch:
            return 0
        out[off:off + 5] = patch
        return 1

    def _fix_cmd_crt_orphan_epilogue_8770(self, out: bytearray) -> int:
        """Orphan pop/ret at 0x8770: jmp post-call site 0x8648 instead of ret RIP=0."""
        if not self.text_rva:
            return 0
        site_rva = 0x8770
        good = 0x8648
        off = site_rva - self.text_rva
        if off < 0 or off + 5 > len(out) or out[off] != 0x5F:
            return 0
        rel = good - (site_rva + 5)
        patch = b'\xe9' + struct.pack('<i', rel)
        if out[off:off + 5] == patch:
            return 0
        out[off:off + 5] = patch
        return 1

    def _fix_cmd_crt_getmainargs_flag_gate_877b(self, out: bytearray) -> int:
        """0x877B getmainargs: if parse flag set, xor eax,eax; ret (skip CRT re-init)."""
        if not self.text_rva:
            return 0
        flag_rva = 0x41F58
        entry_rva = 0x877B
        cont_rva = 0x8780
        cave_rva = 0x8BF7
        cave_end = 0x8C16
        entry_off = entry_rva - self.text_rva
        cave_off = cave_rva - self.text_rva
        if entry_off < 0 or cave_off < 0 or cave_end - cave_rva < 22:
            return 0
        if entry_off + 5 > len(out) or cave_end - self.text_rva > len(out):
            return 0
        if out[entry_off] != 0x55:
            return 0
        cmp_end = cave_rva + 7
        jne_from = cave_rva + 7
        skip_rva = cave_rva + 22
        jmp_from = cave_rva + 17
        if not (-2147483648 <= (skip_rva - (jne_from + 6)) <= 2147483647
                and -2147483648 <= (cont_rva - (jmp_from + 5)) <= 2147483647
                and -2147483648 <= (cave_rva - (entry_rva + 5)) <= 2147483647):
            return 0
        cave = (
            b'\x83\x3d' + struct.pack('<i', flag_rva - cmp_end) + b'\x00'
            + b'\x0f\x85' + struct.pack('<i', skip_rva - (jne_from + 6))
            + b'\x55' + b'\x48\x89\xe5'
            + b'\xe9' + struct.pack('<i', cont_rva - (jmp_from + 5))
            + b'\x31\xc0\xc3'
            + b'\x90' * (cave_end - skip_rva - 3)
        )
        if len(cave) != cave_end - cave_rva:
            return 0
        patch = b'\xe9' + struct.pack('<i', cave_rva - (entry_rva + 5))
        fixed = 0
        if out[cave_off:cave_off + len(cave)] != cave:
            out[cave_off:cave_off + len(cave)] = cave
            fixed += 1
        if out[entry_off:entry_off + 5] != patch:
            out[entry_off:entry_off + 5] = patch
            fixed += 1
        return fixed

    def _fix_cmd_interactive_skip_closehandle_2e66e(self, out: bytearray) -> int:
        """Banner tail: skip null IAT CloseHandle call; enter live REPL at 0x2EAD4."""
        if not self.text_rva:
            return 0
        stub_off = 0x2E66E - self.text_rva
        stub_end = 0x2E682 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        jmp_at = stub_off
        if out[stub_off] == 0xF0 and out[stub_off + 1] == 0xE9:
            jmp_at = stub_off + 1
        elif out[stub_off] == 0xE9:
            jmp_at = stub_off
        elif out[stub_off:stub_off + 2] == b'\x48\xb8':
            pass  # fall through: overwrite movabs with jmp below
        else:
            return 0
        jmp_from = self.text_rva + jmp_at
        rel = 0x2EAD6 - (jmp_from + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (stub_end - jmp_at - 5)
        if len(patch) > stub_end - jmp_at:
            return 0
        out[jmp_at:jmp_at + len(patch)] = patch
        if jmp_at > stub_off:
            out[stub_off] = 0x90
        return 1

    def _fix_cmd_repl_prompt_entry_nop_2eae9(self, out: bytearray) -> int:
        """Clear invalid 0x0000 prefix at REPL prompt entry (0x2EAE9)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        off = 0x2EAE9 - self.text_rva
        if off < 0 or off + 2 > len(out):
            return 0
        if out[off:off + 2] == b'\x90\x90':
            return 0
        if out[off:off + 2] != b'\x00\x00':
            return 0
        out[off:off + 2] = b'\x90\x90'
        return 1

    def _fix_cmd_interactive_repl_jmp_2e6f1(self, out: bytearray) -> int:
        """Banner r8!=2 paths jmp exit 0x2E6F1 — snap to live REPL continuation 0x2EAD4."""
        if not self.text_rva:
            return 0
        good = 0x2EAD6
        fixed = 0
        for site_rva in (0x2E683, 0x2E68C):
            off = site_rva - self.text_rva
            if off < 0 or off + 6 > len(out):
                continue
            if out[off] == 0xE9 and off + 5 <= len(out):
                rel = struct.unpack_from('<i', out, off + 1)[0]
                if site_rva + 5 + rel != 0x2E6F1:
                    continue
                want = good - (site_rva + 5)
                struct.pack_into('<i', out, off + 1, want)
                fixed += 1
            elif out[off:off + 2] == b'\x0f\x85':
                rel = struct.unpack_from('<i', out, off + 2)[0]
                if site_rva + 6 + rel != 0x2E6F1:
                    continue
                want = good - (site_rva + 6)
                struct.pack_into('<i', out, off + 2, want)
                fixed += 1
        return fixed

    def _fix_cmd_interactive_repl_edi_gate_2e72d(self, out: bytearray) -> int:
        """REPL gate: edi!=ebx took wrong path — jmp to live continuation only.

        Do not redirect 0x2EAD8 into a synthetic print/read loop; natural ReadConsole
        at 0x3D193 must block and return into the parse path.
        """
        if not self.win10_test_shim or not self.text_rva:
            return 0
        fixed = 0
        for gate_rva, prompt_rva in ((0x2E72F, 0x2E76A),):
            off = gate_rva - self.text_rva
            if off < 0 or off + 6 > len(out):
                continue
            rel = prompt_rva - (gate_rva + 5)
            if not (-2147483648 <= rel <= 2147483647):
                continue
            patch = b'\xe9' + struct.pack('<i', rel) + b'\x90'
            if out[off:off + 2] == b'\x0f\x85':
                if out[off:off + 6] != patch:
                    out[off:off + 6] = patch
                    fixed += 1
            elif out[off:off + 6] != patch and out[off] == 0xE9:
                if out[off:off + 6] != patch:
                    out[off:off + 6] = patch
                    fixed += 1
        return fixed

    def _fix_cmd_repl_jmp_2e728_to_gate(self, out: bytearray) -> int:
        """Banner epilogue jmp at 0x2E728 must land on REPL gate (0x2EAD6), not mid-instruction."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        site_rva = 0x2E728
        gate_rva = 0x2EAD6
        off = site_rva - self.text_rva
        if off < 0 or off + 5 > len(out) or out[off] != 0xE9:
            return 0
        rel = gate_rva - (site_rva + 5)
        patch = b'\xe9' + struct.pack('<i', rel)
        if out[off:off + 5] == patch:
            return 0
        out[off:off + 5] = patch
        return 1

    def _fix_cmd_interactive_skip_repl_exit_ret(self, out: bytearray) -> int:
        """Skip orphan ``mov rbp,rsp; pop rbp; ret`` before live REPL gates."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        fixed = 0
        for ep_rva, gate_rva in ((0x2E728, 0x2EAD6), (0x2EAC8, 0x2EAD6)):
            off = ep_rva - self.text_rva
            if off < 0 or off + 5 > len(out):
                continue
            if out[off:off + 3] != b'\x48\x89\xec':
                continue
            rel = gate_rva - (ep_rva + 5)
            if not (-2147483648 <= rel <= 2147483647):
                continue
            patch = b'\xe9' + struct.pack('<i', rel)
            if out[off:off + 5] != patch:
                out[off:off + 5] = patch
                fixed += 1
        return fixed

    def _fix_cmd_interactive_startup_91b5(self, out: bytearray) -> int:
        """Print version banner, then ReadConsole hook at 0x3D196 (prints drive prompt)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        fixed_print = self._ensure_cmd_wide_stdout_print_stub(out)
        if not self._cmd_stdout_print_rva:
            return 0
        print_rva = self._cmd_stdout_print_rva
        gate_off = 0x91B5 - self.text_rva
        if gate_off < 0 or gate_off + 5 > len(out):
            return 0
        stub = bytearray()
        stub += b'\x48\xba' + struct.pack('<Q', self.new_base + 0x414E0)
        c1 = 0 + len(stub)
        stub += b'\xe8' + struct.pack('<i', print_rva - (c1 + 5))
        jf = 0 + len(stub)
        stub += b'\xe9' + struct.pack('<i', 0x3D196 - (jf + 5))
        need = len(stub)
        avoid = [(0x8000, 0x9200), (0x8FF0, 0x9048), (0x92B0, 0x92D0),
                 (0x2E490, 0x2E520)]
        cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
        if cave_off is None:
            cave_off = self._find_text_nop_cave(
                out, need, avoid=[(0x92B0, 0x92D0), (0x2E490, 0x2E520)])
        if cave_off is None:
            return 0
        cave_rva = self.text_rva + cave_off
        stub = bytearray()
        stub += b'\x48\xba' + struct.pack('<Q', self.new_base + 0x414E0)
        c1 = cave_rva + len(stub)
        stub += b'\xe8' + struct.pack('<i', print_rva - (c1 + 5))
        jf = cave_rva + len(stub)
        stub += b'\xe9' + struct.pack('<i', 0x3D196 - (jf + 5))
        cave_sz = need
        patch_gate = b'\xe9' + struct.pack('<i', cave_rva - (0x91B5 + 5))
        fixed = 0
        body = stub + b'\x90' * (cave_sz - len(stub))
        if out[cave_off:cave_off + cave_sz] != body:
            out[cave_off:cave_off + cave_sz] = body
            fixed += 1
        if out[gate_off:gate_off + 5] != patch_gate:
            out[gate_off:gate_off + 5] = patch_gate
            fixed += 1
        self._cmd_interactive_startup_rva = cave_rva
        return fixed + fixed_print

    def _fix_cmd_force_interactive_banner_91b6(self, out: bytearray) -> int:
        """Interactive: always enter version banner (test eax,eax often skips on Win10)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        off = 0x91B5 - self.text_rva
        if off < 0 or off + 6 > len(out) or out[off:off + 2] != b'\x0f\x85':
            return 0
        rel = 0x2E4B2 - (0x91B5 + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90'
        if out[off:off + 6] == patch:
            return 0
        out[off:off + 6] = patch
        return 1

    def _fix_cmd_parse_line_call_3cdc7(self, out: bytearray) -> int:
        """Snap ``call`` into cmd parse helper (±8 of 0x3CDC8) to push-rbx entry."""
        if not self.text_rva:
            return 0
        target = 0x3CDC8
        fixed = 0
        for call_rva in (0x3D029, 0x3D046, 0x3D170, 0x3D1ED):
            off = call_rva - self.text_rva
            if off < 0 or off + 5 > len(out) or out[off] != 0xE8:
                continue
            want = target - (call_rva + 5)
            if struct.unpack_from('<i', out, off + 1)[0] != want:
                struct.pack_into('<i', out, off + 1, want)
                fixed += 1
        lo_rva, hi_rva = target - 8, target + 8
        i = 0
        while i < len(out) - 5:
            call_at = None
            if out[i] == 0xF0 and i + 6 <= len(out) and out[i + 1] == 0xE8:
                call_at = i + 1
            elif out[i] == 0xE8:
                call_at = i
            if call_at is not None:
                call_rva = self.text_rva + call_at
                rel = struct.unpack_from('<i', out, call_at + 1)[0]
                tgt = call_rva + 5 + rel
                if lo_rva <= tgt <= hi_rva and tgt != target:
                    want = target - (call_rva + 5)
                    if struct.unpack_from('<i', out, call_at + 1)[0] != want:
                        struct.pack_into('<i', out, call_at + 1, want)
                        fixed += 1
                i = call_at + 5
            else:
                i += 1
        return fixed

    def _fix_cmd_readconsole_call_sites(self, out: bytearray) -> int:
        """Snap ``call`` into ReadConsole helper (±0x40 of 0x3D196) to aligned entry."""
        if not self.text_rva:
            return 0
        target = 0x3D193
        fixed = 0
        for call_rva in (0x2EB25,):
            off = call_rva - self.text_rva
            if off < 0 or off + 5 > len(out) or out[off] != 0xE8:
                continue
            want = target - (call_rva + 5)
            if struct.unpack_from('<i', out, off + 1)[0] != want:
                struct.pack_into('<i', out, off + 1, want)
                fixed += 1
        lo_rva, hi_rva = target - 0x40, target + 0x40
        i = 0
        while i < len(out) - 5:
            call_at = None
            if out[i] == 0xF0 and i + 6 <= len(out) and out[i + 1] == 0xE8:
                call_at = i + 1
            elif out[i] == 0xE8:
                call_at = i
            if call_at is not None:
                call_rva = self.text_rva + call_at
                rel = struct.unpack_from('<i', out, call_at + 1)[0]
                tgt = call_rva + 5 + rel
                if lo_rva <= tgt <= hi_rva and tgt != target:
                    want = target - (call_rva + 5)
                    if struct.unpack_from('<i', out, call_at + 1)[0] != want:
                        struct.pack_into('<i', out, call_at + 1, want)
                        fixed += 1
                i = call_at + 5
            else:
                i += 1
        return fixed

    def _fix_cmd_interactive_prompt_print_2eb23(self, out: bytearray) -> int:
        """ReadConsole helper entry: print L\"C:\\> \" via banner stub, then original prologue.

        Cave must not overlap 0x90E9 (drive-letter path jmp target) — use a distant nop run.
        """
        if not self.win10_test_shim or not self.text_rva:
            return 0
        entry_rva = 0x3D196
        entry_off = entry_rva - self.text_rva
        need = 38
        avoid = [(0x8000, 0x9200), (0x8FF0, 0x9048)]
        cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
        if cave_off is None:
            cave_off = self._find_nop_run(out, need)
        if cave_off is None:
            return 0
        cave_rva = self.text_rva + cave_off
        cave_end = cave_rva + max(need, 42)
        if entry_off < 0 or entry_off + 8 > len(out):
            return 0
        if cave_off < 0 or cave_end - self.text_rva > len(out):
            return 0
        if not self._cmd_stdout_print_rva:
            self._ensure_cmd_wide_stdout_print_stub(out)
        print_rva = self._cmd_stdout_print_rva or 0x2D813
        orig = bytes(out[entry_off:entry_off + 8])
        cont_rva = entry_rva + 8
        stub = bytearray()
        stub += b'\x48\xba' + struct.pack('<Q', self.new_base + 0x414B0)
        call_at = cave_rva + len(stub)
        stub += b'\xe8' + struct.pack('<i', print_rva - (call_at + 5))
        stub += orig
        jmp_from = cave_rva + len(stub)
        stub += b'\xe9' + struct.pack('<i', cont_rva - (jmp_from + 5))
        if len(stub) > cave_end - cave_rva:
            return 0
        patch = b'\xe9' + struct.pack('<i', cave_rva - (entry_rva + 5))
        fixed = 0
        cave_sz = cave_end - cave_rva
        body = stub + b'\x90' * (cave_sz - len(stub))
        if out[cave_off:cave_off + cave_sz] != body:
            out[cave_off:cave_off + cave_sz] = body
            fixed += 1
        if out[entry_off:entry_off + 5] != patch:
            out[entry_off:entry_off + 5] = patch
            fixed += 1
        return fixed

    def _fix_cmd_banner_swprintf_format_rdx(self, out: bytearray) -> int:
        """Banner swprintf: mov rdx must point at wide format in .rdata, not a code VA."""
        if not self.text_rva:
            return 0
        fixes = (
            (0x2E4FF, 0x50668),   # L"Microsoft Windows 2000 [Version %1]%0\\r\\n"
        )
        fixed = 0
        for site_rva, str_rva in fixes:
            off = site_rva - self.text_rva
            if off < 0 or off + 10 > len(out) or out[off:off + 2] != b'\x48\xba':
                continue
            want_va = self.new_base + str_rva
            patch = b'\x48\xba' + struct.pack('<Q', want_va)
            if out[off:off + 10] != patch:
                out[off:off + 10] = patch
                fixed += 1
        return fixed

    def _fix_cmd_banner_copyright_clear_rdx_2e5ac(self, out: bytearray) -> int:
        """Copyright print (0x2E5C3): clear RDX so writer uses RCX buffer not format ptr."""
        if not self.text_rva:
            return 0
        off = 0x2E5AC - self.text_rva
        if off < 0 or off + 10 > len(out) or out[off:off + 2] != b'\x48\xba':
            return 0
        patch = b'\x48\x31\xd2' + b'\x90' * 8
        if out[off:off + 10] == patch:
            return 0
        out[off:off + 10] = patch
        return 1

    def _fix_cmd_banner_copyright_string_rcx_2e5a2(self, out: bytearray) -> int:
        """Copyright line: RCX must point at L\"Copyright...\" in .rdata (0x4F78C)."""
        if not self.text_rva:
            return 0
        off = 0x2E5A2 - self.text_rva
        if off < 0 or off + 10 > len(out) or out[off:off + 2] != b'\x48\xb9':
            return 0
        want_va = self.new_base + 0x4F78C
        patch = b'\x48\xb9' + struct.pack('<Q', want_va)
        if out[off:off + 10] == patch:
            return 0
        out[off:off + 10] = patch
        return 1

    def _fix_cmd_banner_skip_post_copyright_2e5ce(self, out: bytearray) -> int:
        """After copyright print epilogue, jmp REPL — volume/heap tail AVs under shim."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        site_rva = 0x2E5CE
        end_rva = 0x2EAD6
        off = site_rva - self.text_rva
        end = end_rva - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        rel = end_rva - (site_rva + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (end - off - 5)
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_banner_swprintf_epilogue_2e520(self, out: bytearray) -> int:
        """Banner swprintf: leaf frame (sub/add rsp) and restore ``lea rax,[rbp-0xcc]``."""
        if not self.text_rva:
            return 0
        wrap_off = 0x2E50C - self.text_rva
        ep_off = 0x2E51F - self.text_rva
        lea_off = 0x2E523 - self.text_rva
        if wrap_off < 0 or wrap_off + 13 > len(out) or ep_off < 0 or ep_off + 4 > len(out):
            return 0
        if lea_off < 0 or lea_off + 17 > len(out):
            return 0
        wrap_patch = b'\x48\x83\xec\x28' + b'\x90' * 9
        ep_patch = b'\x48\x83\xc4\x28'
        mov_off = 0x2E528 - self.text_rva
        if mov_off < 0 or mov_off + 10 > len(out):
            return 0
        mov_rcx = bytes(out[mov_off:mov_off + 10])
        if mov_rcx[0:2] != b'\x48\xb9':
            mov_rcx = b'\x48\xb9' + struct.pack('<Q', self.new_base + 0x417A0)
        lea_patch = b'\x48\x8d\x85\x34\xff\xff\xff' + mov_rcx
        fixed = 0
        if out[wrap_off:wrap_off + 13] != wrap_patch:
            out[wrap_off:wrap_off + 13] = wrap_patch
            fixed += 1
        if out[ep_off:ep_off + 4] != ep_patch:
            out[ep_off:ep_off + 4] = ep_patch
            fixed += 1
        if out[lea_off:lea_off + len(lea_patch)] != lea_patch:
            out[lea_off:lea_off + len(lea_patch)] = lea_patch
            fixed += 1
        rdx_off = 0x2E534 - self.text_rva
        if 0 <= rdx_off < len(out) - 3 and out[rdx_off:rdx_off + 3] != b'\x48\x89\xc2':
            out[rdx_off:rdx_off + 3] = b'\x48\x89\xc2'
            fixed += 1
        return fixed

    def _fix_cmd_banner_gvi_epilogue_pop_rbp_2e4d3(self, out: bytearray) -> int:
        """GVI wrapper pushes rbp (0x2E4BF) but epilogue popped r13 — fix to pop rbp."""
        if not self.text_rva:
            return 0
        off = 0x2E4D3 - self.text_rva
        if off < 0 or off + 2 > len(out) or out[off:off + 2] != b'\x41\x5d':
            return 0
        if out[off:off + 2] == b'\x5d\x90':
            return 0
        out[off:off + 2] = b'\x5d\x90'
        return 1

    def _fix_cmd_banner_swprintf_iat_call_2e519(self, out: bytearray) -> int:
        """Replace ``call rsi`` through IAT cell with direct ``ff15`` swprintf."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        off = 0x2E519 - self.text_rva
        if off < 0 or off + 6 > len(out) or out[off:off + 2] != b'\xff\xd6':
            return 0
        iat = self._loader_iat_va('MSVCRT.dll', 'swprintf')
        if not iat:
            iat = self._resolve_iat_slot_va(self.new_base + 0x6E4B9)
        if not iat:
            return 0
        at_rva = 0x2E519
        rel = iat - (self.new_base + at_rva + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xff\x15' + struct.pack('<i', rel) + b'\x90'
        if out[off:off + 6] == patch:
            return 0
        out[off:off + 6] = patch
        return 1

    def _fix_cmd_banner_format_swprintf_s(self, out: bytearray, sect_rva: int) -> int:
        """Banner format uses FormatMessage %%1; MSVCRT swprintf needs %%s.

        The wide format string lives in ``.rsrc`` (not ``.data``) in the
        translated image.  Because section layout shifts between builds, we
        search for the ``%1`` needle dynamically rather than relying on a
        hardcoded RVA.

        Also null-terminates the FormatMessage %%0 escape which swprintf does
        not understand, turning ``...%s]%0\\r\\n`` into ``...%s]``.
        """
        # Dynamic search: wide "%1" = 25 00 31 00, followed by "]%0" = 5D 00 25 00 30 00
        needle1 = b'\x25\x00\x31\x00\x5D\x00\x25\x00\x30\x00'  # %1]%0 in UTF-16LE
        pos = out.find(needle1)
        if pos < 0:
            return 0
        # Patch %1 → %s at '1' byte (pos+2)
        if out[pos:pos + 4] != b'\x25\x00\x73\x00':  # not already %s
            out[pos + 2:pos + 4] = b'\x73\x00'
        # Null-terminate at ']' (pos+4) to remove %0\r\n
        if pos + 4 + 2 <= len(out) and out[pos + 4:pos + 4 + 2] != b'\x00\x00':
            out[pos + 4:pos + 4 + 2] = b'\x00\x00'
        return 1

    def _fix_cmd_data_banner_format_swprintf_s(self, out: bytearray, sect_rva: int) -> int:
        return self._fix_cmd_banner_format_swprintf_s(out, sect_rva)

    def _fix_cmd_data_os_version_fmt(self, out: bytearray, sect_rva: int) -> int:
        """Wide L\"%d.%02d\" for GetVersion major/minor (RVA 0x4149C)."""
        msg_rva = 0x4149C
        off = msg_rva - sect_rva
        want = '%d.%02d'.encode('utf-16-le') + b'\x00\x00'
        if off < 0 or off + len(want) > len(out):
            return 0
        if out[off:off + len(want)] == want:
            return 0
        out[off:off + len(want)] = want
        return 1

    def _fix_cmd_data_os_version_buffer(self, out: bytearray, sect_rva: int) -> int:
        """Writable wide OS version scratch (RVA 0x414A0); filled at runtime via GetVersion."""
        msg_rva = 0x414A0
        off = msg_rva - sect_rva
        pad = 32
        if off < 0 or off + pad > len(out):
            return 0
        want = b'\x00' * pad
        if out[off:off + pad] == want:
            return 0
        out[off:off + pad] = want
        return 1

    def _fix_cmd_data_prompt_buffer(self, out: bytearray, sect_rva: int) -> int:
        """Writable wide prompt path buffer (RVA 0x414B0, 520 wchar bytes)."""
        msg_rva = 0x414B0
        off = msg_rva - sect_rva
        pad = 520
        if off < 0 or off + pad > len(out):
            return 0
        want = b'\x00' * pad
        if out[off:off + pad] == want:
            return 0
        out[off:off + pad] = want
        return 1

    def _fix_cmd_data_readline_buffer(self, out: bytearray, sect_rva: int) -> int:
        """Writable wide ReadConsole line buffer (RVA 0x41600, 1024 bytes)."""
        msg_rva = 0x41600
        off = msg_rva - sect_rva
        pad = 1024
        if off < 0 or off + pad > len(out):
            return 0
        want = b'\x00' * pad
        if out[off:off + pad] == want:
            return 0
        out[off:off + pad] = want
        return 1

    def _fix_cmd_banner_swprintf_version_arg_r8_2e50a(self, out: bytearray) -> int:
        """Banner swprintf %%1 arg: ``mov r8d,eax`` must be ``mov r8,rsi`` (version ptr)."""
        if not self.text_rva:
            return 0
        off = 0x2E509 - self.text_rva
        if off < 0 or off + 3 > len(out):
            return 0
        patch = b'\x49\x89\xf0'  # mov r8, rsi
        if out[off:off + 3] == patch:
            return 0
        if out[off:off + 3] != b'\x41\x89\xc0':
            return 0
        out[off:off + 3] = patch
        return 1

    def _fix_cmd_banner_version_string_ptr_2e4ef(self, out: bytearray) -> int:
        """Version %%1: load wide string at 0x414A0, not a broken IAT/name-table deref."""
        if not self.text_rva:
            return 0
        off = 0x2E4EF - self.text_rva
        if off < 0 or off + 13 > len(out) or out[off:off + 2] != b'\x48\xbe':
            return 0
        want_va = self.new_base + 0x414A0
        patch = b'\x48\xbe' + struct.pack('<Q', want_va) + b'\x90\x90\x90'
        if out[off:off + 13] == patch:
            return 0
        out[off:off + 13] = patch
        return 1

    def _fix_cmd_banner_fill_version_cave(self, out: bytearray) -> int:
        """Before banner swprintf, GetVersion + swprintf into 0x414A0 (dynamic major.minor)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        site_rva = 0x2E4E8
        resume_rva = 0x2E4EF
        site_off = site_rva - self.text_rva
        if site_off < 0 or site_off + 3 > len(out):
            return 0
        if out[site_off:site_off + 3] not in (b'\x48\x8d\x85', b'\x48\xbe'):
            return 0
        getver = self._loader_iat_va('KERNEL32.dll', 'GetVersion')
        if not getver:
            getver = self._resolve_iat_slot_va(self.old_base + 0x111C)
        swp = self._loader_iat_va('MSVCRT.dll', 'swprintf')
        if not getver or not swp:
            return 0
        buf_va = self.new_base + 0x414A0
        fmt_va = self.new_base + 0x4149C
        need = 80
        cave_rva = 0x2E800
        cave_off = cave_rva - self.text_rva
        if cave_off < 0 or cave_off + need > len(out):
            return 0
        avoid = []
        cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
        if cave_off is None:
            cave_off = self._find_nop_run(out, need, avoid=[(0x2E5CE, 0x2E800)])
        if cave_off is not None:
            cave_rva = self.text_rva + cave_off
        else:
            cave_off = cave_rva - self.text_rva
        body = bytearray()
        body += b'\x48\x83\xec\x28'
        ff_gv = cave_rva + len(body)
        rel = getver - (self.new_base + ff_gv + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x89\xc3'                           # mov ebx, eax
        body += b'\x41\x0f\xb6\xc3'                   # movzx r8d, bl (major)
        body += b'\x41\x0f\xb6\xcb'                   # movzx r9d, bh (minor)
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        body += b'\x48\xba' + struct.pack('<Q', fmt_va)
        ff_swp = cave_rva + len(body)
        rel = swp - (self.new_base + ff_swp + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\x83\xc4\x28'
        body += b'\x48\x8d\x85\x34\xff\xff\xff'       # lea rax, [rbp-0xCC]
        jmp_from = cave_rva + len(body)
        body += b'\xe9' + struct.pack('<i', resume_rva - (jmp_from + 5))
        if len(body) > need:
            return 0
        body += b'\x90' * (need - len(body))
        call_rel = cave_rva - (site_rva + 5)
        if not (-2147483648 <= call_rel <= 2147483647):
            return 0
        site_patch = b'\xe8' + struct.pack('<i', call_rel) + b'\x90\x90'
        fixed = 0
        if out[cave_off:cave_off + need] != body:
            out[cave_off:cave_off + need] = body
            fixed += 1
        if out[site_off:site_off + 7] != site_patch:
            out[site_off:site_off + 7] = site_patch
            fixed += 1
        return fixed

    def _fix_cmd_banner_repl_frame_fixup(self, out: bytearray) -> int:
        """Banner + REPL: translated ``mov rbp,r13`` / ``mov rsp,r12`` corrupt the stack."""
        if not self.text_rva:
            return 0
        fixed = 0
        lo = 0x2E4B2 - self.text_rva
        hi = 0x2EB40 - self.text_rva
        if lo < 0:
            return 0
        i = max(0, lo)
        while i < min(hi, len(out) - 3):
            if out[i:i + 3] == b'\x49\x89\xe5':
                out[i:i + 3] = b'\x48\x89\xe5'
                fixed += 1
            elif out[i:i + 3] == b'\x4c\x89\xec':
                out[i:i + 3] = b'\x48\x89\xec'
                fixed += 1
            i += 1
        return fixed

    def _fix_cmd_banner_copyright_print_leaf_2e5b8(self, out: bytearray) -> int:
        """Copyright print wrapper at 0x2E5B8: leaf frame — must not clobber main rbp."""
        if not self.text_rva:
            return 0
        wrap_off = 0x2E5B7 - self.text_rva
        ep_off = 0x2E5C9 - self.text_rva
        call_off = 0x2E5C4 - self.text_rva
        if wrap_off < 0 or wrap_off + 13 > len(out) or ep_off < 0 or ep_off + 5 > len(out):
            return 0
        if call_off < 0 or call_off >= len(out) or out[call_off] != 0xE8:
            return 0
        wrap_patch = b'\x48\x83\xec\x28' + b'\x90' * 9
        ep_patch = b'\x48\x83\xc4\x28\x90'
        fixed = 0
        if out[wrap_off:wrap_off + 13] != wrap_patch:
            out[wrap_off:wrap_off + 13] = wrap_patch
            fixed += 1
        if out[ep_off:ep_off + 5] != ep_patch:
            out[ep_off:ep_off + 5] = ep_patch
            fixed += 1
        return fixed

    def _fix_cmd_banner_line_print_leaf_2e536(self, out: bytearray) -> int:
        """Banner line print wrapper at 0x2E537: leaf frame — preserve main rbp."""
        if not self.text_rva:
            return 0
        wrap_off = 0x2E537 - self.text_rva
        ep_off = 0x2E547 - self.text_rva
        call_off = 0x2E542 - self.text_rva
        wrap_len = 11
        if wrap_off < 0 or wrap_off + wrap_len > len(out) or ep_off < 0 or ep_off + 5 > len(out):
            return 0
        if call_off < 0 or call_off >= len(out) or out[call_off] != 0xE8:
            return 0
        wrap_patch = b'\x48\x83\xec\x28' + b'\x90' * (wrap_len - 4)
        ep_patch = b'\x48\x83\xc4\x28\x90'
        fixed = 0
        if out[wrap_off:wrap_off + wrap_len] != wrap_patch:
            out[wrap_off:wrap_off + wrap_len] = wrap_patch
            fixed += 1
        if out[ep_off:ep_off + 5] != ep_patch:
            out[ep_off:ep_off + 5] = ep_patch
            fixed += 1
        return fixed

    def _fix_cmd_repl_prompt_cave(self, out: bytearray) -> int:
        """Leaf cave: print wide prompt at 0x414B0 via stdout helper (returns with ret)."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        if not self._cmd_stdout_print_rva:
            self._ensure_cmd_wide_stdout_print_stub(out)
        print_rva = self._cmd_stdout_print_rva or 0x2D813
        if not print_rva:
            return 0
        buf_va = self.new_base + 0x414B0
        need = 32
        cave_rva = 0x2E6A0
        cave_off = cave_rva - self.text_rva
        if cave_off < 0 or cave_off + need > len(out):
            avoid = [(0x8FF0, 0x9048), (0x2E5CE, 0x2E800)]
            cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
            if cave_off is None:
                cave_off = self._find_nop_run(out, need, avoid=avoid)
            if cave_off is None:
                return 0
            cave_rva = self.text_rva + cave_off
        body = bytearray()
        body += b'\x48\xba' + struct.pack('<Q', buf_va)
        cpr = cave_rva + len(body)
        body += b'\xe8' + struct.pack('<i', print_rva - (cpr + 5))
        body += b'\xc3'
        if len(body) > need:
            return 0
        body += b'\x90' * (need - len(body))
        if out[cave_off:cave_off + need] != body:
            out[cave_off:cave_off + need] = body
            return 1
        return 0

    def _fix_cmd_repl_readconsole_leaf_2eb18(self, out: bytearray) -> int:
        """REPL: print cwd prompt cave, call ReadConsole, jmp back to REPL gate."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        self._fix_cmd_repl_prompt_cave(out)
        wrap_off = 0x2EB18 - self.text_rva
        wrap_len = 18
        prompt_rva = 0x2E6A0
        rc_rva = 0x3D193
        gate_rva = 0x2EAD6
        if wrap_off < 0 or wrap_off + wrap_len > len(out):
            return 0
        body = bytearray()
        c0 = 0x2EB18
        body += b'\xe8' + struct.pack('<i', prompt_rva - (c0 + 5))
        c1 = 0x2EB18 + len(body)
        body += b'\xe8' + struct.pack('<i', rc_rva - (c1 + 5))
        jmp_from = 0x2EB18 + len(body)
        body += b'\xe9' + struct.pack('<i', gate_rva - (jmp_from + 5))
        if len(body) > wrap_len:
            return 0
        body += b'\x90' * (wrap_len - len(body))
        if out[wrap_off:wrap_off + 2] not in (b'\x41\x55', b'\x48\x83'):
            return 0
        if out[wrap_off:wrap_off + wrap_len] == body:
            return 0
        out[wrap_off:wrap_off + wrap_len] = body
        return 1

    def _fix_cmd_repl_seh_je_2ee65(self, out: bytearray) -> int:
        """SEH unwind epilogue: ``je`` after ``test rax,rax`` must skip 12 bytes, not 10."""
        if not self.text_rva:
            return 0
        pat = (
            b'\x65\x48\x8b\x04\x25\x00\x00\x00\x00'  # mov rax, gs:[0]
            + b'\x48\x85\xc0'                         # test rax, rax
            + b'\x74\x0a'                             # je +0x0a (wrong)
            + b'\x48\x8b\x00'                         # mov rax, [rax]
            + b'\x65\x48\x89\x04\x25\x00\x00\x00\x00' # mov gs:[0], rax
            + b'\x48\x89\xec'                         # mov rsp, rbp
        )
        want = pat[:12] + b'\x74\x0c' + pat[14:]
        fixed = 0
        pos = 0
        while True:
            idx = out.find(pat, pos)
            if idx < 0:
                break
            out[idx:idx + len(want)] = want
            fixed += 1
            pos = idx + len(want)
        return fixed

    def _fix_cmd_repl_readconsole_jmp_loop_2eb2a(self, out: bytearray) -> int:
        """After ReadConsole returns, jmp REPL gate — not orphan epilogue at 0x2EE43."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        site_rva = 0x2EB36
        loop_rva = 0x2EAD6
        off = site_rva - self.text_rva
        if off < 0 or off + 5 > len(out) or out[off] != 0xE9:
            return 0
        rel = loop_rva - (site_rva + 5)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        patch = b'\xe9' + struct.pack('<i', rel)
        if out[off:off + 5] == patch:
            return 0
        out[off:off + 5] = patch
        return 1

    def _fix_cmd_prompt_helper_cave_200e5(self, out: bytearray) -> int:
        """Replace broken volume-chain prompt (0x200E5) with GetCurrentDirectoryW + stdout write."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        entry_rva = 0x200E5
        entry_off = entry_rva - self.text_rva
        if entry_off < 0 or entry_off + 5 > len(out):
            return 0
        if not self._cmd_stdout_print_rva:
            self._ensure_cmd_wide_stdout_print_stub(out)
        print_rva = self._cmd_stdout_print_rva or 0x2D813
        getcwd = self._loader_iat_va('KERNEL32.dll', 'GetCurrentDirectoryW')
        wcslen = self._loader_iat_va('MSVCRT.dll', 'wcslen')
        if not getcwd or not wcslen:
            return 0
        buf_va = self.new_base + 0x414B0
        need = 96
        avoid = [(0x8FF0, 0x9048), (0x2E5CE, 0x2E6A0)]
        cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
        if cave_off is None:
            cave_off = self._find_nop_run(out, need, avoid=avoid)
        if cave_off is None:
            return 0
        cave_rva = self.text_rva + cave_off
        body = bytearray()
        body += b'\x48\x83\xec\x28'
        body += b'\xba\x04\x01\x00\x00'               # mov edx, 260
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        ff_gc = cave_rva + len(body)
        rel = getcwd - (self.new_base + ff_gc + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        ff_wl = cave_rva + len(body)
        rel = wcslen - (self.new_base + ff_wl + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\x89\xc3'                       # mov rbx, rax (wchar len)
        body += b'\x01\xdb'                           # add ebx, ebx (byte offset)
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        body += b'\x48\x01\xd9'                       # add rcx, rbx -> append ptr
        body += b'\x66\xc7\x01\x3e\x00'               # mov word [rcx], '>'
        body += b'\x66\xc7\x41\x02\x20\x00'           # mov word [rcx+2], ' '
        body += b'\x66\xc7\x41\x04\x00\x00'           # mov word [rcx+4], 0
        body += b'\x48\xba' + struct.pack('<Q', buf_va)
        cpr = cave_rva + len(body)
        body += b'\xe8' + struct.pack('<i', print_rva - (cpr + 5))
        body += b'\x48\x83\xc4\x28'
        body += b'\xc3'
        if len(body) > need:
            return 0
        body += b'\x90' * (need - len(body))
        call_rel = cave_rva - (entry_rva + 5)
        if not (-2147483648 <= call_rel <= 2147483647):
            return 0
        patch = b'\xe8' + struct.pack('<i', call_rel) + b'\xc3'
        fixed = 0
        if out[cave_off:cave_off + need] != body:
            out[cave_off:cave_off + need] = body
            fixed += 1
        if out[entry_off:entry_off + 6] != patch:
            out[entry_off:entry_off + 6] = patch
            fixed += 1
        return fixed

    def _fix_cmd_readconsole_cwd_fill_3d193(self, out: bytearray) -> int:
        """Before ReadConsole helper runs, fill 0x414B0 with GetCurrentDirectoryW + \"> \"."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        entry_rva = 0x3D193
        entry_off = entry_rva - self.text_rva
        resume_rva = 0x3D198
        if entry_off < 0 or entry_off + 5 > len(out):
            return 0
        getcwd = self._loader_iat_va('KERNEL32.dll', 'GetCurrentDirectoryW')
        wcslen = self._loader_iat_va('MSVCRT.dll', 'wcslen')
        if not getcwd or not wcslen:
            return 0
        buf_va = self.new_base + 0x414B0
        need = 80
        avoid = [(0x8FF0, 0x9048), (0x2E5CE, 0x2E800)]
        cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
        if cave_off is None:
            cave_off = self._find_nop_run(out, need, avoid=avoid)
        if cave_off is None:
            return 0
        cave_rva = self.text_rva + cave_off
        body = bytearray()
        body += b'\x48\x83\xec\x28'
        body += b'\xba\x04\x01\x00\x00'
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        ff_gc = cave_rva + len(body)
        rel = getcwd - (self.new_base + ff_gc + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        ff_wl = cave_rva + len(body)
        rel = wcslen - (self.new_base + ff_wl + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\x89\xc3'
        body += b'\x01\xdb'
        body += b'\x48\xb9' + struct.pack('<Q', buf_va)
        body += b'\x48\x01\xd9'
        body += b'\x66\xc7\x01\x3e\x00'
        body += b'\x66\xc7\x41\x02\x20\x00'
        body += b'\x66\xc7\x41\x04\x00\x00'
        body += b'\x48\x83\xc4\x28'
        jmp_from = cave_rva + len(body)
        body += b'\xe9' + struct.pack('<i', resume_rva - (jmp_from + 5))
        if len(body) > need:
            return 0
        body += b'\x90' * (need - len(body))
        jmp = b'\xe9' + struct.pack('<i', cave_rva - (entry_rva + 5))
        fixed = 0
        if out[cave_off:cave_off + need] != body:
            out[cave_off:cave_off + need] = body
            fixed += 1
        if out[entry_off:entry_off + 5] != jmp:
            out[entry_off:entry_off + 5] = jmp
            fixed += 1
        return fixed

    def _fix_cmd_read_line_cave_3cdc8(self, out: bytearray) -> int:
        """Replace broken parse/read helper entry (0x3CDC8) with kernel32 ReadConsoleW."""
        if not self.win10_test_shim or not self.text_rva:
            return 0
        entry_rva = 0x3CDC8
        entry_off = entry_rva - self.text_rva
        if entry_off < 0 or entry_off + 5 > len(out) or out[entry_off] != 0x55:
            return 0
        getstd = self._loader_iat_va('KERNEL32.dll', 'GetStdHandle')
        readc = self._loader_iat_va('KERNEL32.dll', 'ReadConsoleW')
        if not getstd or not readc:
            return 0
        line_va = self.new_base + 0x41600
        need = 80
        avoid = [(0x8FF0, 0x9048), (0x2E5CE, 0x2E700), (0x3CDC8, 0x3CE00)]
        cave_off = self._find_text_nop_cave(out, need, avoid=avoid)
        if cave_off is None:
            cave_off = self._find_nop_run(out, need, avoid=avoid)
        if cave_off is None:
            return 0
        cave_rva = self.text_rva + cave_off
        body = bytearray()
        body += b'\x48\x83\xec\x48'
        body += b'\xb9\xf5\xff\xff\xff'               # STD_INPUT_HANDLE
        ff_gs = cave_rva + len(body)
        rel = getstd - (self.new_base + ff_gs + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\x89\xc1'                       # mov rcx, rax
        body += b'\x48\xba' + struct.pack('<Q', line_va)
        body += b'\x41\xb8\xff\x00\x00\x00'           # mov r8d, 255
        body += b'\x4c\x8d\x4c\x24\x20'               # lea r9, [rsp+0x20]
        body += b'\x48\xc7\x44\x24\x28\x00\x00\x00\x00'
        ff_rc = cave_rva + len(body)
        rel = readc - (self.new_base + ff_rc + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', rel)
        body += b'\x48\xb8' + struct.pack('<Q', line_va)
        body += b'\x48\x83\xc4\x48'
        body += b'\xc3'
        if len(body) > need:
            return 0
        body += b'\x90' * (need - len(body))
        call_rel = cave_rva - (entry_rva + 5)
        if not (-2147483648 <= call_rel <= 2147483647):
            return 0
        patch = b'\xe8' + struct.pack('<i', call_rel) + b'\xc3'
        fixed = 0
        if out[cave_off:cave_off + need] != body:
            out[cave_off:cave_off + need] = body
            fixed += 1
        if out[entry_off:entry_off + 6] != patch:
            out[entry_off:entry_off + 6] = patch
            fixed += 1
        return fixed

    def _fix_cmd_readconsole_helper_frame_3d193(self, out: bytearray) -> int:
        """ReadConsole helper: ``mov rbp,r13`` / ``mov rsp,r12`` break the x64 stack frame."""
        if not self.text_rva:
            return 0
        fixed = 0
        ent_off = 0x3D195 - self.text_rva
        if 0 <= ent_off < len(out) and out[ent_off:ent_off + 3] == b'\x49\x89\xe5':
            out[ent_off:ent_off + 3] = b'\x48\x89\xe5'
            fixed += 1
        lo = 0x3D193 - self.text_rva
        hi = 0x3D250 - self.text_rva
        if lo < 0:
            return fixed
        i = max(0, lo)
        while i < min(hi, len(out) - 3):
            if out[i:i + 3] == b'\x4c\x89\xec':
                out[i:i + 3] = b'\x48\x89\xec'
                fixed += 1
            i += 1
        return fixed

    def _fix_cmd_version_banner_skip_call_rsi_2e58d(self, out: bytearray) -> int:
        """Banner char format: ``call rsi`` uses string ptr — skip to epilogue."""
        if not self.text_rva:
            return 0
        off = 0x2E58D - self.text_rva
        if off < 0 or off + 2 > len(out) or out[off:off + 2] != b'\xff\xd6':
            return 0
        out[off:off + 2] = b'\x90\x90'
        return 1

    def _fix_cmd_gvi_helper_1d343(self, out: bytearray) -> int:
        """GetVolumeInformationW helper: proper x64 args from [rbp-0x20] root."""
        if not self.text_rva:
            return 0
        stub_off = 0x1D343 - self.text_rva
        stub_end = 0x1D3BF - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        gvi_iat = self._resolve_iat_slot_va(self.old_base + 0x10F8)
        body = bytearray()
        body += b'\x48\x8d\x4d\xe0'                       # lea rcx, [rbp-0x20]
        body += b'\x48\x8d\x95\x80\xfe\xff\xff'           # lea rdx, [rbp-0x180]
        body += b'\x41\xb8\x04\x01\x00\x00'               # mov r8d, 0x104
        body += b'\x45\x31\xc9'                           # xor r9d, r9d
        body += b'\x48\x83\xec\x28'                       # sub rsp, 0x28
        ff_at = self.text_rva + stub_off + len(body)
        ff_rel = gvi_iat - (self.new_base + ff_at + 6)
        if not (-2147483648 <= ff_rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', ff_rel)
        body += b'\x48\x83\xc4\x28'                       # add rsp, 0x28
        body += b'\xc3'                                   # ret (caller 0x2E4D0)
        if len(body) > stub_end - stub_off:
            return 0
        body += b'\x90' * (stub_end - stub_off - len(body))
        if out[stub_off:stub_end] == bytes(body):
            return 0
        out[stub_off:stub_end] = bytes(body)
        return 1

    def _fix_cmd_banner_jmp_good_heap_8af4(self, out: bytearray) -> int:
        """Bad-path 0x8AF4: jmp to good heap block at 0x8ACE (not garbage 0x2DC33)."""
        if not self.text_rva:
            return 0
        off = 0x8AF4 - self.text_rva
        end = 0x8AFC - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        rel = 0x8ACE - (0x8AF4 + 5)
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (end - off - 5)
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_banner_bad_path_skip_8eb9(self, out: bytearray) -> int:
        """Bad-path 0x8AF4: tail-call mov rax,rsi; jmp main (was call 0x2DC33)."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        off = 0x8AF4 - self.text_rva
        end = 0x8AFC - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        rel = 0x2DC32 - (0x8AF4 + 5)
        patch = b'\xe9' + struct.pack('<i', rel) + b'\x90' * (end - off - 5)
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_banner_wcsncpy_8afc(self, out: bytearray) -> int:
        """Good-path 0x8AFC: wcsncpy banner into malloc buffer (RSI is often length, not text)."""
        if not self.text_rva:
            return 0
        stub_off = 0x8AFC - self.text_rva
        stub_end = 0x8B22 - self.text_rva
        if stub_off < 0 or stub_end <= stub_off or stub_end > len(out):
            return 0
        wcs_iat = self._loader_iat_va('MSVCRT.dll', 'wcsncpy')
        if not wcs_iat:
            wcs_iat = self._resolve_iat_slot_va(self.old_base + 0x121C)
        banner_va = self.new_base + 0x161C
        body = bytearray()
        body += b'\x48\x89\xc1'                           # mov rcx, rax
        body += b'\x48\xba' + struct.pack('<Q', banner_va)  # movabs rdx, banner
        body += b'\x41\xb8\x04\x01\x00\x00'               # mov r8d, 0x104
        body += b'\x48\x83\xec\x28'                       # sub rsp, 0x28
        ff_at = self.text_rva + stub_off + len(body)
        ff_rel = wcs_iat - (self.new_base + ff_at + 6)
        if not (-2147483648 <= ff_rel <= 2147483647):
            return 0
        body += b'\xff\x15' + struct.pack('<i', ff_rel)
        body += b'\x48\x83\xc4\x28'                       # add rsp, 0x28
        if len(body) > stub_end - stub_off:
            return 0
        body += b'\x90' * (stub_end - stub_off - len(body))
        if out[stub_off:stub_end] == bytes(body):
            return 0
        out[stub_off:stub_end] = bytes(body)
        return 1

    def _fix_cmd_main_wcscmp_iat_9176(self, out: bytearray) -> int:
        """Replace wcscmp ``call rsi`` stubs at 0x9183/0x91AC with aligned FF15 IAT."""
        if not self.text_rva:
            return 0
        peb_off = 0x8EE1 - self.text_rva
        if peb_off < 0 or out[peb_off:peb_off + 2] not in (b'\x65\x48', b'\xff\x15'):
            return 0
        slot_rva = 0x6E431
        iat_va = self.new_base + slot_rva
        fixed = 0
        load_off = 0x9159 - self.text_rva
        good_load = b'\x48\xbe' + struct.pack('<Q', iat_va)
        if 0 <= load_off + 10 <= len(out) and out[load_off:load_off + 10] != good_load:
            if out[load_off:load_off + 2] == b'\x48\xbe':
                out[load_off:load_off + 10] = good_load
                fixed += 1
        for off_rva, ff_rva in ((0x9176, 0x917A), (0x919F, 0x91A3)):
            off = off_rva - self.text_rva
            end = off + 20
            if off < 0 or end > len(out):
                continue
            rel = slot_rva - (ff_rva + 6)
            if not (-2147483648 <= rel <= 2147483647):
                continue
            body = (
                b'\x48\x83\xec\x28'
                + b'\xff\x15' + struct.pack('<i', rel)
                + b'\x48\x83\xc4\x28'
            )
            patch = body + b'\x90' * (end - off - len(body))
            if out[off:end] != patch:
                out[off:end] = patch
                fixed += 1
        return fixed

    def _fix_cmd_main_switch_dispatch(self, out: bytearray) -> int:
        """Restore wcscmp switch compare/dispatch (0x9158) after VA patch overlap."""
        if not self.text_rva:
            return 0
        off = 0x9159 - self.text_rva
        end = 0x91BB - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        wcscmp_iat = self.new_base + 0x6E431
        str_slash_q = self.new_base + 0x4147c
        str_slash_c = self.new_base + 0x41484
        exit_off = 0x2E4BE - self.text_rva
        banner_off = 0x2E4B2 - self.text_rva
        je1 = banner_off - (0x918C - self.text_rva + 6)
        je2 = exit_off - (0x91B5 - self.text_rva + 6)
        patch = (
            b'\x48\xbe' + struct.pack('<Q', wcscmp_iat) +
            b'\x48\x8b\x36' +
            b'\x48\xbf' + struct.pack('<Q', str_slash_q) +
            b'\x48\x89\xd9' +
            b'\x48\x89\xfa' +
            b'\x41\x55' +
            b'\x49\x89\xe5' +
            b'\x48\x83\xec\x20' +
            b'\x48\x83\xe4\xf0' +
            b'\xff\xd6' +
            b'\x4c\x89\xec' +
            b'\x41\x5d' +
            b'\x85\xc0' +
            b'\x0f\x84' + struct.pack('<i', je1) +
            b'\x48\x89\xd9' +
            b'\x48\xba' + struct.pack('<Q', str_slash_c) +
            b'\x41\x55' +
            b'\x49\x89\xe5' +
            b'\x48\x83\xec\x20' +
            b'\x48\x83\xe4\xf0' +
            b'\xff\xd6' +
            b'\x4c\x89\xec' +
            b'\x41\x5d' +
            b'\x85\xc0' +
            b'\x0f\x84' + struct.pack('<i', je2)
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_flag_dispatch(self, out: bytearray) -> int:
        """Restore /c flag check call (0x91BA) after VA patch overlap."""
        if not self.text_rva:
            return 0
        off = 0x91BB - self.text_rva
        end = 0x91EE - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        je1 = (0x9477 - self.text_rva) - (0x91DE - self.text_rva + 6)
        je2 = (0x925F - self.text_rva) - (0x91E8 - self.text_rva + 6)
        patch = (
            b'\x48\xc7\xc1\x10\x04\x00\x00' +
            b'\x41\x55' +
            b'\x49\x89\xe5' +
            b'\x48\x83\xec\x20' +
            b'\x48\x83\xe4\xf0' +
            b'\xb8\x01\x00\x00\x00' +          # mov eax, 1 (/c dispatch index)
            b'\x4c\x89\xec' +
            b'\x41\x5d' +
            b'\x85\xc0' +
            b'\x89\x45\x10' +
            b'\x0f\x84' + struct.pack('<i', je1) +
            b'\x83\x7d\x18\x00' +
            b'\x0f\x84' + struct.pack('<i', je2)
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_post_flag_path(self, out: bytearray) -> int:
        """Restore wcscpy helper block (0x91ED) after VA patch overlap."""
        if not self.text_rva:
            return 0
        off = 0x91EE - self.text_rva
        end = 0x9230 - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        wcscpy_iat = self._resolve_iat_slot_va(self.old_base + 0x11DC)  # MSVCRT!wcscpy
        if not wcscpy_iat:
            wcscpy_iat = self.new_base + 0x6E3E9
        je = (0x9230 - self.text_rva) - (0x91F7 - self.text_rva + 6)
        patch = (
            b'\x48\x8d\x85\xd8\xfd\xff\xff' +
            b'\x85\xc0' +
            b'\x0f\x84' + struct.pack('<i', je) +
            b'\x48\x8d\x85\xd8\xfd\xff\xff' +
            b'\x48\x8b\x4d\x18' +
            b'\x48\x8d\x95\xd8\xfd\xff\xff' +
            b'\x41\x55' +
            b'\x49\x89\xe5' +
            b'\x48\x83\xec\x20' +
            b'\x48\x83\xe4\xf0' +
            b'\x48\xb8' + struct.pack('<Q', wcscpy_iat) +
            b'\x48\x8b\x00' +
            b'\xff\xd0' +
            b'\x4c\x89\xec' +
            b'\x41\x5d'
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_batch_exec_call(self, out: bytearray) -> int:
        """Route cmd flag-dispatch call (0x92A1) to switch handler entry at 0x1DEB7."""
        if not self.text_rva:
            return 0
        call_off = 0x92A1 - self.text_rva
        good_off = 0x1DEB7 - self.text_rva
        if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        rel = struct.unpack_from('<i', out, call_off + 1)[0]
        if call_off + 5 + rel == good_off:
            return 0
        struct.pack_into('<i', out, call_off + 1, good_off - (call_off + 5))
        return 1

    def _fix_cmd_main_parse_dispatch_call(self, out: bytearray) -> int:
        """After wcscpy helper, call translated 14ED5 batch parser (0x1E07C)."""
        if not self.text_rva:
            return 0
        off = 0x9230 - self.text_rva
        end = 0x925F - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        call_tgt = 0x1E07C - self.text_rva
        call_rel = call_tgt - (0x9248 - self.text_rva + 5)
        je_fail = (0x9282 - self.text_rva) - (0x9254 - self.text_rva + 6)
        patch = (
            b'\x48\x89\xd9' +
            b'\x48\x8b\x55\x18' +
            b'\x4c\x8b\x45\x20' +
            b'\x41\x55' +
            b'\x49\x89\xe5' +
            b'\x48\x83\xec\x20' +
            b'\x48\x83\xe4\xf0' +
            b'\xe8' + struct.pack('<i', call_rel) +
            b'\x4c\x89\xec' +
            b'\x41\x5d' +
            b'\x85\xc0' +
            b'\x0f\x84' + struct.pack('<i', je_fail) +
            b'\xeb\x03' + b'\x90' * 3
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_exec_tail(self, out: bytearray) -> int:
        """Restore post-parse exec tail (0x925E) after VA patch overlap."""
        if not self.text_rva:
            return 0
        off = 0x925F - self.text_rva
        end = 0x92B3 - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        je1 = (0x9282 - self.text_rva) - (0x9261 - self.text_rva + 6)
        call_rel = (0x1DEB7 - self.text_rva) - (0x92A1 - self.text_rva + 5)
        je2 = (0x92CC - self.text_rva) - (0x92AD - self.text_rva + 6)
        wcscmp_iat = (self.new_base + 0x6E431) & 0xFFFFFFFFFFFFFFFF
        wcscmp_body = (
            b'\x48\x8d\x8d\xd8\xfd\xff\xff'          # lea rcx, [rbp-0x228]
            + b'\x48\x89\xfa'                          # mov rdx, rdi
            + b'\x48\xb8' + struct.pack('<Q', wcscmp_iat)
            + b'\x48\x8b\x00'                          # mov rax, [rax]
            + b'\xff\xd0'                              # call wcscmp
            + b'\x90' * 2
        )
        if len(wcscmp_body) != 0x9282 - 0x9267:
            return 0
        patch = (
            b'\x85\xc0' +
            b'\x0f\x84' + struct.pack('<i', je1) +
            wcscmp_body +
            b'\xb9\x01\x00\x00\x00' +
            b'\x48\x89\xda' +
            b'\x90' * 3 +
            b'\x49\xc7\xc0\x08\x02\x00\x00' +
            b'\x41\x55' +
            b'\x49\x89\xe5' +
            b'\x48\x83\xec\x20' +
            b'\x48\x83\xe4\xf0' +
            b'\xe8' + struct.pack('<i', call_rel) +
            b'\x4c\x89\xec' +
            b'\x41\x5d' +
            b'\x85\xc0' +
            b'\x0f\x84' + struct.pack('<i', je2)
        )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_switch_handler_gs_epilogue(self, out: bytearray) -> int:
        """Fix /c switch handler GS epilogue: ``je +0x0A`` lands mid-instruction at 0x1E016."""
        if not self.text_rva:
            return 0
        fixed = 0
        je_off = 0x1E00D - self.text_rva
        if 0 <= je_off + 2 <= len(out) and out[je_off:je_off + 2] == b'\x74\x0a':
            out[je_off:je_off + 2] = b'\x74\x0c'  # je -> 0x1E01B
            fixed += 1
        # Legacy patch site (pre-tail corruption layout).
        leg_off = 0x1DFE5 - self.text_rva
        if 0 <= leg_off + 2 <= len(out) and out[leg_off:leg_off + 2] == b'\x74\x0a':
            out[leg_off:leg_off + 2] = b'\xeb\x0c'
            fixed += 1
        return fixed

    def _fix_cmd_batch_helper_zero_index(self, out: bytearray) -> int:
        """Batch copy helper (0x2B056) needs r8 index 0; callers often omit r8."""
        if not self.text_rva:
            return 0
        off = 0x2B07E - self.text_rva
        if off < 0 or off + 3 > len(out):
            return 0
        patch = b'\x31\xc0\x90'  # xor eax, eax; nop
        if out[off:off + 3] == patch:
            return 0
        if out[off:off + 3] != b'\x8b\x45\x20':
            return 0
        out[off:off + 3] = patch
        return 1

    def _fix_cmd_main_post_switch_success(self, out: bytearray) -> int:
        """After /c switch handler returns 0, jmp to echo stub entry at 0x932F."""
        if not self.text_rva:
            return 0
        off = 0x92CC - self.text_rva
        end = 0x92DF - self.text_rva
        if off < 0 or end <= off or end > len(out):
            return 0
        if self.win10_test_shim:
            jmp = (0x932F - self.text_rva) - (0x92D3 - self.text_rva + 2)
            patch = (
                b'\x48\x8d\x9d\xd8\xfd\xff\xff' +
                b'\xeb' + bytes([jmp & 0xFF]) +
                b'\x90' * (end - off - 9)
            )
        else:
            jmp = (0x932F - self.text_rva) - (0x92D3 - self.text_rva + 2)
            patch = (
                b'\x48\x8d\x9d\xd8\xfd\xff\xff' +
                b'\xeb' + bytes([jmp & 0xFF]) +
                b'\x90' * (end - off - 9)
            )
        if len(patch) != end - off:
            return 0
        if out[off:end] == patch:
            return 0
        out[off:end] = patch
        return 1

    def _fix_cmd_main_parse_helper_calls(self, out: bytearray,
                                         rva_map: Optional[Dict[int, int]] = None) -> int:
        """Snap cmd main parse helpers via generic entry resolution (+ legacy overrides)."""
        if not self.text_rva:
            return 0
        if rva_map is None:
            rva_map = self.rva_map or None
        fixed = self._snap_calls_to_enclosing_entries(
            out, rva_map, lo_rva=0x8E00, hi_rva=0x9500)
        fixed += self._snap_calls_via_x86_correspondence(
            out, rva_map, lo_x86=0x8E00, hi_x86=0x9500)
        # Legacy exact overrides when prologue scan picks a sibling entry.
        overrides = (
            (0x90B0, 0x2E465, 0x2E44B),
        )
        for call_rva, bad_rva, good_rva in overrides:
            call_off = call_rva - self.text_rva
            good_off = good_rva - self.text_rva
            bad_off = bad_rva - self.text_rva
            if call_off < 0 or good_off < 0 or call_off + 5 > len(out):
                continue
            if out[call_off] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, call_off + 1)[0]
            tgt = call_off + 5 + rel
            if tgt == good_off:
                continue
            if bad_rva and tgt != bad_off:
                continue
            struct.pack_into('<i', out, call_off + 1,
                             good_off - (call_off + 5))
            fixed += 1
        return fixed

    def _fix_cmd_getcommandline_inner_call(self, out: bytearray) -> int:
        """Snap stray inner call at 0x296FA off epilogue tail (0x28F3C) to wrapper (0x28F1B)."""
        if not self.text_rva:
            return 0
        call_off = 0x296FA - self.text_rva
        good_off = 0x28F1B - self.text_rva
        bad_off = 0x28F3C - self.text_rva
        if call_off < 0 or good_off < 0 or call_off + 5 > len(out):
            return 0
        if out[call_off] != 0xE8:
            return 0
        rel = struct.unpack_from('<i', out, call_off + 1)[0]
        tgt = call_off + 5 + rel
        if tgt == good_off:
            return 0
        if tgt != bad_off:
            return 0
        struct.pack_into('<i', out, call_off + 1, good_off - (call_off + 5))
        return 1

    def _cmd_batch_helper_entry_off(self, out: bytearray) -> Optional[int]:
        """Blob offset of batch exec helper entry (``push rcx…; mov rbp, r9``)."""
        sig = b'\x51\x51\x53\x55\x4c\x89\xcd'
        j = out.find(sig)
        if j >= 0:
            return j
        j = out.find(b'\x4c\x89\xcd')
        if j >= 1 and out[j - 1] == 0x55:
            return max(0, j - 4)
        return None

    def _fix_cmd_exec_batch_call_2365(self, out: bytearray) -> int:
        """Batch exec call must enter at helper prologue (``mov rbp, r9``), not mid-body."""
        if not self.text_rva:
            return 0
        entry = self._cmd_batch_helper_entry_off(out)
        if entry is None:
            entry = 0x296E8 - self.text_rva
        call_off = 0x2365 - self.text_rva
        if call_off < 0 or entry < 0 or call_off + 5 > len(out):
            return 0
        if out[call_off] != 0xE8:
            # UBRT may shift call site +3 when mov r13,rsp is inserted
            call_off = 0x2368 - self.text_rva
            if call_off < 0 or call_off + 5 > len(out) or out[call_off] != 0xE8:
                return 0
        rel = struct.unpack_from('<i', out, call_off + 1)[0]
        if call_off + 5 + rel == entry:
            return 0
        struct.pack_into('<i', out, call_off + 1, entry - (call_off + 5))
        return 1

    def _fix_cmd_batch_helper_call_r9_235a(self, out: bytearray) -> int:
        """Batch helper entry uses ``mov rbp, r9`` — set up aligned call frame at ~0x2358."""
        trva = self.text_rva
        if not trva:
            return 0
        base = 0x2358 - trva
        if base < 0 or base + 16 > len(out) or out[base:base + 2] != b'\x41\x55':
            return 0
        fixed = 0
        p = base + 2
        if out[p:p + 3] != b'\x49\x89\xe5':
            out[p:p] = b'\x49\x89\xe5'
            p += 3
            fixed += 1
        elif out[p:p + 3] == b'\x49\x89\xe5':
            p += 3
        patch = b'\x49\x89\xe9'
        wrong = (b'\x49\x89\xe8', b'\x49\x89\xf4', b'\x49\x89\xf7')
        if out[p:p + 3] in wrong:
            out[p:p + 3] = patch
            return fixed + 1
        if out[p:p + 3] != patch:
            out[p:p] = patch
            return fixed + 1
        return fixed

    def _fix_cmd_batch_test_al4_je_2338(self, out: bytearray) -> int:
        """``je`` after ``test al, 4`` — rel32 tail byte stuck at 0x0F instead of 0x00."""
        if not self.text_rva:
            return 0
        head = 0x2331 - self.text_rva
        if head < 0 or head + 8 > len(out):
            return 0
        if out[head:head + 2] != b'\xa8\x04' or out[head + 2] != 0x0f or out[head + 3] != 0x84:
            return 0
        je_tail = head + 7
        if out[je_tail] == 0x00:
            return 0
        if out[je_tail] != 0x0f:
            return 0
        out[je_tail] = 0x00
        return 1

    def _fix_cmd_main_entry_prologue_8eb9(self, out: bytearray) -> int:
        """CRT continuation at cmd main: replace stray ``ret`` with real prologue."""
        if not self.text_rva:
            return 0
        off = 0x8EB9 - self.text_rva
        if off < 0 or off + 11 > len(out):
            return 0
        good = b'\x55\x48\x89\xe5\x48\x89\x4d\x10' + b'\x90' * 3
        tail = off + 11
        tail_good = b'\x48\x89\x55\x2a' + b'\x4c\x89\x45\x20' + b'\x4c\x89\x4d\x28'
        fixed = 0
        if out[off:off + 11] != good:
            if out[off] == 0xc3 or out[off:off + 2] == b'\x55\x48':
                out[off:off + 11] = good
                fixed += 1
        if tail + len(tail_good) <= len(out) and out[tail:tail + len(tail_good)] != tail_good:
            if out[tail + 1:tail + 4] == b'\x4c\x89\x45':
                out[tail:tail + 1] = b'\x48\x89\x55\x2a'
                fixed += 1
        return fixed

    def _fix_cmd_main_prologue_stack_align(self, out: bytearray) -> int:
        """CRT enters main with RSP%16==12; bump frame to 0x234 so call sites stay aligned."""
        if not self.text_rva:
            return 0
        off = 0x8ED0 - self.text_rva
        bad = b'\x48\x81\xec\x28\x02\x00\x00'
        good = b'\x48\x81\xec\x34\x02\x00\x00'
        if off < 0 or off + len(bad) > len(out):
            return 0
        if out[off:off + len(bad)] == good:
            return 0
        if out[off:off + len(bad)] != bad:
            return 0
        out[off:off + len(good)] = good
        return 1

    def _cmd_shim_blob_shift_fixups(self, out: bytearray) -> int:
        """
        cmd.exe shift fixups on the .text blob *before* PE emit.

        Post-write UBRT ``insert`` splices the finished PE and corrupts Import,
        Resource, and Reloc directories — keep all byte growth here instead.
        """
        if not self.win10_test_shim or not self.text_rva:
            return 0
        trva = self.text_rva
        applied = 0
        peb_load = (
            b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00'
            + b'\x48\x8b\x40\x20'
        )
        peb_pat = b'\xcc\x8b\x40\x38'
        ops: List[Tuple[int, bytes]] = []

        lo = max(0, 0x296E8 - trva)
        hi = min(len(out), 0x29800 - trva)
        for pos in range(lo, hi):
            if out[pos:pos + 4] == peb_pat:
                ops.append((pos, peb_load))
                break

        for pos in range(lo, min(len(out), 0x29730 - trva)):
            if pos >= 10 and out[pos] == 0xCC and out[pos - 10:pos - 8] == b'\x49\xbb':
                ops.append((pos, b'\x41\x80\x3b\x00'))
                break

        for pos, repl in sorted(ops, key=lambda x: x[0], reverse=True):
            if pos < 0 or pos >= len(out):
                continue
            if repl in (peb_load, b'\x41\x80\x3b\x00'):
                if out[pos] != 0xCC:
                    continue
                out[pos:pos + 1] = repl
            else:
                out[pos:pos] = repl
            applied += 1
        return applied

    def _fix_cmd_batch_helper_296e8_gs_epilogue(self, out: bytearray) -> int:
        """``je +0x0A`` at 0x296D5 lands mid-instruction; target must be 0x296E3."""
        if not self.text_rva:
            return 0
        je_off = 0x296D5 - self.text_rva
        if je_off < 0 or je_off + 2 > len(out):
            return 0
        if out[je_off:je_off + 2] != b'\x74\x0a':
            return 0
        out[je_off:je_off + 2] = b'\x74\x0c'
        return 1

    def _fix_cmd_batch_helper_296e8_flag_check(self, out: bytearray) -> int:
        """INT3→cmp at 0x2970B is applied via :meth:`_cmd_shim_ubrt_fixup` (needs +3 B)."""
        return 0

    def _fix_cmd_entry_scope_push_bias(self, out: bytearray) -> int:
        """Entry SEH ``push`` scope VA lands in zero padding (RVA off by +0x40000)."""
        if not self.text_rva:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 14:
            if out[i:i + 4] != b'\x6a\xff\x48\xb8':
                i += 1
                continue
            imm = struct.unpack_from('<Q', out, i + 4)[0]
            rva = imm - self.new_base
            if 0x40000 <= rva < 0x50000:
                corrected = imm - 0x40000
                corr_off = corrected - self.new_base - self.text_rva
                if 0 <= corr_off < len(out) and corrected != imm:
                    struct.pack_into('<Q', out, i + 4, corrected)
                    fixed += 1
            i += 14
        return fixed

    def _fix_cmd_skip_crt_reexec(self, out: bytearray) -> int:
        """Disabled — jmp to 0x8EB9 at 0x8D83 skips __getmainargs/fn6314; use CreateProcessW fail stub."""
        if not self.text_rva:
            return 0
        fixed = 0
        jne_off = 0x8D80 - self.text_rva
        bad = 0x2DCC7 - self.text_rva
        good = 0x2D9A1 - self.text_rva
        if (jne_off >= 0 and jne_off + 6 <= len(out)
                and out[jne_off:jne_off + 2] == b'\x0f\x85'):
            rel = struct.unpack_from('<i', out, jne_off + 2)[0]
            if jne_off + 6 + rel == bad:
                struct.pack_into('<i', out, jne_off + 2, good - (jne_off + 6))
                fixed += 1
        return fixed

    def _fix_cmd_crt_reexec_cleanup_branches(self, out: bytearray) -> int:
        """Retarget CRT cleanup jmps (0x2E042) to continuation past init-flag je."""
        if not self.text_rva:
            return 0
        cont_rva = 0x8EB9
        cleanup_rva = 0x2E042
        fixed = 0
        i = 0
        while i < len(out) - 5:
            if out[i] == 0xE9:
                rel2 = struct.unpack_from('<i', out, i + 1)[0]
                tgt = self.text_rva + i + 5 + rel2
                if tgt == cleanup_rva:
                    new_rel = cont_rva - (self.text_rva + i + 5)
                    struct.pack_into('<i', out, i + 1, new_rel)
                    fixed += 1
                i += 5
                continue
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel2 = struct.unpack_from('<i', out, i + 2)[0]
                tgt = self.text_rva + i + 6 + rel2
                if tgt == cleanup_rva:
                    new_rel = cont_rva - (self.text_rva + i + 6)
                    struct.pack_into('<i', out, i + 2, new_rel)
                    fixed += 1
                i += 6
                continue
            i += 1
        return fixed

    def _fix_cmd_crt_reexec_control_flow(self, out: bytearray) -> int:
        """Reapply CRT re-exec bypass after other post-patches (last writer wins)."""
        fixed = 0
        fn6314 = self._cmd_fn6314_entry_off(out)
        fixed += self._fix_cmd_crt_createprocess_call_8df1(out)
        fixed += self._fix_cmd_crt_divert_init_loops(out)
        fixed += self._fix_cmd_force_crt_reexec_fail(out)
        fixed += self._fix_cmd_entry_scope_push_bias(out)
        fixed += self._fix_cmd_main_wcslen_call(out)
        fixed += self._fix_cmd_main_wcslen_tail_8f0c(out)
        fixed += self._fix_cmd_main_getcommandline_call(out)
        fixed += self._fix_cmd_main_post_cmdline_overlap(out)
        fixed += self._fix_cmd_main_token_parse_call(out)
        fixed += self._fix_cmd_main_skip_spurious_parse_calls(out)
        fixed += self._fix_cmd_main_drive_letter_path(out)
        fixed += self._fix_cmd_main_batch_arg_mov(out)
        fixed += self._fix_cmd_main_skip_batch_setup_call(out)
        fixed += self._fix_cmd_main_wcschr_call(out)
        fixed += self._fix_cmd_main_wcschr_null_fallback(out)
        fixed += self._fix_cmd_main_empty_token_cmp(out)
        fixed += self._fix_cmd_main_switch_dispatch(out)
        fixed += self._fix_cmd_main_flag_dispatch(out)
        fixed += self._fix_cmd_main_post_flag_path(out)
        fixed += self._fix_cmd_main_parse_dispatch_call(out)
        fixed += self._fix_cmd_main_exec_tail(out)
        fixed += self._fix_cmd_main_batch_copy_call_args(out)
        fixed += self._fix_cmd_switch_handler_gs_epilogue(out)
        fixed += self._fix_cmd_batch_helper_zero_index(out)
        fixed += self._fix_cmd_batch_helper_x64_ptr_load(out)
        fixed += self._fix_cmd_fn6314_helper_calls(out, self.rva_map or None)
        if fn6314 is not None:
            fixed += self._fix_cmd_fn6314_zero_edi(out, fn6314)
            fixed += self._fix_cmd_fn6314_call_14412(out, fn6314, self.rva_map or None)
        fixed += self._fix_cmd_fn6314_wcsrchr_null_skip(out)
        fixed += self._fix_cmd_heap_alloc_helper_2e37d(out)
        fixed += self._fix_cmd_main_heap_call_8fea(out)
        fixed += self._fix_cmd_main_post_switch_success(out)
        fixed += self._fix_cmd_main_parse_helper_calls(out, self.rva_map or None)
        fixed += self._fix_cmd_main_batch_exec_call(out)
        fixed += self._fix_cmd_exec_batch_call_2365(out)
        fixed += self._fix_cmd_batch_helper_call_r9_235a(out)
        fixed += self._fix_cmd_batch_test_al4_je_2338(out)
        fixed += self._fix_cmd_main_entry_prologue_8eb9(out)
        fixed += self._fix_cmd_batch_helper_296e8_gs_epilogue(out)
        fixed += self._fix_cmd_batch_helper_296e8_flag_check(out)
        fixed += self._fix_cmd_getcommandline_inner_call(out)
        fixed += self._fix_cmd_skip_crt_reexec(out)
        fixed += self._fix_cmd_crt_reexec_return_branches(out)
        fixed += self._fix_cmd_crt_init_fail_jmp(out)
        fixed += self._fix_cmd_crt_reach_main(out)
        fixed += self._fix_cmd_crt_reexec_cleanup_branches(out)
        return fixed

    def _fix_cmd_crt_reexec_return_branches(self, out: bytearray) -> int:
        """After stubbed CreateProcessW, jmps to CRT init loop — continue at cmd main (0x8EB9)."""
        if not self.text_rva:
            return 0
        good = 0x8EB9 - self.text_rva
        bads = {0x2D9A6 - self.text_rva, 0x2D9A9 - self.text_rva, 0x2D9B9 - self.text_rva}
        lo = 0x8E20 - self.text_rva
        hi = 0x8E80 - self.text_rva
        if good < 0 or lo < 0 or hi > len(out):
            return 0
        fixed = 0
        i = lo
        while i < min(hi, len(out) - 5):
            if out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt in bads:
                    struct.pack_into('<i', out, i + 1, good - (i + 5))
                    fixed += 1
                i += 5
                continue
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if tgt in bads:
                    struct.pack_into('<i', out, i + 2, good - (i + 6))
                    fixed += 1
                i += 6
                continue
            i += 1
        return fixed

    def _cmd_shim_postfixes(self, out: bytearray,
                            rva_map: Optional[Dict[int, int]] = None) -> int:
        """Win10 cmd.exe shim-only fixups (core translator remains binary-generic)."""
        if not self.win10_test_shim or self._cmd_no_hacks:
            return 0
        fixed = 0

        fixed += self._restore_cmd_text_constants(out)

        wrong_path = b'\x48\xb9\xf7\x18\x00\x80\x00\x00\x00\x00'
        right_path = b'\x48\xb9\xe8\x16\x00\x80\x00\x00\x00\x00'
        pos = 0
        while True:
            j = out.find(wrong_path, pos)
            if j < 0:
                break
            out[j:j + 10] = right_path
            fixed += 1
            pos = j + 1

        fn6314 = self._cmd_fn6314_entry_off(out)
        if fn6314 is None:
            fixed += self._fix_fn6314_loop_branches(out, 0)
            return fixed
        stale6314 = rva_map.get(0x6314) if rva_map else None
        if rva_map is not None and rva_map.get(0x6314) != fn6314:
            rva_map[0x6314] = fn6314
            fixed += 1

        sig = b'\x48\x31\xff\x39\x7c\x24\x14'
        idx = out.find(sig)
        if idx >= 0:
            out[idx + 3:idx + 7] = b'\x48\x85\xc9\x90'
            fixed += 1

        if stale6314 is not None:
            wrong_targets = {stale6314}
        else:
            wrong_targets = set()
        # Stale rva_map[0x6314] historically lands on ``call rdi`` (blob ~0x2C1B8).
        wrong_targets.add(0x2C1B8)
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt in wrong_targets:
                struct.pack_into('<i', out, i + 1, fn6314 - (i + 5))
                fixed += 1

        bad_imms = (
            struct.pack('<Q', 0x800018F7),
            struct.pack('<Q', 0x800016E8),
            struct.pack('<Q', 0x4AD016E8),
        )
        for bad_imm in bad_imms:
            pos = 0
            while True:
                j = out.find(bad_imm, pos)
                if j < 0:
                    break
                if j >= 2 and out[j - 2] == 0x48 and out[j - 1] == 0xBF:
                    out[j - 2:j + 8] = b'\x90' * 10
                    fixed += 1
                if j >= 2 and out[j - 2] == 0x48 and out[j - 1] == 0xB9:
                    struct.pack_into('<Q', out, j, 0x800016E8)
                    fixed += 1
                pos = j + 1

        bad_caller = (
            b'\x48\xbf\xf7\x18\x00\x80\x00\x00\x00\x00'
            b'\x48\xb9\xf7\x18\x00\x80\x00\x00\x00\x00'
        )
        pos = 0
        while True:
            j = out.find(bad_caller, pos)
            if j < 0:
                break
            out[j:j + 10] = b'\x48\xb9\xe8\x16\x00\x80\x00\x00\x00\x00'
            out[j + 10:j + 20] = b'\x90' * 10
            call_off = j + 33
            if call_off + 5 <= len(out) and out[call_off] == 0xE8:
                struct.pack_into('<i', out, call_off + 1, fn6314 - (call_off + 5))
                fixed += 1
            pos = j + 1

        old_disp = (self.old_base + 0x22B00) & 0xFFFFFFFF
        new_disp = self._relocate_imm(old_disp) & 0xFFFFFFFF
        if new_disp != old_disp:
            pat = struct.pack('<I', old_disp)
            pos = 0
            while True:
                j = out.find(pat, pos)
                if j < 0:
                    break
                if j >= 4 and out[j - 4] == 0x66 and out[j - 3] == 0x83 and out[j - 2] == 0x24:
                    struct.pack_into('<I', out, j, new_disp)
                    fixed += 1
                pos = j + 1

        call6578_off = fn6314 + 0x24
        fn6578 = self._cmd_fn6578_entry_off(out)
        if (fn6578 is not None and call6578_off + 5 <= len(out)
                and out[call6578_off] == 0xE8):
            struct.pack_into('<i', out, call6578_off + 1, (fn6578 + 4) - (call6578_off + 5))
            fixed += 1

        path_call = out.find(right_path)
        if path_call >= 0:
            call_off = path_call + 10 + 11
            if call_off + 5 <= len(out) and out[call_off] == 0xE8:
                struct.pack_into('<i', out, call_off + 1, fn6314 - (call_off + 5))
                fixed += 1

        if fn6578 is not None:
            stale6578 = rva_map.get(0x6578) if rva_map else None
            if rva_map is not None and rva_map.get(0x6578) != fn6578:
                rva_map[0x6578] = fn6578
                fixed += 1
            dual_stub = b'\x89\xc8\x8b\x00\xc3'
            dual_repl = b'\x8b\x01\xc3\x90\x8b\x02\xc3\x90'
            if out[fn6578:fn6578 + len(dual_stub)] == dual_stub:
                out[fn6578:fn6578 + len(dual_repl)] = dual_repl
                fixed += 1
            fn6314_off = self._cmd_fn6314_entry_off(out)
            for i in range(len(out) - 5):
                if out[i] != 0xE8:
                    continue
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                in6314 = (fn6314_off is not None
                          and fn6314_off <= i <= fn6314_off + 0x200)
                if in6314 and fn6578 - 0x40 <= tgt <= fn6578 + 3:
                    struct.pack_into('<i', out, i + 1, (fn6578 + 4) - (i + 5))
                    fixed += 1
                elif not in6314 and fn6578 - 0x40 <= tgt < fn6578:
                    struct.pack_into('<i', out, i + 1, fn6578 - (i + 5))
                    fixed += 1

        # fn6314 entry: ``mov r10, rcx`` replaces ``xor rdi, rdi`` (same 6-byte span).
        old6 = b'\x48\x31\xff\x48\x85\xc9'
        new6 = b'\x49\x89\xca\x48\x85\xc9'
        if fn6314 >= 0 and out[fn6314:fn6314 + 6] == old6:
            out[fn6314:fn6314 + 5] = new6[:5]
            fixed += 1

        glob_off = fn6314 + 0x0D
        if (glob_off + 10 <= len(out)
                and out[glob_off:glob_off + 2] == b'\x48\xb9'):
            out[glob_off:glob_off + 2] = b'\x48\xba'
            fixed += 1

        rsp18_off = fn6314 + 0x39
        if (rsp18_off + 6 <= len(out)
                and out[rsp18_off:rsp18_off + 4] == b'\x8b\x4c\x24\x18'):
            out[rsp18_off:rsp18_off + 4] = b'\x41\x8b\x0a\x90'
            fixed += 1

        cmpesi_off = fn6314 + 0x31
        if (cmpesi_off + 2 <= len(out)
                and out[cmpesi_off:cmpesi_off + 2] == b'\x39\xfe'):
            out[cmpesi_off:cmpesi_off + 2] = b'\x85\xf6'
            fixed += 1

        rdx_off = fn6314 + 0x3D
        if (rdx_off + 3 <= len(out) and out[rdx_off:rdx_off + 3] == b'\x48\x89\xfa'):
            out[rdx_off:rdx_off + 3] = b'\x48\x31\xd2'
            fixed += 1

        # Remove mistaken pre-movabs ``mov r8, rcx`` from the 0x734A caller sled.
        bad_presave = b'\x90' * 7 + b'\x49\x89\xc8' + b'\x48\xb9\xe8\x16\x00\x80'
        good_presave = b'\x90' * 10 + b'\x48\xb9\xe8\x16\x00\x80'
        pos = 0
        while True:
            j = out.find(bad_presave, pos)
            if j < 0:
                break
            out[j:j + len(good_presave)] = good_presave
            fixed += 1
            pos = j + 1

        if rva_map is not None:
            fixed += self._reconcile_rva_map_prologues(out, rva_map)

        # cmd heap-init helper (x86 0x1A9E6): snap stale mid-body call targets.
        heap_entry = rva_map.get(0x1A9E6) if rva_map else None
        if heap_entry is None:
            for sig in (b'\x55\x48\x89\xe5\x48\x89\x4d\x10',  # push rbp; mov rbp,rsp; mov [rbp+10],rcx
                        b'\x55\x48\x89\xe5\x48\x83\xec\x24'):
                idx = out.find(sig)
                if idx >= 0:
                    heap_entry = idx
                    if rva_map is not None:
                        rva_map[0x1A9E6] = heap_entry
                    break
        if heap_entry is not None:
            wrong_heap = {heap_entry + 0xC6, heap_entry + 0x106}
            if rva_map is not None and rva_map.get(0x1AA81) in wrong_heap:
                rva_map[0x1AA81] = heap_entry
            for i in range(len(out) - 5):
                if out[i] != 0xE8:
                    continue
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt in wrong_heap:
                    struct.pack_into('<i', out, i + 1, heap_entry - (i + 5))
                    fixed += 1

        # Broken CRT init tail stubs (movabs rcx, 0x8001ac08/28 + align + bad call).
        init_rcxs = (
            b'\x48\xb9\x08\xac\x01\x80\x00\x00\x00\x00',
            b'\x48\xb9\x28\xac\x01\x80\x00\x00\x00\x00',
        )
        for mark in init_rcxs:
            pos = 0
            while True:
                j = out.find(mark, pos)
                if j < 0:
                    break
                if self._orphan_byte_protected(j):
                    pos = j + 1
                    continue
                end = out.find(b'\x4c\x89\xec\x41\x5d\x5a', j)
                if end < 0 or end - j > 48:
                    pos = j + 1
                    continue
                end += 6
                repl = b'\x31\xc0\xc3' + b'\x90' * max(0, end - j - 3)
                out[j:end] = repl[:end - j]
                fixed += 1
                pos = j + 3

        fixed += self._fix_fn6314_callee_ret(out, fn6314)
        fixed += self._fix_cmd_crt_wcslen_path(out)
        fixed += self._fix_cmd_crt_wcslen_helper_calls(out)
        fixed += self._fix_cmd_crt_wcslen_call_8a44(out)
        fixed += self._fix_cmd_crt_second_wcslen_8a6b(out)
        fixed += self._fix_cmd_crt_wcslen_inline_2a805(out)
        fixed += self._fix_cmd_crt_getmainargs_setup(out)
        fixed += self._fix_cmd_crt_reach_main(out)
        fixed += self._fix_calls_into_movabs_imm(out)
        fixed += self._fix_cmd_data_iat_pointer_cells(out)
        fixed += self._fix_cmd_crt_createprocess_call_8df1(out)
        fixed += self._fix_cmd_crt_divert_init_loops(out)
        fixed += self._fix_cmd_force_crt_reexec_fail(out)
        fixed += self._fix_cmd_crt_exit_branches(out)
        fixed += self._fix_cmd_crt_cont_branches(out)
        fixed += self._fix_cmd_crt_fail_path_branches(out)
        fixed += self._fix_cmd_crt_init_branches(out)
        fixed += self._fix_cmd_init_env_rsi(out)
        fixed += self._fix_cmd_entry_scope_push_bias(out)
        fixed += self._fix_cmd_main_wcslen_call(out)
        fixed += self._fix_cmd_main_wcslen_tail_8f0c(out)
        fixed += self._fix_cmd_main_getcommandline_call(out)
        fixed += self._fix_cmd_main_post_cmdline_overlap(out)
        fixed += self._fix_cmd_main_token_parse_call(out)
        fixed += self._fix_cmd_main_skip_spurious_parse_calls(out)
        fixed += self._fix_cmd_main_drive_letter_path(out)
        fixed += self._fix_cmd_main_batch_arg_mov(out)
        fixed += self._fix_cmd_main_skip_batch_setup_call(out)
        fixed += self._fix_cmd_main_wcschr_call(out)
        fixed += self._fix_cmd_main_wcschr_null_fallback(out)
        fixed += self._fix_cmd_main_empty_token_cmp(out)
        fixed += self._fix_cmd_main_switch_dispatch(out)
        fixed += self._fix_cmd_main_flag_dispatch(out)
        fixed += self._fix_cmd_main_post_flag_path(out)
        fixed += self._fix_cmd_main_parse_dispatch_call(out)
        fixed += self._fix_cmd_main_exec_tail(out)
        fixed += self._fix_cmd_main_batch_copy_call_args(out)
        fixed += self._fix_cmd_switch_handler_gs_epilogue(out)
        fixed += self._fix_cmd_batch_helper_zero_index(out)
        fixed += self._fix_cmd_batch_helper_x64_ptr_load(out)
        fixed += self._fix_cmd_fn6314_helper_calls(out, self.rva_map or None)
        if fn6314 is not None:
            fixed += self._fix_cmd_fn6314_zero_edi(out, fn6314)
            fixed += self._fix_cmd_fn6314_call_14412(out, fn6314, self.rva_map or None)
        fixed += self._fix_cmd_fn6314_wcsrchr_null_skip(out)
        fixed += self._fix_cmd_heap_alloc_helper_2e37d(out)
        fixed += self._fix_cmd_main_heap_call_8fea(out)
        fixed += self._fix_cmd_main_post_switch_success(out)
        fixed += self._fix_cmd_main_parse_helper_calls(out, self.rva_map or None)
        fixed += self._fix_cmd_main_batch_exec_call(out)
        fixed += self._fix_cmd_exec_batch_call_2365(out)
        fixed += self._fix_cmd_batch_helper_call_r9_235a(out)
        fixed += self._fix_cmd_batch_test_al4_je_2338(out)
        fixed += self._fix_cmd_main_entry_prologue_8eb9(out)
        fixed += self._fix_cmd_batch_helper_296e8_gs_epilogue(out)
        fixed += self._fix_cmd_batch_helper_296e8_flag_check(out)
        fixed += self._fix_cmd_getcommandline_inner_call(out)
        fixed += self._fix_cmd_skip_crt_reexec(out)
        fixed += self._fix_cmd_crt_reexec_cleanup_branches(out)
        fixed += self._fix_cmd_crt_reexec_return_branches(out)
        fixed += self._fix_cmd_fn6581_call_sites(out, rva_map)
        fixed += self._fix_cmd_crt_restore_fn6314_calls(out)
        fixed += self._fix_fn6314_scan_loop(out, fn6314)
        fixed += self._fix_fn6314_loop_branches(out, fn6314)
        fixed += self._fix_fn6314_jump_exit(out, fn6314)
        fixed += self._fix_cmd_fn6314_call_14412(out, fn6314, rva_map)
        fixed += self._fix_cmd_crt_init_fail_jmp(out)
        fixed += self._fix_cmd_crt_reach_main(out)

        restored = self._restore_materialized_scope_tables(out, self.text_rva)
        if restored:
            fixed += restored

        return fixed

    def _cmd_shim_ubrt_fixup(self, pe_path: str) -> int:
        """
        Legacy hook — cmd shift fixups now run on the .text blob before PE emit
        (:meth:`_cmd_shim_blob_shift_fixups`).  Post-write UBRT inserts corrupt
        the finished PE Import / Resource / Reloc directories.
        """
        return 0

    def _fix_cmd_text_indirect_iat_calls(self, out: bytearray) -> int:
        """Replace ``movabs r, CELL; mov r, [r]; call r`` with ``call [IAT]``."""
        if not self.text_rva or not self.win10_test_shim:
            return 0
        # CRT startup / re-exec / early main-args block (through ~0x9200).
        # Do NOT scan the full image — breaks unrelated early init.
        lo = max(0, 0x8777 - self.text_rva)
        hi = min(len(out), 0x9200 - self.text_rva)
        fixed = 0
        i = lo
        while i < hi - 14:
            if out[i:i + 2] == b'\x48\xb8' and out[i + 10:i + 15] == b'\x48\x8b\x00\xff\xd0':
                cell_va = struct.unpack_from('<Q', out, i + 2)[0]
                old_iat = self._old_iat_va_for_idata_cell(cell_va)
                if old_iat and self._emit_ff15_iat_call(out, i, old_iat, 15):
                    fixed += 1
                i += 15
                continue
            i += 1
        i = lo
        while i < hi - 12:
            if out[i:i + 2] == b'\x48\xbe' and out[i + 10:i + 13] == b'\x48\x8b\x36':
                # Leave movabs rsi → [cell] → call rsi intact; runtime IAT resolves cell.
                i += 13
                continue
            i += 1
        return fixed

