"""Predicates and searches over translated and untranslated code.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403
from ._healing import HealingMixin


class AnalysisMixin:
    """See the module docstring."""

    _CALL_ENTRY_PROLOGUES = (
        b'\x55\x48\x89',       # push rbp; mov rbp, rsp
        b'\x48\x83\xec',       # sub rsp, N
        b'\x53',               # push rbx
        b'\x56',               # push rsi
        b'\x57',               # push rdi
        b'\x41\x56',           # push r14
        b'\x41\x57',           # push r15
        # Frameless function body starts (no prologue):
        b'\x89\xc8',           # mov eax, ecx
        b'\x89\xd0',           # mov eax, edx
        b'\x89\xd1',           # mov ecx, edx
        b'\x48\x89\xc8',       # mov rax, rcx
        b'\x48\x89\xd0',       # mov rax, rdx
    )

    _SYNTHETIC_ENTRY_SIGS = (
        b'\x48\x89\xf1',       # mov rcx, rsi (import wrapper body)
        b'\x49\x89\xca',       # mov r10, rcx (cmd fn6314 patch)
    )


    def _is_alloca_probe_rva(self, rva: int) -> bool:
        """MSVC _alloca_probe / __chkstk — must not get Win64 shadow space."""
        data = self.pe.read_rva(rva, 8)
        if not data or len(data) < 5:
            return False
        if data[:5] == b'\x3d\x00\x10\x00\x00':          # cmp eax, 0x1000
            return True
        if len(data) >= 6 and data[0] == 0x51 and data[1:6] == b'\x3d\x00\x10\x00\x00':
            return True
        return False

    def _find_nop_run(self, out: bytearray, min_len: int,
                      avoid: Optional[List[Tuple[int, int]]] = None) -> Optional[int]:
        """Return blob offset of the first ``min_len``-byte 0x90 run (optional RVA avoid list)."""
        if not self.text_rva:
            return None
        run = 0
        start = 0
        for i, b in enumerate(out):
            rva = self.text_rva + i
            if avoid and any(lo_rva <= rva < hi_rva for lo_rva, hi_rva in avoid):
                run = 0
                continue
            if b in (0x90, 0xCC):
                if run == 0:
                    start = i
                run += 1
                if run >= min_len:
                    return start
            else:
                run = 0
        return None

    def _find_text_nop_cave(self, out: bytearray, need: int,
                            avoid: Optional[List[Tuple[int, int]]] = None
                            ) -> Optional[int]:
        """Blob offset of a ``need``-byte 0x90 run in .text, skipping ``avoid`` RVAs."""
        if need <= 0 or not self.text_rva:
            return None
        if avoid is None:
            avoid = [(0x9200, 0x9400)]
        lo = max(0, 0x2000 - self.text_rva)
        run = 0
        start = 0
        for i in range(lo, len(out)):
            rva = self.text_rva + i
            if any(lo_rva <= rva < hi_rva for lo_rva, hi_rva in avoid):
                run = 0
                continue
            if out[i] in (0x90, 0xCC):
                if run == 0:
                    start = i
                run += 1
                if run >= need:
                    return start
            else:
                run = 0
        return self._find_nop_run(out, need, avoid=avoid)

    def _offset_is_function_entry(self, out: bytearray, pos: int) -> bool:
        if pos < 0 or pos + 3 > len(out):
            return False
        if out[pos:pos + 3] == b'\x55\x48\x89':
            return True
        if pos + 4 <= len(out) and out[pos:pos + 4] == b'\x40\x55\x48\x89':
            return True
        for pro in self._CALL_ENTRY_PROLOGUES[1:]:
            if out[pos:pos + len(pro)] == pro:
                if (pro == b'\x48\x83\xec'
                        and self._outer_entry_before_align(out, pos) is not None):
                    return False
                return True
        return False

    def _offset_is_synthetic_entry(self, out: bytearray, pos: int) -> bool:
        for sig in self._SYNTHETIC_ENTRY_SIGS:
            if out[pos:pos + len(sig)] == sig:
                return True
        return False

    def _offset_is_wrapper_entry(self, out: bytearray, pos: int) -> bool:
        """Small translated cdecl→fastcall thunks that are valid call targets."""
        if pos < 0 or pos >= len(out):
            return False
        if out[pos] == 0xC3:
            return True
        if out[pos] == 0xC2 and pos + 3 <= len(out):
            return True
        if pos + 3 > len(out):
            return False
        # Frameless pointer-deref helpers (x86 fn6578-style: mov eax,[ptr]; ret).
        if out[pos:pos + 3] in (b'\x8b\x01\xc3', b'\x8b\x02\xc3', b'\x8b\x00\xc3'):
            return True
        if pos + 4 <= len(out) and out[pos + 3] == 0xC3:
            if out[pos] in (0x8B,) and out[pos + 1] in (0x01, 0x02, 0x00):
                return True
            if out[pos:pos + 2] == b'\x8b\x41':  # mov eax, [rcx+disp8]; ret
                return True
        if pos + 4 > len(out):
            return False
        if out[pos:pos + 4] == b'\x48\x83\xf9\x00':  # cmp rcx, 0
            return True
        if out[pos:pos + 3] == b'\x48\x85\xc9':       # test rcx, rcx
            return True
        if out[pos:pos + 4] == b'\x48\x83\x7d\x10':  # cmp qword [rbp+10], 0
            return True
        return False

    def _offset_is_mapped_entry(self, out: bytearray, pos: int) -> bool:
        return (self._offset_is_function_entry(out, pos)
                or self._offset_is_wrapper_entry(out, pos))

    def _offset_is_valid_entry(self, out: bytearray, pos: int) -> bool:
        """Mapped entry that passes pure-mode prologue quality when required."""
        if not self._offset_is_mapped_entry(out, pos):
            return False
        if self._cmd_no_hacks:
            return self._x64_entry_prologue_ok(out, pos)
        return True

    def _entry_snapworthy(self, out: bytearray, entry: int,
                          rva_map: Optional[Dict[int, int]] = None) -> bool:
        if entry < 0 or entry >= len(out):
            return False
        if self._cmd_no_hacks:
            return self._x64_entry_prologue_ok(out, entry)
        if rva_map and entry in rva_map.values():
            return True
        if self._offset_is_synthetic_entry(out, entry):
            return False
        return self._offset_is_mapped_entry(out, entry)

    def _find_enclosing_function_entry(self, out: bytearray, tgt_off: int,
                                       rva_map: Optional[Dict[int, int]] = None,
                                       max_back: int = 320,
                                       max_body: int = 0x800) -> Optional[int]:
        """Map a mid-function blob offset to the nearest real entry (prologue scan + rva_map).

        Uses *max_back*=320 to reach function bodies past large shared epilogues
        (``pop rdi; pop rsi; pop rbx; mov rsp,rbp; pop rbp; ret`` can be 15+
        bytes, and the function body may be 180+ bytes before the epilogue).

        When *tgt_off* lands inside a call-align epilogue
        (``call …; mov rsp,r13; pop r13; ret; [nop…]; <body>``), the
        backward scan detects the alignment-wrapper byte pattern, skips
        past the ``ret``, and returns the first real instruction of the
        function body.  This fixes the universal pattern where rva_map
        entries point at stale offsets inside the alignment wrapper
        instead of the actual translated code.
        """
        if tgt_off < 0 or tgt_off >= len(out):
            return None
        outer = self._outer_entry_before_align(out, tgt_off)
        if outer is not None:
            return outer
        if rva_map and self._fn_entry_rvas:
            for old_rva in self._fn_entry_rvas:
                if rva_map.get(old_rva) == tgt_off:
                    if self._offset_is_valid_entry(out, tgt_off):
                        return tgt_off
        if self._offset_is_valid_entry(out, tgt_off):
            # tgt_off itself looks like a function entry, but check whether
            # it is actually the *second* instruction of a frameless function
            # (e.g. ``mov eax,ecx; push rsi``).  Walk backward a few bytes
            # to find the real first instruction.
            for probe in (1, 2, 3):
                candidate = tgt_off - probe
                if candidate >= 0 and self._offset_is_valid_entry(out, candidate):
                    # Don't cross a ret boundary
                    if 0xC3 not in out[candidate:tgt_off] and 0xC2 not in out[candidate:tgt_off]:
                        return candidate
            return tgt_off
        align = self._ALIGN_WRAP
        for back in range(0, max_back):
            pos = tgt_off - back
            if pos < 0:
                break
            # Alignment-wrapper epilogue detection:
            #   E8 xx xx xx xx 4C 89 EC 41 5D C3 [90…] <body>
            #   |--- call ---|  |- mov rsp,r13 -|  |pop|ret|
            # The translator prepends this 11-byte wrapper before
            # many frameless functions.  When we hit the ``ret`` (C3),
            # check whether it is preceded by the full wrapper and, if
            # so, look *past* the ret+nop padding to find the real
            # function body.
            if back > 0 and out[pos] == 0xC3:
                if (pos >= 10
                        and out[pos - 10] == 0xE8
                        and out[pos - 5:pos - 2] == b'\x4c\x89\xec'  # mov rsp,r13
                        and out[pos - 2:pos] == b'\x41\x5d'):       # pop r13
                    # This ret is part of an alignment wrapper epilogue.
                    # Skip past ret + optional nop/int3 padding to
                    # find the function body start.  The body may start
                    # with ANY instruction — frameless functions don't
                    # always begin with a push prologue.
                    body = pos + 1
                    while body < len(out) and out[body] in (0x90, 0xCC):
                        body += 1
                    if body < len(out):
                        # Accept the body start if it's a recognized
                        # entry or if the byte at body is a valid
                        # non-padding instruction byte.
                        if self._offset_is_valid_entry(out, body):
                            return body
                        if rva_map and body in rva_map.values():
                            return body
                        # Frameless function body: accept any non-padding
                        # byte that isn't inside another ret/control insn.
                        if out[body] not in (0xC3, 0xC2, 0xE9, 0xEB, 0xCC, 0x90):
                            return body
                break
            if pos + len(align) <= len(out):
                al_end = pos + len(align)
                if out[pos:pos + len(align)] == align and pos <= tgt_off < al_end:
                    continue
            if self._offset_is_valid_entry(out, pos):
                return pos
        if rva_map and self._fn_entry_rvas:
            best: Optional[int] = None
            for old_rva in self._fn_entry_rvas:
                ent = rva_map.get(old_rva)
                if ent is None or ent > tgt_off or tgt_off - ent >= max_body:
                    continue
                if best is None or ent > best:
                    best = ent
            if best is not None and self._entry_snapworthy(out, best, rva_map):
                return best
        return None

    def _is_wcsrchr_wrapper_entry(self, out: bytearray, pos: int) -> bool:
        if pos < 0 or pos + 40 > len(out):
            return False
        if out[pos:pos + 4] != b'\x48\x83\xf9\x00':
            return False
        return b'\xa1\xf4\x06\x80' in out[pos:pos + 40]

    def _find_shim_call_for_x86_call(self, out: bytearray, x86_call_rva: int,
                                     x86_tgt_rva: int,
                                     rva_map: Dict[int, int]) -> Optional[int]:
        """Locate the shim E8 for an x86 call site (linear map + local signature scan)."""
        off = self._shim_offset_for_x86_rva(x86_call_rva, rva_map)
        if off is not None and 0 <= off < len(out) - 5 and out[off] == 0xE8:
            return off
        fn_entries = self._fn_entry_rvas or set(rva_map.keys())
        candidates = [(rva_map[o], o) for o in fn_entries
                      if o <= x86_call_rva and o in rva_map]
        if not candidates:
            return None
        shim_fn, old_fn = max(candidates, key=lambda x: x[1])
        scan = min(len(out) - 5, shim_fn + 0x400)
        prefixes: Tuple[bytes, ...] = ()
        if x86_tgt_rva == 0x195F0:
            prefixes = (b'\x48\xc7\xc2\x20\x00\x00\x00',)
        for prefix in prefixes:
            pos = shim_fn
            while pos < scan:
                j = out.find(prefix, pos, scan)
                if j < 0:
                    break
                for k in range(j + len(prefix), min(j + len(prefix) + 48, scan)):
                    if out[k] == 0xE8:
                        return k
                pos = j + 1
        return None

    def _x86_push_is_pointer_imm(self, imm: int) -> bool:
        """True when ``push imm32`` pushed a global/data VA (not a small mode flag)."""
        imm &= 0xFFFFFFFF
        return self.old_base <= imm < self.old_base + self.pe.image_size

    def _is_image_pointer(self, imm32: int) -> bool:
        """True if imm32 looks like a VA inside the PE image (needs 64-bit ALU)."""
        imm32 &= 0xFFFFFFFF
        if self.old_base <= imm32 < self.old_base + self.pe.image_size:
            return True
        if self.new_base <= imm32 < self.new_base + self.pe.image_size:
            return True
        return imm32 in self.dyn.pointer_values

    @staticmethod
    def _is_cdecl_scratch_push(insn_idx: int, insns) -> bool:
        """push r; call; pop ecx; push eax; call — MSVC cdecl scratch (time/srand)."""
        if insn_idx + 4 >= len(insns):
            return False
        cur, call1, pop_ecx, push_eax, call2 = insns[insn_idx:insn_idx + 5]
        if cur.mnemonic != 'push' or not cur.operands:
            return False
        if cur.operands[0].type != X86_OP_REG:
            return False
        if call1.mnemonic != 'call' or not call1.operands:
            return False
        if pop_ecx.mnemonic != 'pop' or not pop_ecx.operands:
            return False
        if (pop_ecx.operands[0].type != X86_OP_REG
                or pop_ecx.operands[0].reg != X86_REG_ECX):
            return False
        if push_eax.mnemonic != 'push' or not push_eax.operands:
            return False
        if (push_eax.operands[0].type != X86_OP_REG
                or push_eax.operands[0].reg != X86_REG_EAX):
            return False
        return call2.mnemonic == 'call' and bool(call2.operands)

    def _note_code_span(self, start: int, size: int) -> None:
        """Record a translated code region so INT3/orphan passes cannot clobber it."""
        if size <= 0:
            return
        end = start + size
        self._code_span_ranges.append((start, end))

    @staticmethod
    def _out_tail_pop_reg(out: bytearray) -> Optional[str]:
        """Return the 64-bit register name if ``out`` ends with a POP insn."""
        if not out or not HAS_CAPSTONE:
            return None
        start = max(0, len(out) - 16)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        insns = list(md.disasm(bytes(out[start:]), start, count=8))
        if not insns:
            return None
        last = insns[-1]
        if last.mnemonic == 'pop' and last.operands:
            return last.op_str
        return None

    @staticmethod
    def _opcode_class(head: bytes) -> Optional[str]:
        """Classify the first instruction in *head* by opcode family.

        Returns one of: CALL, JMP, JCC, RET, PUSH, POP, LEA, MOV, TEST,
        CMP, ARITH (add/sub/and/or/xor), or None if unrecognised.
        Used by ``_pure_mapped_entry_sane`` to reject swallowed entries
        where the x86 and x64 first instructions belong to different
        opcode families.
        """
        if not head:
            return None
        b = head[0]
        # REX.W-prefixed forms (movabs, mov r64, xor r64, call rax, …) were
        # previously unclassified (None) and slipped past the CALL/JMP entry
        # rule — a stale ``movabs r11,<VA>`` slot counted as a valid entry
        # for an x86 CALL head (cmd 0x12E14 → 0x35DE1).  Classify by the
        # opcode byte after the REX prefix.
        if b in (0x48, 0x49, 0x4C, 0x4D) and len(head) >= 2:
            sub = AnalysisMixin._opcode_class(head[1:])
            if sub is not None:
                return sub
            if 0xB8 <= head[1] <= 0xBF:
                return 'MOV'
        # ── CALL ──
        if b == 0xE8:                                    # call rel32
            return 'CALL'
        if b == 0xFF and len(head) >= 2:
            if head[1] in (0x10, 0x11, 0x12, 0x13,       # call [mem]
                           0x50, 0x51, 0x52, 0x53,       # call [mem] (64-bit)
                           0x15, 0x1D, 0x25, 0x2D):      # call [rip+disp]
                return 'CALL'
            if head[1] in (0xD0, 0xD1, 0xD2, 0xD3,       # call r/m
                           0xD4, 0xD5, 0xD6, 0xD7):
                return 'CALL'
        # ── JMP ──
        if b in (0xE9, 0xEB):                             # jmp rel32 / jmp rel8
            return 'JMP'
        if b == 0xFF and len(head) >= 2:
            if head[1] in (0x20, 0x21, 0x22, 0x23,       # jmp [mem]
                           0x60, 0x61, 0x62, 0x63,
                           0x25, 0x2D):                  # jmp [rip+disp]
                return 'JMP'
            if head[1] in (0xE0, 0xE1, 0xE2, 0xE3,       # jmp r/m
                           0xE4, 0xE5, 0xE6, 0xE7):
                return 'JMP'
        # ── Jcc (near: 0F 8x, short: 7x, JECXZ: E3) ──
        if b == 0x0F and len(head) >= 2 and 0x80 <= head[1] <= 0x8F:
            return 'JCC'
        if 0x70 <= b <= 0x7F:
            return 'JCC'
        if b == 0xE3:                                     # jecxz / jrcxz
            return 'JCC'
        # ── RET ──
        if b in (0xC3, 0xC2, 0xCA, 0xCB):
            return 'RET'
        # ── PUSH ──
        if 0x50 <= b <= 0x57:                             # push r32/r64
            return 'PUSH'
        if b == 0x68:                                     # push imm32
            return 'PUSH'
        if b == 0x6A:                                     # push imm8
            return 'PUSH'
        if b == 0xFF and len(head) >= 2 and head[1] in (0x30, 0x31, 0x32,
                                                          0x33, 0x34, 0x35,
                                                          0x36, 0x37,
                                                          0x70, 0x71, 0x72,
                                                          0x73, 0x74, 0x75,
                                                          0x76, 0x77):
            return 'PUSH'                                  # push [mem] / push r/m
        # ── POP ──
        if 0x58 <= b <= 0x5F:
            return 'POP'
        # ── LEA ──
        if b == 0x8D:
            return 'LEA'
        # ── MOV ──
        if b in (0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8E):
            return 'MOV'
        if 0xB8 <= b <= 0xBF:                             # mov r, imm
            return 'MOV'
        if b in (0xA0, 0xA1, 0xA2, 0xA3):                # mov [abs], al/eax
            return 'MOV'
        if b in (0xC6, 0xC7):                             # mov [mem], imm
            return 'MOV'
        # ── TEST ──
        if b == 0x85:
            return 'TEST'
        if b == 0xF6 and len(head) >= 2 and (head[1] & 0x38) == 0:
            return 'TEST'
        if b == 0xF7 and len(head) >= 2 and (head[1] & 0x38) == 0:
            return 'TEST'
        # ── CMP ──
        if b in (0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D):
            return 'CMP'
        if b == 0x80 and len(head) >= 2 and (head[1] & 0x38) == 0x38:
            return 'CMP'
        if b == 0x83 and len(head) >= 2 and (head[1] & 0x38) == 0x38:
            return 'CMP'
        # ── ARITH (add/sub/and/or/xor with imm8/imm32) ──
        if b in (0x04, 0x05, 0x0C, 0x0D, 0x24, 0x25, 0x2C, 0x2D,
                 0x34, 0x35, 0x3C, 0x3D):
            return 'ARITH'
        if b in (0x80, 0x81, 0x83):
            return 'ARITH'
        if b in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
                 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
                 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
                 0x30, 0x31, 0x32, 0x33):
            return 'ARITH'
        # ── ENTER ──
        if b == 0xC8:
            return 'ENTER'
        # ── Unrecognised ──
        return None

    @staticmethod
    def _x64_entry_prologue_ok(blob: bytes, off: int) -> bool:
        """True when *off* looks like a real translated function entry."""
        if off < 0 or off + 1 > len(blob):
            return False
        if blob[off] == 0xC3:
            return True
        if blob[off] == 0xC2 and off + 3 <= len(blob):
            return True
        if off + 8 > len(blob):
            return False
        # Translated __chkstk / _alloca_probe — ``cmp eax,0x1000`` (optionally
        # after ``push rcx``).  Must count as a real entry so near-prologue
        # snap does not walk back onto a preceding ``ff 25`` IAT thunk.
        if blob[off:off + 5] == b'\x3d\x00\x10\x00\x00':
            return True
        if blob[off:off + 6] == b'\x51\x3d\x00\x10\x00\x00':
            return True
        if blob[off:off + 3] == b'\x55\x48\x89' and blob[off + 3] == 0xE5:
            tail = blob[off + 4:off + 8]
            if tail[:4] == b'\xff\xff\xff\xff':
                return False
            if tail[0] in (0x00, 0xCC) and tail[1] in (0x00, 0xCC):
                return False
        elif off + 3 <= len(blob) and blob[off:off + 2] in (b'\x49\xbb', b'\x48\xb8'):
            # movabs r11/rax — real frameless global helpers sit after a
            # previous function's ``ret`` / NOP·INT3.  Mid-function movabs
            # (CRT ``movabs rax,&CS; movabs r11,&slot``) must NOT count as an
            # entry: near-prologue / VA fingerprint otherwise retargets
            # ``call EnterCriticalSection`` onto the caller's own movabs
            # (cmd ``/c`` null CS AV).  Never treat 0x00 as a boundary —
            # movabs immediates end in zero high bytes.
            # Also reject movabs immediately after frameless shadow homes —
            # the homes are the real call entry (cmd setenv ``0x6581``).
            if off == 0:
                return True
            prev = blob[off - 1]
            if prev in (0xC3, 0x90, 0xCC):
                return True
            if off >= 3 and blob[off - 3] == 0xC2:
                return True
            return False
        elif (off + len(_FRAMELESS_SHADOW_HOMES) <= len(blob)
              and blob[off:off + len(_FRAMELESS_SHADOW_HOMES)]
              == _FRAMELESS_SHADOW_HOMES):
            # Frameless Win64 shadow-arg homes at true entry.
            return True
        elif off + 4 <= len(blob) and blob[off:off + 3] == b'\x48\x83\xec':
            pass
        elif (off + 4 <= len(blob) and blob[off] == 0x48 and blob[off + 1] == 0x83
              and 0xF8 <= blob[off + 2] <= 0xFF):
            # cmp r64, imm8 — frameless ``cmp [esp+4], imm`` → ``cmp rcx, imm``
            return True
        elif (off + 3 <= len(blob) and blob[off] == 0x83
              and 0xF8 <= blob[off + 1] <= 0xFF):
            # cmp r32, imm8 — but NOT the tail of ``48 83 F9 ib``
            if off > 0 and blob[off - 1] == 0x48:
                return False
            return True
        elif (off + 3 <= len(blob) and blob[off:off + 2] == b'\x48\x85'
              and 0xC0 <= blob[off + 2] <= 0xFF):
            # test r64, r64 — frameless null checks (``test rcx, rcx``)
            return True
        elif blob[off:off + 2] == b'\xff\x25':
            return True
        elif off + 2 <= len(blob) and blob[off:off + 2] == b'\x41\x5d':
            return False  # pop r13 — epilogue tail, never a function entry
        elif off + 3 <= len(blob) and blob[off:off + 3] == b'\x4c\x89\xec':
            return False  # mov rsp, r13 — epilogue / align tail
        elif blob[off] in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
            # push rax..rdi — includes dual ``push rcx; push rcx; and [rsp],0``
            # local frames (cmd ``fbe4`` / pe64 ``1df1c``).
            return True
        elif (blob[off] == 0x40 and off + 2 <= len(blob)
              and 0x50 <= blob[off + 1] <= 0x57):
            # REX-prefixed push rax..rdi.  A bare 0x40 (REX lead of some other
            # instruction, or a mid-imm byte) must NOT count as an entry —
            # stale slots inside movabs immediates used to pass this gate
            # (cmd 0x12E14 → mid-``movabs`` imm 0x40.. → callers executed it).
            return True
        elif blob[off] in (0x68, 0x6A):
            return True  # push imm32 / push imm8 — tiny CRT helpers
        elif blob[off] == 0x89 and off + 1 < len(blob):
            # mov r32, r32 — frameless fastcall entries that forward arg regs
            # Only accept specific patterns: mov eax, ecx (0xC8), mov eax, edx (0xD0),
            # mov ecx, edx (0xD1), mov ecx, eax (0xC1), mov edx, eax (0xC2),
            # mov eax, ebx (0xD8).  Broad mod=3 matches too many interior moves.
            if blob[off + 1] in (0xC8, 0xD0, 0xD1, 0xC1, 0xC2, 0xD8):
                # Reject ``mov eax, e*; pop*; [leave]; ret`` — previous
                # function's epilogue that rva_map collapses onto (cmd
                # ``fbe4`` mapped to ``mov eax,ebx; pop rsi; pop rbx; leave; ret``).
                j = off + 2
                pops = 0
                while (j < len(blob) and j < off + 10
                       and blob[j] in (0x58, 0x59, 0x5A, 0x5B,
                                      0x5C, 0x5D, 0x5E, 0x5F)):
                    pops += 1
                    j += 1
                if pops:
                    if j < len(blob) and blob[j] == 0xC9:  # leave
                        j += 1
                    if j < len(blob) and blob[j] in (0xC3, 0xC2):
                        return False
                return True
            return False
        elif blob[off] == 0x41:
            if off + 1 < len(blob) and blob[off + 1] in (
                    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):
                return True  # push r8–r15
            return False
        elif off + 2 <= len(blob) and blob[off:off + 2] in (b'\x48\x89', b'\x4c\x8b'):
            pass
        else:
            return False
        if HAS_CAPSTONE:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            try:
                insns = list(md.disasm(blob[off:off + 24], off, count=4))
            except CsError:
                return False
            if len(insns) < 2:
                return False
            for ins in insns[:3]:
                if ins.mnemonic in ('db', '.byte', 'invalid'):
                    return False
                if ins.mnemonic.startswith('f') and ins.mnemonic in (
                        'fisttp', 'fcomp', 'fadd', 'fsub', 'fdiv'):
                    return False
        return True

    @staticmethod
    def _e8_byte_is_real_call(out: bytearray, i: int) -> bool:
        """False when *i* is an ``0xE8`` byte inside a ``movabs`` immediate operand."""
        return not HealingMixin._pure_off_in_imm_operand(out, i)

    @staticmethod
    def _movabs_is_abs_load_pair(out, scan: int) -> bool:
        """True when ``movabs reg,imm`` at ``scan`` is immediately followed by a
        ``mov r32/r64,[reg]`` consuming the same register — the absolute-load
        idiom (``mov eax,[abs]``).  Such movabs belong to _try_fix_abs_load
        and must not be reanchored by push/store sites.

        Packed .data keeps dword slots, so the consumer is often
        ``41 8B /r`` (REX.B, no REX.W) rather than ``4x 8B /r``.
        """
        if scan + 2 >= len(out) or out[scan] not in (0x48, 0x49, 0x4C, 0x4D):
            return False
        if not (0xB8 <= out[scan + 1] <= 0xBF):
            return False
        mov_rex = out[scan]
        addr_reg = (out[scan + 1] & 7) + (8 if (mov_rex & 1) else 0)
        for p in range(scan + 10, min(scan + 22, len(out) - 2)):
            q = p
            rex = 0
            if out[q] in range(0x40, 0x50):
                rex = out[q]
                q += 1
                if q >= len(out) - 1:
                    break
            if out[q] != 0x8B:
                continue
            modrm = out[q + 1]
            # mod=00, rm≠4/5 → dword/qword ptr [reg]
            if (modrm & 0xC0) != 0:
                continue
            rm = modrm & 7
            if rm in (4, 5):
                continue
            base = rm + (8 if (rex & 1) else 0)
            if base == addr_reg:
                return True
        return False

    def _x86_rva_in_data_span(self, rva: int) -> bool:
        """True when *rva* falls in a pre-analysed non-code x86 span."""
        cf = self._x86_cf
        if not cf:
            return False
        for lo, hi in cf.data_spans:
            if lo <= rva < hi:
                return True
        return False

    @staticmethod
    def _is_translator_prologue(out: bytearray, pos: int) -> bool:
        """True if *pos* begins ``push r13; mov r13, rsp; sub rsp, N; and rsp, -16``."""
        if pos + 16 > len(out):
            return False
        return (out[pos:pos + 2] == b'\x41\x55'          # push r13
                and out[pos + 2:pos + 5] == b'\x49\x89\xe5'  # mov r13, rsp
                and out[pos + 5] == 0x48                     # REX.W
                and out[pos + 6] in (0x81, 0x83)             # sub rsp, imm
                and out[pos + 7] == 0xec)                    # ... , rsp

    def _find_nearest_crt_startup_off(self, text_blob: bytes,
                                      near_off: int) -> Optional[int]:
        """Locate translated CRT startup nearest *near_off* (PE entry anchor).

        Requires the canonical ``push rbp; mov rbp,rsp; push -1`` head, a
        following ``movabs rax, imm64`` (EH3 handler), and ``mov rax, gs:[0]``
        SEH prologue within 0x30 bytes.
        """
        crt_sig = b'\x55\x48\x89\xe5'  # push rbp; mov rbp, rsp
        crt_sig_old = b'\x55\x48\x89\xe5\x6a\xff'   # classic
        crt_sig_new = b'\x55\x48\x89\xe5\x48\x83\xe4\xf0\x6a\xff'  # aligned
        seh_gs = b'\x65\x48\x8b\x04\x25\x00\x00\x00\x00'
        best: Optional[int] = None
        best_dist = 0x7FFFFFFF
        idx = 0
        while True:
            j = text_blob.find(crt_sig, idx)
            if j < 0:
                break
            # Accept both classic and aligned CRT prologue signatures
            if not (text_blob[j:j + len(crt_sig_old)] == crt_sig_old
                    or (j + len(crt_sig_new) <= len(text_blob)
                        and text_blob[j:j + len(crt_sig_new)] == crt_sig_new)):
                idx = j + 1
                continue
            head = text_blob[j:j + 0x60]
            if b'\x48\xb8' not in head:
                idx = j + 1
                continue
            if seh_gs not in text_blob[j:j + 0x30]:
                idx = j + 1
                continue
            dist = abs(j - near_off)
            if dist < best_dist:
                best_dist = dist
                best = j
            idx = j + 1
        return best

    def _find_real_crt_entry_off(self, text_blob: bytes) -> Optional[int]:
        """Locate the translated MSVC CRT startup (eh3 + sub rsp,0x10c frame)."""
        eh3_imm = w2kshim_except_handler3_va()
        eh3_bytes = b'\x48\xb8' + struct.pack('<Q', eh3_imm)
        frame_10c = b'\x48\x81\xec\x0c\x01\x00\x00'
        best: Optional[int] = None
        idx = 0
        while idx < len(text_blob) - 0x40:
            j = text_blob.find(b'\x55\x48\x89\xe5', idx)
            if j < 0:
                break
            head = text_blob[j:j + 0x80]
            if eh3_bytes not in head or b'\x6a\xff' not in head:
                idx = j + 1
                continue
            chunk = text_blob[j:j + 0x120]
            if frame_10c not in chunk:
                idx = j + 1
                continue
            if best is None or j < best:
                best = j
            idx = j + 1
        return best

    def _looks_like_x64_insn_start(self, out: bytearray, off: int) -> bool:
        """Heuristic: *off* begins a plausible x64 instruction, not orphaned x86."""
        if off >= len(out):
            return False
        b0 = out[off]
        if b0 in (0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF):
            return False
        if off + 2 <= len(out) and out[off:off + 2] == b'\x84\x45':
            return False
        if b0 in (0x00, 0x01, 0x02, 0x03) and off + 1 < len(out) and out[off + 1] == 0x00:
            return False
        return b0 in (
            0x0F, 0x31, 0x33, 0x39, 0x3D, 0x44, 0x45, 0x48, 0x49, 0x4A, 0x4B,
            0x4C, 0x4D, 0x53, 0x55, 0x56, 0x57, 0x5B, 0x5E, 0x5F, 0x6A, 0x83,
            0x85, 0x89, 0x8B,
            0x8D, 0x90, 0xB8, 0xB9, 0xBA, 0xBB, 0xBF, 0xC3, 0xC7, 0xC9, 0xE8,
            0xE9, 0xEB, 0xFF, 0x41, 0x64, 0x66,
            # ALU / logic with imm8 or imm32 (and eax,imm / xor eax,imm / sub …)
            0x04, 0x05, 0x14, 0x15, 0x24, 0x25, 0x2C, 0x2D, 0x34, 0x35,
            0x3C, 0x3D, 0xA8, 0xA9, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
            0xB6, 0xB7, 0x80, 0x81, 0x82, 0x83,
        )

    def _is_spurious_inner_entry(self, func_rva: int, entry_rva: int,
                                 text_data: bytes, text_rva: int) -> bool:
        """Skip nested callee-save clusters that split an EBP-frame function."""
        if entry_rva <= func_rva:
            return False
        if (self._x86_cf and entry_rva in self._x86_cf.epilogue_labels):
            return True
        if self._x86_rva_in_data_span(entry_rva):
            return True
        off = entry_rva - text_rva
        if off < 0 or off + 3 > len(text_data):
            return False
        if _is_nested_ebp_callee_save(text_data, off):
            return True
        # Interior jcc/jmp labels (`mov ecx,[global]` etc.) inside one EBP function.
        if (text_data[off] == 0x8B and off + 1 < len(text_data)
                and text_data[off + 1] in (0x0D, 0x05, 0x15, 0x1D, 0x35, 0x3D)):
            return True
        return False

    def _looks_like_code(self, text_data: bytes, text_rva: int, rva: int) -> bool:
        """Heuristic: does `rva` look like a real function entry (not data)?"""
        off = rva - text_rva
        if off < 0 or off + 4 > len(text_data):
            return False
        b0, b1 = text_data[off], text_data[off + 1]
        # 00 00 = `add [eax],al` filler → data / jump-table padding.
        if b0 == 0x00 and b1 == 0x00:
            return False
        insns = list(self.md.disasm(text_data[off:off + 24],
                                    self.old_base + rva, count=4))
        if len(insns) < 3:
            return False
        # Require the prologue to be a plausible function opener.
        first = insns[0].mnemonic
        good_openers = (
            'push', 'mov', 'sub', 'lea', 'xor', 'cmp', 'test', 'and', 'or',
            'add', 'inc', 'dec', 'call', 'jmp', 'pop', 'enter', 'fld', 'fnclex',
        )
        return first in good_openers
