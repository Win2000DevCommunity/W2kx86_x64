"""Post-translation repair passes.

These re-derive call targets, branch destinations, and entry points after the
fact.  Most of them exist because addresses were baked into emitted bytes;
they shrink as emitters move to recording relocations instead.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class HealingMixin:
    """See the module docstring."""

    _CALLEE_POP_OPCODE: Dict[str, int] = {
        'rbx': 0x5B, 'rbp': 0x5D, 'rsi': 0x5E, 'rdi': 0x5F,
    }

    _WRAPPER_PROLOG = b'\x48\x89\xf1\x48\x89\xfa'   # mov rcx,rsi; mov rdx,rdi

    _WRAPPER_EPILOG = b'\x48\x89\xf0\x5f\x5e\xc3'    # mov rax,rsi; pop rdi; pop rsi; ret


    def _fix_seh_rbp_local_overlap(self, out: bytearray) -> int:
        """Post-patch [RBP+disp] in SEH functions when locals overlap 32-byte SEH record."""
        if not self.win10_test_shim or self._cmd_no_hacks:
            return 0
        gs_set = bytes([0x65, 0x48, 0x89, 0x24, 0x25, 0, 0, 0, 0])
        seh_mark = bytes([0x6A, 0xFF, 0x48, 0xB8])
        rbp_modrm = (0x45, 0x4D, 0x55, 0x5D, 0x65, 0x6D, 0x75, 0x7D)
        fixed = 0
        pos = 0
        while pos < len(out) - 20:
            if out[pos:pos + 4] != seh_mark:
                pos += 1
                continue
            gs = out.find(gs_set, pos, min(len(out), pos + 96))
            if gs < 0:
                pos += 1
                continue
            end = min(len(out), pos + 0x5000)
            npos = out.find(seh_mark, pos + 4, end)
            if npos > pos:
                end = npos
            i = gs + len(gs_set)
            while i < end - 2:
                if out[i] in rbp_modrm:
                    disp = struct.unpack_from('b', out, i + 1)[0]
                    if disp == -4:
                        nd = -8
                    elif disp <= -0x10 and (out[i + 1] & 0xFF) >= 0xE0:
                        nd = disp - 0x10
                    else:
                        nd = disp
                    if nd != disp and -128 <= nd <= 127:
                        struct.pack_into('b', out, i + 1, nd)
                        fixed += 1
                    i += 2
                    continue
                if (out[i] == 0xC7 and i + 2 < end
                        and out[i + 1] in (0x45, 0x85)):
                    disp = struct.unpack_from('b', out, i + 2)[0]
                    if disp == -4:
                        nd = -8
                    elif disp <= -0x10 and (out[i + 2] & 0xFF) >= 0xE0:
                        nd = disp - 0x10
                    else:
                        nd = disp
                    if nd != disp and -128 <= nd <= 127:
                        struct.pack_into('b', out, i + 2, nd)
                        fixed += 1
                i += 1
            pos = end
        return fixed

    def _snap_calls_back_to_nearby_prologue(self, out: bytearray,
                                            max_back: int = 12) -> int:
        """Snap E8 targets that miss a nearby real prologue by a few bytes.

        Typical: rva_map / refine lands 8 bytes into ``cmp rcx,0`` / ``jne``
        (``add [rax],al`` decode of imm tail).  Only walks *backward* onto a
        non-ret prologue within *max_back* bytes — never forward (that rewrote
        CRT calls when Capstone false-started).
        """
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < 0 or tgt >= len(out):
                continue
            if self._x64_entry_prologue_ok(out, tgt):
                continue
            if self._pure_off_in_imm_operand(out, tgt):
                continue  # dedicated mid-imm call snap pass
            # Already on the translated __chkstk body — never walk back onto
            # the neighbouring ``ff 25`` IAT thunk (same 12-byte window).
            if (out[tgt:tgt + 5] == b'\x3d\x00\x10\x00\x00'
                    or out[tgt:tgt + 6] == b'\x51\x3d\x00\x10\x00\x00'):
                continue
            snapped: Optional[int] = None
            for back in range(1, max_back + 1):
                pos = tgt - back
                if pos < 0:
                    break
                if out[pos] in (0xC3, 0xC2):
                    continue
                # IAT jmp thunks are valid *some* call targets, but never a
                # near-miss correction for a missed prologue — walking back
                # from ``cmp eax,0x1000`` (__chkstk) onto ``ff 25`` was the
                # univ48 regression.
                if out[pos:pos + 2] == b'\xff\x25':
                    continue
                if self._x64_entry_prologue_ok(out, pos):
                    snapped = pos
                    break
            if snapped is not None:
                struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                fixed += 1
        return fixed

    def _snap_calls_forward_past_epilogue(self, out: bytearray,
                                          max_fwd: int = 24) -> int:
        """Snap E8 targets that land in the previous function's epilogue.

        rva_map often points at ``pop r13; pop rsi; ret`` / ``and [rsi],0; ret``
        padding immediately before the real body (``push rbx`` / ``movabs`` /
        ``mov eax, ecx``).  Walking *forward* onto the next prologue recovers
        those calls (cmd ``d9bc``/``adad``/``efd6``).
        """
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < 0 or tgt + 8 >= len(out):
                continue
            if self._x64_entry_prologue_ok(out, tgt):
                continue
            # Only when the landing looks like an epilogue / dead pad.
            # Require a clear pop/ret tail — bare 0x41/0x90 matched too many
            # false positives and retargeted live CRT calls (univ51 execute
            # AV at 0x480000).
            looks_epi = (
                out[tgt] in (0xC3, 0xC2)
                or out[tgt:tgt + 2] in (
                    b'\x5e\xc3', b'\x5f\xc3', b'\x5b\xc3', b'\x5d\xc3',
                    b'\x41\x5d', b'\x41\x5e', b'\x41\x5f',
                    b'\x83\x26', b'\xff\xd0')
                or out[tgt:tgt + 3] in (
                    b'\x83\x26\x00', b'\x5e\x5f\xc3', b'\x5f\x5e\xc3')
                or out[tgt:tgt + 4] == b'\x41\x5d\x5e\xc3'
                # ``mov eax, e[bsi]; pop*; leave; ret`` — prior-fn epilogue
                # that call sync re-pins after earlier past-epilogue snaps
                # (cmd ``fbe4`` → ``1df11``).
                or (out[tgt] == 0x89
                    and out[tgt + 1] in (0xD8, 0xF0, 0xF8, 0xC8, 0xD0)
                    and tgt + 2 < len(out)
                    and out[tgt + 2] in (0x58, 0x59, 0x5A, 0x5B,
                                         0x5C, 0x5D, 0x5E, 0x5F))
            )
            if not looks_epi:
                continue
            snapped: Optional[int] = None
            for fwd in range(1, max_fwd + 1):
                pos = tgt + fwd
                if pos + 4 >= len(out):
                    break
                if out[pos] in (0xC3, 0xC2):
                    continue
                if self._x64_entry_prologue_ok(out, pos):
                    snapped = pos
                    break
                # Frameless ``mov eax, ecx`` store-arg openers (cmd adad).
                if (out[pos:pos + 2] in (b'\x89\xc8', b'\x8b\xc1')
                        or out[pos:pos + 3] == b'\x48\x89\xc8'):
                    snapped = pos
                    break
            if snapped is not None and snapped != tgt:
                struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                fixed += 1
        return fixed

    def _fix_arg_select_lea_selfjmp(self, out: bytearray) -> int:
        """Rewrite MSVC ``push buf; jmp join; push alt; join: push fmt; call``.

        Broken translate leaves::
            lea rax, [rbp+disp]
            jmp $                 ; E9 FBFFFFFF
            movabs rcx, fmt
            movabs rdx, alt

        Same-sized rewrite::
            lea rdx, [rbp+disp]   ; success arg2 = buffer
            jmp join              ; skip alt
            movabs rdx, alt       ; fail path (existing ``je`` already lands here)
            movabs rcx, fmt       ; join
        """
        fixed = 0
        i = 0
        while i + 32 <= len(out):
            if (out[i:i + 3] == b'\x48\x8d\x85'
                    and out[i + 7:i + 12] == b'\xe9\xfb\xff\xff\xff'
                    and out[i + 12:i + 14] == b'\x48\xb9'
                    and out[i + 22:i + 24] == b'\x48\xba'):
                rcx_blk = bytes(out[i + 12:i + 22])
                rdx_blk = bytes(out[i + 22:i + 32])
                out[i + 2] = 0x95  # lea rdx, [rbp+disp]
                out[i + 7] = 0xE9
                # after jmp at i+12; join (movabs rcx) at i+22 → rel = 10
                struct.pack_into('<i', out, i + 8, 10)
                out[i + 12:i + 22] = rdx_blk
                out[i + 22:i + 32] = rcx_blk
                fixed += 1
                i += 32
                continue
            i += 1
        return fixed

    def _fix_self_relative_jmps(self, out: bytearray) -> int:
        """Fix known self-jmp patterns from lost branch fixups.

        Only rewrites the MSVC arg-select ``lea`` diamond.  Blind ``jmp $`` →
        fallthrough is unsafe — other self-jmps need a real target, not a
        silent resume into the next unrelated instruction.
        """
        return self._fix_arg_select_lea_selfjmp(out)

    def _fix_calls_into_movabs_imm(self, out: bytearray) -> int:
        """Snap E8 targets that land inside a ``movabs r64, imm64`` immediate.

        Classic failure: call lands 8 bytes into ``48 B8 <imm64>`` (high half of
        an IAT VA such as ``0x8008….``), so the CPU executes the imm as opcodes
        (``add [rax], al`` …) and faults.  Also covers the older special case
        where the low byte of the imm is ``0xE9`` (looks like a jmp opcode).

        Prefer the outer call-align entry (``push r13``) when the movabs sits
        inside an align wrapper so shadow space / alignment stay correct.

        Note: do NOT generalise to ``mov r64, imm32`` (``48 C7 C0+r``) here —
        that false-matched thousands of good call targets (univ161: 4985).
        Function-entry mid-imm32 tips are repaired by
        ``_pure_fix_fn_entry_mid_imm_tips``.
        """
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < 2 or tgt >= len(out):
                continue
            movabs: Optional[int] = None
            # Legacy: landing exactly on 0xE9 with ``48 B8`` two bytes back.
            if out[tgt - 2:tgt] == b'\x48\xb8' and out[tgt] == 0xE9:
                movabs = tgt - 2
            else:
                # General: any offset inside the 8-byte imm of REX.W movabs.
                for back in range(2, 10):
                    p = tgt - back
                    if p < 0:
                        break
                    if (out[p] in (0x48, 0x49, 0x4C, 0x4D)
                            and 0xB8 <= out[p + 1] <= 0xBF
                            and p + 2 <= tgt <= p + 9):
                        movabs = p
                        break
            if movabs is None:
                continue
            snapped = movabs
            outer = self._outer_entry_before_align(out, movabs)
            if outer is not None:
                snapped = outer
            if snapped != tgt:
                struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                fixed += 1
        return fixed

    def _pure_fix_fn_entry_mid_imm_tips(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: Optional[bytes] = None,
            text_rva: int = 0) -> int:
        """Snap function-entry rva_map tips off movabs / mov-r64-imm32 immediates.

        cmd ``db0b`` (``push 0x50; call alloc``) emits ``mov rcx, 0x50`` at the
        thunk entry; rva_map sometimes tips onto the imm32 so callers land mid-
        instruction.  Only ``_fn_entry_rvas`` / x86 call targets are rewritten.
        """
        if not self._cmd_no_hacks or not rva_map:
            return 0
        candidates: Set[int] = set(getattr(self, '_fn_entry_rvas', None) or set())
        text_data = text_data or getattr(self, '_pure_heal_text', None)
        text_rva = int(text_rva or getattr(self, '_pure_heal_text_rva', 0) or 0)
        if text_data:
            n = len(text_data)
            for off in range(max(0, n - 5)):
                if text_data[off] == 0xE8 and off + 5 <= n:
                    rel = struct.unpack_from('<i', text_data, off + 1)[0]
                    tgt = (text_rva + off + 5 + rel) & 0xFFFFFFFF
                    candidates.add(tgt)
        if not candidates:
            return 0
        fixed = 0
        text_new = int(self._old_to_new_section.get(text_rva, text_rva)
                       if self._old_to_new_section else text_rva)

        def _blob_off(v: int) -> Optional[int]:
            v = int(v)
            if 0 <= v < len(out):
                return v
            if text_new and v >= text_new and (v - text_new) < len(out):
                return v - text_new
            return None

        for old_rva in candidates:
            raw = rva_map.get(old_rva)
            if raw is None:
                continue
            off = _blob_off(raw)
            if off is None:
                continue
            if not self._pure_off_in_imm_operand(out, off):
                continue
            snapped = None
            for back in range(1, 10):
                p = off - back
                if p < 0:
                    break
                if (out[p] in (0x48, 0x49, 0x4C, 0x4D)
                        and 0xB8 <= out[p + 1] <= 0xBF):
                    snapped = p
                    break
                if (out[p] in (0x48, 0x49)
                        and out[p + 1] == 0xC7
                        and (out[p + 2] & 0xF8) == 0xC0):
                    snapped = p
                    break
            if snapped is None or snapped == off:
                continue
            # Require thunk shape for non-entry call targets: ``mov r64, imm32``
            # immediately followed by align-stub ``push r13`` (cmd db0b).
            is_fn = old_rva in (getattr(self, '_fn_entry_rvas', None) or set())
            if not is_fn:
                if not (out[snapped] in (0x48, 0x49)
                        and out[snapped + 1] == 0xC7
                        and (out[snapped + 2] & 0xF8) == 0xC0):
                    continue
                after = snapped + 7
                if after + 2 > len(out) or out[after:after + 2] != b'\x41\x55':
                    continue
            # Also retarget direct E8s that still land on the old mid-imm tip.
            for i in range(len(out) - 5):
                if out[i] != 0xE8:
                    continue
                if not self._e8_byte_is_real_call(out, i):
                    continue
                rel = struct.unpack_from('<i', out, i + 1)[0]
                if i + 5 + rel != off:
                    continue
                struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                fixed += 1
            rva_map[old_rva] = snapped
            fixed += 1
        if fixed:
            self._pure_insn_starts_cache = None
        return fixed

    def _fix_jccs_into_movabs_imm(self, out: bytearray) -> int:
        """Snap near/short Jcc targets that land inside a ``movabs`` immediate.

        Same failure mode as :meth:`_fix_calls_into_movabs_imm`, but for
        conditional branches (cmd ``cmp ax,'?'; jne`` → mid-imm of the next
        switch ``movabs`` → execute ``add [rax],al`` / write AV).  Always snap
        *back* to the movabs opcode — never forward onto the following cmp.

        Capstone mid-insn confirmation only — byte-heuristic ``00`` filters
        alone false-positive dozens of real CRT branches (univ58: 72).
        """
        if not HAS_CAPSTONE:
            return 0
        fixed = 0
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        def _movabs_of(tgt: int) -> Optional[int]:
            """Return movabs start if *tgt* falls inside its imm64 (Capstone-confirmed)."""
            if tgt < 2 or tgt >= len(out):
                return None
            for back in range(2, 10):
                p = tgt - back
                if p < 0 or p + 9 >= len(out):
                    break
                if not (out[p] in (0x48, 0x49, 0x4C, 0x4D)
                        and 0xB8 <= out[p + 1] <= 0xBF
                        and p + 2 <= tgt <= p + 9):
                    continue
                # Decode *at* the candidate opcode — avoids window desync
                # false hits that plagued the univ58 byte-heuristic pass.
                got = list(md.disasm(bytes(out[p:p + 10]), p))
                if (got and got[0].address == p and got[0].size == 10
                        and p < tgt < p + 10):
                    return p
            return None

        # Raw-byte Jcc scan, but only rewrite when:
        #  1) a backward Capstone window confirms *i* is a real insn start
        #     (decoding at *i* alone false-hits mid-imm 0F 8x encodings),
        #  2) _movabs_of confirms the target sits mid-imm of a movabs.
        jcc_mnems = {
            'jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc',
            'jz', 'je', 'jnz', 'jne', 'jbe', 'jna', 'ja', 'jnbe',
            'js', 'jns', 'jp', 'jpe', 'jnp', 'jpo', 'jl', 'jnge',
            'jge', 'jnl', 'jle', 'jng', 'jg', 'jnle',
        }

        def _is_real_insn_start(i: int) -> bool:
            lo = max(0, i - 16)
            for insn in md.disasm(bytes(out[lo:i + 6]), lo):
                if insn.address == i:
                    return True
                if insn.address > i:
                    return False
            return False

        for i in range(len(out) - 6):
            if out[i] == 0x0F and 0x80 <= out[i + 1] <= 0x8F:
                if not _is_real_insn_start(i):
                    continue
                site = list(md.disasm(bytes(out[i:i + 6]), i))
                if (not site or site[0].address != i or site[0].size != 6
                        or site[0].mnemonic not in jcc_mnems):
                    continue
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                movabs = _movabs_of(tgt)
                if movabs is not None and movabs != tgt:
                    struct.pack_into('<i', out, i + 2, movabs - (i + 6))
                    fixed += 1
                continue
            if 0x70 <= out[i] <= 0x7F:
                if not _is_real_insn_start(i):
                    continue
                site = list(md.disasm(bytes(out[i:i + 2]), i))
                if (not site or site[0].address != i or site[0].size != 2
                        or site[0].mnemonic not in jcc_mnems):
                    continue
                rel = struct.unpack_from('<b', out, i + 1)[0]
                tgt = i + 2 + rel
                movabs = _movabs_of(tgt)
                if movabs is not None and movabs != tgt:
                    new_rel = movabs - (i + 2)
                    if -128 <= new_rel <= 127:
                        out[i + 1] = new_rel & 0xFF
                        fixed += 1
        return fixed

    def _fix_fn6314_scan_loop(self, out: bytearray, fn6314: int) -> int:
        """fn6314 ``=`` scan loop: x86 ``ebp`` length must not live in ``rbp`` (frame ptr)."""
        lo = fn6314
        hi = min(len(out), fn6314 + 0x170)
        span = out[lo:hi]
        fixed = 0
        # ``mov rbp, rax`` after wcslen(path) → ``mov r12, rax``
        mov_rbp = b'\x48\x89\xc5'
        mov_r12 = b'\x49\x89\xc4'
        pos = 0
        while True:
            j = span.find(mov_rbp, pos)
            if j < 0:
                break
            off = lo + j
            if (off + 8 <= len(out)
                    and out[off + 3:off + 8] == b'\xe9\x03\x00\x00\x00'):
                out[off:off + 3] = mov_r12
                fixed += 1
            pos = j + 1
        tail = b'\xe9\x03\x00\x00\x00\x48\x31\xed\x48\x85\xed'
        repl = b'\xe9\x03\x00\x00\x00\x4d\x31\xe4\x4d\x85\xe4'
        j = span.find(tail)
        if j >= 0:
            out[lo + j:lo + j + len(tail)] = repl
            fixed += 1
        good_lea = b'\x4a\x8d\x74\x66\x02'  # lea rsi, [rsi + r12*2 + 2]
        for bad in (b'\x48\x8d\x74\x6e\x02', b'\x48\x8d\x74\x7e\x02',
                    b'\x48\x8d\x74\x46\x02'):
            p = 0
            while True:
                k = span.find(bad, p)
                if k < 0:
                    break
                out[lo + k:lo + k + len(good_lea)] = good_lea
                fixed += 1
                p = k + 1
        return fixed

    def _fix_fn6314_loop_branches(self, out: bytearray, fn6314: int) -> int:
        """Snap SetEnv callers that branch to fn6314+0xB9 instead of the loop head."""
        if not self.text_rva:
            return 0
        loop = 0x2DCC0 - self.text_rva
        bad = 0x2DCC4 - self.text_rva
        if loop < 0 or bad < 0 or loop + 8 >= len(out):
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 6:
            if out[i] == 0x0F and out[i + 1] in (0x84, 0x85, 0x8C, 0x8D, 0x8E, 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if tgt == bad:
                    struct.pack_into('<i', out, i + 2, loop - (i + 6))
                    fixed += 1
                i += 6
                continue
            if out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt == bad:
                    struct.pack_into('<i', out, i + 1, loop - (i + 5))
                    fixed += 1
                i += 5
                continue
            i += 1
        return fixed

    def _fix_fn6314_jump_exit(self, out: bytearray, fn6314: int) -> int:
        """CRT jumps into fn6314 scan loop — shared exit must jmp, not ret."""
        exit_off = fn6314 + 0x15D
        cont_off = 0x8EB9 - self.text_rva
        if (exit_off + 5 > len(out) or cont_off < 0
                or out[exit_off:exit_off + 1] != b'\xc3'):
            return 0
        rel = cont_off - (exit_off + 5)
        out[exit_off] = 0xE9
        struct.pack_into('<i', out, exit_off + 1, rel)
        return 1

    def _materialized_scope_byte_size(self, out: bytearray, off: int) -> int:
        """Byte size of a scope table already copied into the output blob."""
        if off < 0 or off + 4 > len(out):
            return 16
        if out[off:off + 4] != b'\xff\xff\xff\xff':
            return 16
        code_lo = self.new_base + self.text_rva
        code_hi = code_lo + len(out)
        size = 4
        for _ in range(32):
            eoff = off + size
            if eoff + 16 > len(out):
                break
            begin, end, filt, handler = struct.unpack_from('<4I', out, eoff)
            if not (code_lo <= begin < code_hi and code_lo < end <= code_hi
                    and begin < end):
                break
            if filt and not (code_lo <= filt < code_hi):
                break
            if handler and not (code_lo <= handler < code_hi):
                break
            size += 16
        return max(size, 16)

    def _snap_calls_to_enclosing_entries(self, out: bytearray,
                                         rva_map: Optional[Dict[int, int]] = None,
                                         lo_rva: int = 0,
                                         hi_rva: int = 0) -> int:
        """Snap E8 rel32 call targets onto enclosing function entries (binary-generic)."""
        if not self.text_rva:
            return 0
        lo = lo_rva - self.text_rva if lo_rva else 0
        hi = hi_rva - self.text_rva if hi_rva else len(out)
        fixed = 0
        for i in range(max(0, lo), min(len(out) - 5, hi)):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt <= 0 or tgt >= len(out):
                continue
            if out[tgt] in (0xC3, 0xC2):
                continue
            if (self._x86_cf and rva_map
                    and any(rva_map.get(ep_rva) == tgt
                            for ep_rva in self._x86_cf.epilogue_labels)):
                continue
            entry = self._find_enclosing_function_entry(out, tgt, rva_map)
            if (entry is not None and entry != tgt
                    and self._entry_snapworthy(out, entry, rva_map)):
                struct.pack_into('<i', out, i + 1, entry - (i + 5))
                fixed += 1
        return fixed

    def _snap_call_to_x86_target(self, out: bytearray, x86_call_rva: int,
                                 x86_tgt_rva: int,
                                 rva_map: Optional[Dict[int, int]]) -> int:
        """Snap one shim E8 to the entry for *x86_tgt_rva* (rva_map correspondence)."""
        if not rva_map or not self.text_rva:
            return 0
        call_off = self._find_shim_call_for_x86_call(
            out, x86_call_rva, x86_tgt_rva, rva_map)
        entry = self._entry_for_x86_target(out, x86_tgt_rva, rva_map)
        if call_off is None or entry is None:
            return 0
        if call_off + 5 > len(out) or out[call_off] != 0xE8:
            return 0
        rel = struct.unpack_from('<i', out, call_off + 1)[0]
        if call_off + 5 + rel == entry:
            return 0
        struct.pack_into('<i', out, call_off + 1, entry - (call_off + 5))
        return 1

    def _snap_calls_via_x86_correspondence(self, out: bytearray,
                                           rva_map: Optional[Dict[int, int]],
                                           lo_x86: int = 0,
                                           hi_x86: int = 0) -> int:
        """Snap misaligned shim CALL sites using x86 call/target pairs + rva_map."""
        if not rva_map or not self.text_rva or not self.pe:
            return 0
        sec = self.pe.section_for_rva(self.text_rva)
        if not sec:
            return 0
        x86_text = self.pe.get_section_data(sec)
        x86_base = sec['vaddr']
        lo = lo_x86 - x86_base if lo_x86 else 0
        hi = hi_x86 - x86_base if hi_x86 else len(x86_text)
        image_end = self.pe.image_size
        fixed = 0
        for i in range(max(0, lo), min(len(x86_text) - 5, hi)):
            if x86_text[i] != 0xE8:
                continue
            rel = struct.unpack_from('<i', x86_text, i + 1)[0]
            tgt_off = i + 5 + rel
            if tgt_off < 0 or tgt_off >= len(x86_text):
                continue
            call_x86 = x86_base + i
            tgt_x86 = x86_base + tgt_off
            if tgt_x86 < x86_base or tgt_x86 >= image_end:
                continue
            entry = self._entry_for_x86_target(out, tgt_x86, rva_map)
            if entry is None:
                continue
            call_off = self._find_shim_call_for_x86_call(
                out, call_x86, tgt_x86, rva_map)
            if call_off is None or call_off + 5 > len(out):
                continue
            if out[call_off] != 0xE8:
                continue
            cur = call_off + 5 + struct.unpack_from('<i', out, call_off + 1)[0]
            if cur == entry:
                continue
            if (self._offset_is_function_entry(out, cur)
                    and cur == entry):
                continue
            struct.pack_into('<i', out, call_off + 1, entry - (call_off + 5))
            fixed += 1
        return fixed

    def _fix_fn6314_callee_ret(self, out: bytearray, fn6314: int) -> int:
        """fn6314 early/success exits used an SEH epilogue without a matching prologue."""
        # Blob offset of ``pop rdi; pop rsi; pop rbx; …; ret`` shared exit (RVA 0x2DD68).
        exit_off = fn6314 + 0x15D
        bad_head = b'\x5f\x5e\x5b\xc7\x45\xf8\xff\xff\xff\xff'
        span = 0x2DD91 - 0x2DD68
        if (exit_off + len(bad_head) > len(out)
                or out[exit_off:exit_off + len(bad_head)] != bad_head):
            return 0
        out[exit_off:exit_off + span] = b'\xc3' + b'\x90' * (span - 1)
        return 1

    def _fix_scope_handlers_at_push_sites(self, out: bytearray,
                                          text_rva: int) -> int:
        """Normalize handler DWORDs at every SEH ``push scope`` target (reliable tail fix)."""
        if not self.win10_test_shim:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 14:
            if not (out[i] == 0x6A and out[i + 1] == 0xFF
                    and out[i + 2] == 0x48 and out[i + 3] == 0xB8):
                i += 1
                continue
            scope_imm = struct.unpack_from('<Q', out, i + 4)[0]
            scope_off = scope_imm - self.new_base - text_rva
            if (scope_off < 0 or scope_off + 20 > len(out)
                    or out[scope_off:scope_off + 4] != b'\xff\xff\xff\xff'):
                i += 14
                continue
            rec = scope_off + 4
            end = min(scope_off + 64, len(out) - 15)
            while rec + 16 <= end:
                begin, end_va, _filt, handler = struct.unpack_from('<4I', out, rec)
                if not self._valid_scope_record_begin_end(begin, end_va):
                    break
                new_h = self._scope_handler_dword(handler)
                if new_h != handler:
                    struct.pack_into('<I', out, rec + 12, new_h)
                    fixed += 1
                rec += 16
            i += 14
        return fixed

    def _fix_broken_entry_seh_scope_pushes(self, out: bytearray,
                                           rva_map: Optional[Dict[int, int]],
                                           text_rva: Optional[int] = None) -> int:
        """Point SEH scope pushes at restored tail scope tables, not NOP sled interiors."""
        if not self.win10_test_shim:
            return 0
        if text_rva is None:
            text_rva = self.text_rva
        bad_lo = self.new_base + 0x3FD50
        bad_hi = self.new_base + 0x3FE20
        fixed = 0
        scope_by_base = dict(self._scope_table_old_rva)
        i = 0
        while i < len(out) - 14:
            if not (out[i] == 0x6A and out[i + 1] == 0xFF
                    and out[i + 2] == 0x48 and out[i + 3] == 0xB8):
                i += 1
                continue
            imm = struct.unpack_from('<Q', out, i + 4)[0]
            blob_off = imm - self.new_base - text_rva
            correct_off = None
            if blob_off in scope_by_base:
                correct_off = blob_off
            elif 0 <= blob_off < len(out) and self._valid_scope_sentinel(out, blob_off):
                correct_off = blob_off
            elif bad_lo <= imm <= bad_hi:
                slot = ((blob_off - 0x3ED50) // 0x10) * 0x10 + 0x3ED50
                if slot in scope_by_base:
                    correct_off = slot
                else:
                    for base in sorted(scope_by_base.keys()):
                        if abs(base - blob_off) <= 0x20:
                            correct_off = base
                            break
            if correct_off is not None:
                new_imm = self.new_base + text_rva + correct_off
                if imm != new_imm:
                    tgt = correct_off
                    if (0 <= tgt < len(out)
                            and self._valid_scope_sentinel(out, tgt)):
                        i += 14
                        continue
                    struct.pack_into('<Q', out, i + 4, new_imm)
                    fixed += 1
            i += 14
        return fixed

    def _repair_branches_from_ubrt(self, out: bytearray,
                                   rva_map: Dict[int, int]) -> int:
        """
        Patch relative branches using win2k_analyzer UBRT static reference DB.
        Authoritative (ref_rva, target_rva) pairs from the x86 source PE.
        """
        refs = self._load_ubrt_refs()
        if not refs:
            return 0

        md64 = Cs(CS_ARCH_X86, CS_MODE_64)
        md64.detail = True
        fixed = 0
        seen: Set[Tuple[int, int]] = set()

        for ref in refs:
            rtype = ref.ref_type.value if hasattr(ref.ref_type, 'value') else str(ref.ref_type)
            if rtype not in _UBRT_BRANCH_TYPES:
                continue
            if not ref.is_relative:
                continue
            src_rva = ref.ref_rva
            tgt_rva = ref.target_rva
            tgt_new = rva_map.get(tgt_rva)
            if tgt_new is None:
                continue
            src_new = self._rva_map_lookup(rva_map, src_rva)
            if src_new is None or src_new >= len(out):
                continue
            key = (src_new, tgt_new)
            if key in seen:
                continue

            window = bytes(out[src_new:src_new + 16])
            patched = False
            for insn in md64.disasm(window, src_new, count=1):
                if insn.mnemonic not in ('call', 'jmp') and not insn.mnemonic.startswith('j'):
                    break
                if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                    break
                if insn.size == 2 and insn.operands[0].size == 8:
                    rel = tgt_new - (insn.address + 2)
                    if -128 <= rel <= 127:
                        out[insn.address + 1] = rel & 0xFF
                        fixed += 1
                        patched = True
                elif insn.size >= 5:
                    disp_off = insn.address + insn.size - 4
                    rel = tgt_new - (disp_off + 4)
                    struct.pack_into('<i', out, disp_off, rel)
                    fixed += 1
                    patched = True
                break
            if patched:
                seen.add(key)
        return fixed

    def _pure_old_iat_for_imm(self, imm: int) -> Optional[int]:
        """Map a movabs/cell immediate to its x86 IAT slot VA when possible."""
        if self.old_base <= imm < self.old_base + self.pe.image_size:
            old_rva = imm - self.old_base
            if old_rva in self._iat_rva_map or old_rva in self._iat_old_rvas:
                return self.old_base + old_rva
        if self.new_base <= imm < self.new_base + 0x200000:
            for delta in (0, -1, 1, -8, 8):
                old = self._old_iat_va_for_idata_cell(imm + delta)
                if old:
                    return old
            cell_rva = imm - self.new_base
            # Exact slot match first — a ref that already sits exactly on its
            # slot must win.  Adjacent slots are 8 bytes apart, so a ±8
            # first-found match would misidentify e.g. slot 11 (_setjmp3) as
            # slot 10 (_except_handler3) and silently re-route the call.
            for old_rva, new_rva in (self._iat_rva_map or {}).items():
                if new_rva == cell_rva:
                    return self.old_base + old_rva
            # Nearest-neighbour within ±8 only when no exact slot matches.
            best_rva = None
            best_dist = 9
            for old_rva, new_rva in (self._iat_rva_map or {}).items():
                dist = abs(new_rva - cell_rva)
                if dist < best_dist:
                    best_dist = dist
                    best_rva = old_rva
            if best_rva is not None:
                return self.old_base + best_rva
        return None

    def _fix_pure_iat_movabs_cells(self, out: bytearray) -> int:
        """Point movabs IAT cell loads at PE64 .idata slots (pure mode)."""
        if not self._cmd_no_hacks or not self._iat_rva_map:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 10:
            if out[i] not in (0x48, 0x49, 0x4C, 0x4D) or not (0xB8 <= out[i + 1] <= 0xBF):
                i += 1
                continue
            imm = struct.unpack_from('<Q', out, i + 2)[0]
            old_iat = self._pure_old_iat_for_imm(imm)
            if old_iat:
                new_imm = self._resolve_iat_slot_va(old_iat)
                if new_imm != imm:
                    struct.pack_into('<Q', out, i + 2, new_imm)
                    fixed += 1
            i += 10
        return fixed

    def _fix_pure_indirect_iat_calls(self, out: bytearray) -> int:
        """CRT/early-init only: avoid full-.text movabs→call [IAT] rewrites."""
        if not self._cmd_no_hacks or not self.win10_test_shim or not self.text_rva:
            return 0
        return self._fix_cmd_text_indirect_iat_calls(out)

    def _materialized_scope_base(self, scope_old: int) -> Optional[int]:
        for base, old in self._scope_table_old_rva.items():
            if old == scope_old:
                return base
        return self.rva_map.get(scope_old)

    def _fix_scope_tables_in_blob(self, out: bytearray) -> int:
        """Last-chance rewrite of SEH scope begin/end DWORDs in the orphan tail."""
        if not self._orphan_blob_out_ranges:
            return 0
        fixed = 0
        tail = min(s for s, _ in self._orphan_blob_out_ranges)
        for off in range(tail, len(out) - 19):
            if not self._valid_scope_sentinel(out, off):
                continue
            scope_old = None
            for old_rva, mapped in self.rva_map.items():
                if mapped == off:
                    scope_old = old_rva
                    break
            if scope_old is None:
                scope_old = self._scope_old_rva_for_blob_off(off)
            pos = off + 4
            begin, end_va, filt, handler = struct.unpack_from('<4I', out, pos)
            for idx, val in enumerate((begin, end_va, filt, handler)):
                if idx == 3:
                    new_val = self._scope_handler_dword(val)
                elif val == 0:
                    new_val = 0
                elif self.old_base <= val < self.old_base + self.pe.image_size:
                    new_val = self._scope_va_to_pe64(val, scope_old) & 0xFFFFFFFF
                else:
                    new_val = val
                struct.pack_into('<I', out, pos + idx * 4, new_val)
                if new_val != val:
                    fixed += 1
            pos += 16
            if pos + 16 <= len(out):
                b2, e2, f2, h2 = struct.unpack_from('<4I', out, pos)
                if not (self.old_base <= b2 < self.old_base + self.pe.image_size
                        and self.old_base < e2 <= self.old_base + self.pe.image_size):
                    pass
        return fixed

    def _pure_off_in_zero_hole(self, out: bytearray, off: int) -> bool:
        """True when *off* sits inside a >=8-byte run of zeros (wiped hole)."""
        if off < 0 or off + 4 > len(out) or any(out[off:off + 4]):
            return False
        lo = off
        while lo > 0 and out[lo - 1] == 0:
            lo -= 1
        hi = off + 4
        while hi < len(out) and out[hi] == 0:
            hi += 1
        return (hi - lo) >= 8

    def _materialize_x86_code_region(self, out: bytearray, rva_map: Dict[int, int],
                                     text_data: bytes, text_rva: int,
                                     start_rva: int, end_rva: int,
                                     deferred_branches: List[Tuple[int, int, str]]) -> None:
        """Translate a small x86 code blob (CRT tail wrappers) omitted by discovery."""
        if start_rva in rva_map:
            return
        off = start_rva - text_rva
        end_off = end_rva - text_rva
        if off < 0 or end_off > len(text_data) or end_off <= off:
            return
        blob = text_data[off:end_off]
        base = len(out)
        chunk_out, chunk_map = self._translate_function(
            start_rva, blob, False, 0, chunk_base=base, section_rva=text_rva,
            global_rva_map=rva_map, deferred_branches=deferred_branches)
        if not chunk_out:
            return
        rva_map[start_rva] = base
        for old_va, rel in chunk_map.items():
            old_r = old_va - self.old_base
            if old_r not in rva_map:
                rva_map[old_r] = base + rel
            elif self._pure_off_in_zero_hole(out, rva_map[old_r]):
                # Stale entry points into a wiped hole — chunk-local wins.
                rva_map[old_r] = base + rel
        out += chunk_out
        pad = (4 - len(out) % 4) % 4
        if pad:
            out += b'\x90' * pad

    def _materialize_orphan_text_refs(self, out: bytearray, rva_map: Dict[int, int],
                                      text_data: bytes, text_rva: int,
                                      refs: Set[int],
                                      deferred_branches: Optional[List[Tuple[int, int, str]]] = None) -> int:
        """Emit SEH scope tables and IAT jmp thunks omitted by function-driven layout."""
        code_refs: List[int] = []
        data_refs: List[int] = []
        for old_rva in sorted(refs):
            if old_rva in rva_map:
                continue
            off = old_rva - text_rva
            if off < 0 or off >= len(text_data):
                continue
            if text_data[off:off + 2] == b'\xff\x25':
                code_refs.append(old_rva)
            else:
                data_refs.append(old_rva)

        added = 0
        if deferred_branches is not None:
            for old_rva in code_refs:
                off = old_rva - text_rva
                raw = text_data[off:off + 6]
                iat_va = struct.unpack_from('<I', raw, 2)[0]
                old_slot = self._imm_to_old_rva(iat_va)
                if old_slot in self._iat_old_rvas:
                    continue
                ptr32 = self._read_pe_dword(old_slot)
                if (ptr32 and self.old_base <= ptr32 < self.old_base + self.pe.image_size):
                    stub_rva = ptr32 - self.old_base
                    stub_end = self._runtime_stub_end_rva(text_data, text_rva, stub_rva)
                    self._materialize_x86_code_region(
                        out, rva_map, text_data, text_rva,
                        stub_rva, stub_end, deferred_branches)

        for old_rva in code_refs:
            off = old_rva - text_rva
            raw = text_data[off:off + 6]
            iat_va = struct.unpack_from('<I', raw, 2)[0]
            old_slot = self._imm_to_old_rva(iat_va)
            if old_slot in self._iat_old_rvas:
                base = len(out)
                rva_map[old_rva] = base
                self._emit_iat_jmp(out, iat_va, at_rva=text_rva + base)
            else:
                pad = (8 - len(out) % 8) % 8
                if pad:
                    out += b'\x00' * pad
                slot_off = self._emit_runtime_pointer_slot(
                    out, text_data, text_rva, old_slot, rva_map)
                slot_va = self.new_base + text_rva + slot_off
                jmp_off = len(out)
                rva_map[old_rva] = jmp_off
                self._emit_iat_jmp(out, slot_va, at_rva=text_rva + jmp_off)
                pad16 = (16 - len(out) % 16) % 16
                if pad16:
                    out += b'\x90' * pad16
            pad = (4 - len(out) % 4) % 4
            if pad:
                out += b'\x90' * pad
            added += 1

        for old_rva in data_refs:
            off = old_rva - text_rva
            raw = text_data[off:off + 32]
            if raw[:4] == b'\xff\xff\xff\xff':
                size = _msvc_scope_table_size(self.pe, text_data, text_rva, off)
                raw = text_data[off:off + size]
            else:
                size = _embedded_text_blob_size(text_data, off)
                raw = text_data[off:off + size]
            base = len(out)
            out += raw[:size]
            pad = (4 - len(out) % 4) % 4
            if pad:
                out += b'\x00' * pad
            rva_map[old_rva] = base
            if raw[:4] == b'\xff\xff\xff\xff':
                self._scope_table_out_ranges.append((base, size))
                self._scope_table_old_rva[base] = old_rva
            self._orphan_blob_out_ranges.append((base, size))
            added += 1
        return added

    def _relink_branch_targets(self, out: bytearray,
                               relink: Dict[int, int]) -> int:
        """Patch E8/E9 rel32 that still aim at superseded blob offsets."""
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] == 0xE8:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt in relink:
                    struct.pack_into('<i', out, i + 1, relink[tgt] - (i + 5))
                    fixed += 1
            elif out[i] == 0xE9:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt in relink:
                    struct.pack_into('<i', out, i + 1, relink[tgt] - (i + 5))
                    fixed += 1
            elif out[i] == 0x0F and i + 5 < len(out) and 0x80 <= out[i + 1] <= 0x8F:
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                if tgt in relink:
                    struct.pack_into('<i', out, i + 2, relink[tgt] - (i + 6))
                    fixed += 1
        return fixed

    @staticmethod
    def _pure_is_corrupt_x86_hybrid(out: bytearray, off: int) -> bool:
        """True when *off* begins a broken x86 spill encoded inside PE64 text."""
        if off < 0 or off + 6 > len(out):
            return False
        if off + 2 <= len(out) and out[off] in (0x53, 0x56, 0x57, 0x55):
            if out[off + 1:off + 3] == b'\xff\x35':
                return True
        if off + 8 <= len(out) and out[off:off + 2] == b'\xff\x35':
            tail = out[off + 5:off + 8]
            if tail in (b'\x89\x44\x24', b'\x89\x04\x24', b'\x89\x54\x24'):
                return True
        if (off > 0 and out[off - 1] in (0x53, 0x56, 0x57, 0x55)
                and out[off:off + 2] == b'\xff\x35'):
            return True
        return False

    def _pure_is_unrelocated_old_va_movabs(self, out: bytearray,
                                           off: int) -> bool:
        """True when *off* opens with a movabs whose imm is an OLD-BASE VA.

        Unrelocated x86 absolutes inside translated code (``movabs r11,
        0x4AD1CF40`` for x86 ``cmp dword [0x4ad1cf40],0``) are first-pass
        artifacts.  They look like prologues to the entry gate
        (movabs-after-pad) and keep stale rva_map entries (cmd 0x12E14 →
        0x35DE1) from being rematerialized — callers then execute the stale
        slot.  A real translated entry never loads an old-base VA.
        """
        if off < 0 or off + 10 > len(out):
            return False
        if out[off:off + 2] not in (
                b'\x49\xbb', b'\x48\xb8', b'\x48\xbf', b'\x48\xbe',
                b'\x48\xbb', b'\x48\xb9', b'\x48\xba',
                b'\x48\xbc', b'\x48\xbd'):
            return False
        imm = struct.unpack_from('<Q', out, off + 2)[0]
        ob = int(getattr(self, 'old_base', 0) or 0)
        if ob and ob <= imm < ob + 0x200000:
            return True
        return False

    @staticmethod
    def _pure_x86_ff35_leads_call(text_data: bytes, text_rva: int,
                                  func_rva: int) -> bool:
        """True when x86 ``push [global]`` at *func_rva* feeds the next ``call``."""
        func_off = func_rva - text_rva
        if func_off < 0 or func_off + 6 > len(text_data):
            return False
        if text_data[func_off:func_off + 2] != b'\xff\x35':
            return False
        for nxt in range(func_off + 6, min(func_off + 14, len(text_data) - 1)):
            b0 = text_data[nxt]
            if b0 == 0xE8:
                return True
            if b0 == 0xFF and text_data[nxt + 1] in (0x15, 0x25):
                return True
            if b0 in (0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x68, 0x6A):
                continue
            if b0 == 0xFF and text_data[nxt + 1] == 0x35:
                return False
            break
        return False

    def _pure_ff35_global_va_from_x86(self, text_data: bytes, text_rva: int,
                                      func_rva: int) -> Optional[int]:
        func_off = func_rva - text_rva
        if func_off < 0 or func_off + 6 > len(text_data):
            return None
        if text_data[func_off:func_off + 2] != b'\xff\x35':
            return None
        disp = struct.unpack_from('<I', text_data, func_off + 2)[0]
        return self._relocate_imm(disp)

    @staticmethod
    def _pure_x64_movabs_imm64(out: bytearray, off: int) -> Optional[int]:
        if off < 0 or off + 10 > len(out):
            return None
        if out[off:off + 2] in (b'\x49\xbb', b'\x48\xb8'):
            return struct.unpack_from('<Q', out, off + 2)[0]
        return None

    def _pure_x64_region_has_va(self, out: bytearray, off: int,
                                span: int, va: int) -> bool:
        va &= 0xFFFFFFFFFFFFFFFF
        end = min(len(out), off + span)
        for pos in range(max(0, off), end - 7):
            if out[pos:pos + 2] in (b'\x49\xbb', b'\x48\xb8'):
                imm = struct.unpack_from('<Q', out, pos + 2)[0]
                if imm == va:
                    return True
        return False

    def _pure_ff35_global_va_match(self, out: bytearray, off: int,
                                   func_rva: int, text_data: bytes,
                                   text_rva: int) -> bool:
        exp = self._pure_ff35_global_va_from_x86(text_data, text_rva, func_rva)
        if exp is None:
            return True
        imm = self._pure_x64_movabs_imm64(out, off)
        if imm is not None:
            return imm == exp
        return self._pure_x64_region_has_va(out, off, 40, exp)

    def _pure_infer_entry_from_interior_map(self, out: bytearray, func_rva: int,
                                            rva_map: Dict[int, int],
                                            text_data: bytes,
                                            text_rva: int) -> Optional[int]:
        """Recover a function entry when only interior byte maps survived heal skew."""
        samples: List[Tuple[int, int]] = []
        for dr in range(1, 64):
            xr = (func_rva + dr) & 0xFFFFFFFF
            mapped = rva_map.get(xr)
            if mapped is None:
                continue
            if self._pure_mapping_is_swallowed_slot(out, mapped):
                continue
            if self._pure_is_corrupt_x86_hybrid(out, mapped):
                continue
            samples.append((dr, mapped))
        if not samples:
            return None
        uniq = sorted(set(mapped for _, mapped in samples))
        median = uniq[len(uniq) // 2]
        cluster = {mapped for _, mapped in samples
                   if abs(mapped - median) <= 0x200}
        if not cluster:
            cluster = set(uniq)
        seed = min(cluster)
        for back in range(0, 56):
            pos = seed - back
            if pos < 0:
                break
            refined = self._refine_shim_target_off(out, func_rva, pos)
            for try_off in range(refined, max(-1, refined - 12), -1):
                if try_off < 0:
                    break
                if not self._pure_call_target_plausible(out, try_off):
                    continue
                if self._pure_mapped_entry_sane(
                        out, try_off, func_rva, text_data, text_rva):
                    return try_off
        return None

    @staticmethod
    def _pure_x86_global_store_va_from_head(x86: bytes) -> Optional[int]:
        """Abs32 from x86 global guard/store prologues (``and [abs]``, ``mov [abs]``)."""
        if len(x86) < 7:
            return None
        if x86[:3] == b'\x66\x83\x25':  # and word ptr [abs], imm8
            return struct.unpack_from('<I', x86, 3)[0]
        if x86[0] == 0x80 and x86[1] == 0x25:  # and byte ptr [abs], imm8
            return struct.unpack_from('<I', x86, 2)[0]
        if x86[0] == 0x83 and x86[1] == 0x25:  # and dword ptr [abs], imm8
            return struct.unpack_from('<I', x86, 2)[0]
        if x86[0] == 0xC6 and x86[1] == 0x05:  # mov byte ptr [abs], imm8
            return struct.unpack_from('<I', x86, 2)[0]
        if x86[:3] == b'\x66\xc7\x05':  # mov word ptr [abs], imm16
            return struct.unpack_from('<I', x86, 3)[0]
        if x86[0] == 0xC7 and x86[1] == 0x05:  # mov dword ptr [abs], imm32
            return struct.unpack_from('<I', x86, 2)[0]
        return None

    @staticmethod
    def _pure_x86_abs_load_va_from_head(x86: bytes) -> Optional[int]:
        """Abs32 from x86 ``mov r32, [imm32]`` / ``mov eax, [imm32]`` entry heads.

        Helpers like cmd ``0xB186`` (``mov ecx, [global]; cmp word ptr [ecx],0``)
        collapse onto unrelated align stubs when the generic prologue gate
        accepts ``push r13``.  The absolute VA is the unique fingerprint.
        """
        if len(x86) < 5:
            return None
        if x86[0] == 0xA1:  # mov eax, [imm32]
            return struct.unpack_from('<I', x86, 1)[0]
        # mov r32, [imm32] — opcode 8B /r with mod=00 rm=101 (disp32 only)
        if x86[0] == 0x8B and len(x86) >= 6 and (x86[1] & 0xC7) == 0x05:
            return struct.unpack_from('<I', x86, 2)[0]
        return None

    def _pure_fn_entry_x86_for_x64_off(self, rva_map: Dict[int, int],
                                     off: int,
                                     fn_rvas: Set[int]) -> Optional[int]:
        """x86 function entry that maps to x64 offset *off*, if any."""
        for r in fn_rvas:
            if rva_map.get(r) == off:
                return r
        return None

    def _pure_mapped_entry_sane(self, out: bytearray, off: int,
                                func_rva: int, text_data: bytes,
                                text_rva: int) -> bool:
        """True when *off* looks like a real translation of *func_rva* (uses x86 head)."""
        func_off = func_rva - text_rva
        if func_off < 0 or func_off + 8 > len(text_data):
            return self._x64_entry_prologue_ok(out, off)
        x86 = text_data[func_off:func_off + 16]
        x64 = out[off:off + 16]
        if os.environ.get('DBG_MMF') and func_rva == 0x12E14:
            print(f"[SANE-DBG] off=0x{off:X} func_off=0x{func_off:X} "
                  f"x86={x86[:10].hex()} x64={x64[:10].hex()} "
                  f"cls_x86={self._opcode_class(x86)} "
                  f"cls_x64={self._opcode_class(x64)}")
        if self._pure_is_corrupt_x86_hybrid(out, off):
            return False
        if self._pure_is_unrelocated_old_va_movabs(out, off):
            return False
        if x86[:2] == b'\xff\x35':  # push dword ptr [imm32]
            if x64[:3] == b'\x49\xbb':
                if not self._x64_entry_prologue_ok(out, off):
                    return False
                return self._pure_ff35_global_va_match(
                    out, off, func_rva, text_data, text_rva)
            if self._pure_x86_ff35_leads_call(text_data, text_rva, func_rva):
                if not self._x64_entry_prologue_ok(out, off):
                    return False
                if x64[:3] in (b'\x89\x44', b'\x89\x04', b'\x89\x54', b'\x66\xc7'):
                    return False
                exp = self._pure_ff35_global_va_from_x86(
                    text_data, text_rva, func_rva)
                if exp is not None and not self._pure_x64_region_has_va(
                        out, off, 48, exp):
                    return False
                return True
            if x64[:2] == b'\xff\x35':
                return (not self._pure_is_corrupt_x86_hybrid(out, off)
                        and self._pure_ff35_global_va_match(
                            out, off, func_rva, text_data, text_rva))
            return False
        if x86[:2] in (b'\xff\x15', b'\xff\x25'):  # call/jmp [imm32]
            if (x64[:2] in (b'\xff\x15', b'\xff\x25')
                    or x64[:2] == b'\x48\xb8' or x64[:3] == b'\x49\xbb'):
                return True
            # Frameless homes + align-wrapped IAT body (cmd GetVersion helper
            # ``0xacab``): the real call entry is the homes, not the movabs.
            home_n = len(_FRAMELESS_SHADOW_HOMES)
            if (off + home_n <= len(out)
                    and out[off:off + home_n] == _FRAMELESS_SHADOW_HOMES):
                body = off + home_n
                pro, _ = self._pure_align_stub_pro_epilogue()
                pl = len(pro)
                if (body + pl <= len(out)
                        and out[body:body + pl] == pro):
                    body += pl
                return self._pure_is_movabs_iat_call_body(out, body)
            return False
        if x86[0] == 0x68:  # push imm32
            if x64[0] == 0x68:
                return True
            if x64[:3] in (b'\x48\xc7\xc1', b'\x48\xc7\xc2', b'\x48\xc7\xc0',
                           b'\x49\xc7\xc1', b'\x49\xc7\xc2'):
                return True
            if x64[0] == 0x41 and x64[1] == 0xb9:
                return True
            return False
        if x86[:2] == b'\x8b\xec':  # mov ebp, esp → must be mov rbp, rsp
            return x64[:3] == b'\x48\x89\xe5' or (x64[:3] == b'\x55\x48\x89'
                                                   and x64[3:4] == b'\xe5')
        if x86[:2] == b'\x55\x8b':  # push ebp; mov ebp, esp → check first 4 bytes
            return x64[:4] == b'\x55\x48\x89' and x64[4:5] == b'\xe5'
        if x86[:2] in (b'\x83\xec', b'\x81\xec'):  # sub esp, imm (frameless entry)
            # Must translate to ``sub rsp, imm`` — never ``push rbp`` (different fn).
            return x64[:3] in (b'\x48\x83\xec', b'\x48\x81\xec')
        # Large-frame probe prologue ``mov eax,imm32; call __chkstk``.  The
        # translated opener is ``mov rax/eax,imm`` immediately followed by a
        # direct ``call`` to the one __chkstk body — an exact fingerprint.  This
        # explicit rule keeps a collapsed slot (which lands in the previous
        # function's tail) from sneaking through the generic prologue gate, so
        # the reconcile/resolve path re-snaps it onto the real entry.
        if (x86[:1] == b'\xb8' and len(x86) >= 10 and x86[5] == 0xE8):
            rel = int.from_bytes(x86[6:10], 'little', signed=True)
            if self._is_alloca_probe_rva((func_rva + 10 + rel) & 0xFFFFFFFF):
                imm = int.from_bytes(x86[1:5], 'little')
                simm = imm - 0x100000000 if imm >= 0x80000000 else imm
                if x64[:3] == b'\x48\xc7\xc0' and x64[3:7] == struct.pack('<i', simm):
                    c = off + 7
                elif x64[:1] == b'\xb8' and x64[1:5] == struct.pack('<I', imm):
                    c = off + 5
                else:
                    return False
                # Opener carrying the exact frame size + a ``call`` opcode is a
                # collision-resistant fingerprint.  Do not require the call's
                # rel32 to already resolve to __chkstk: at heal time it may still
                # be a deferred (rel=0) placeholder.
                return c + 5 <= len(out) and out[c] == 0xE8
        # Global guard/store prologue (``and [abs],imm`` / ``mov [abs],imm``)
        # translates to ``movabs r11/rax, <relocated VA>; <op> [reg], imm``.
        # The 8-byte VA immediately after the movabs is a unique fingerprint of
        # this exact entry, so accept it here — the generic prologue gate below
        # would otherwise reject the ``movabs r11`` opener and the VA-scan in
        # _pure_find_sane_entry_for_x86 would never snap scrambled call targets
        # back onto the real function body.  Purely additive: only a positive
        # match returns early; everything else falls through unchanged.
        # Frameless bodies may also open with Win64 shadow homes *before* the
        # movabs — that prefix is the real call entry (cmd setenv ``0x6581``).
        gva0 = self._pure_x86_global_store_va_from_head(x86)
        if gva0 is not None:
            exp0 = self._relocate_imm(gva0) & 0xFFFFFFFFFFFFFFFF
            body0 = off + self._pure_frameless_shadow_homes_len_at(out, off)
            if (body0 + 10 <= len(out)
                    and out[body0:body0 + 2] in (b'\x49\xbb', b'\x48\xb8')
                    and int.from_bytes(out[body0 + 2:body0 + 10], 'little')
                    == exp0):
                return True
            if (x64[:2] in (b'\x49\xbb', b'\x48\xb8') and len(x64) >= 10
                    and int.from_bytes(x64[2:10], 'little') == exp0
                    and self._pure_frameless_shadow_homes_len_before(out, off)
                    == 0):
                return True
        # Abs32 load prologue (``mov r32,[imm]`` / ``mov eax,[imm]``).  Must
        # open with movabs of the relocated VA — never an align stub / push.
        lva0 = self._pure_x86_abs_load_va_from_head(x86)
        if lva0 is not None:
            return self._pure_abs_load_entry_matches(out, off, x86, lva0)
        # Frameless function whose first instruction tests its first stack
        # argument, e.g. ``cmp dword[esp+4], imm``.  After translation arg1 lives
        # in rcx, so the head becomes ``cmp rcx/ecx, imm`` (no push/sub frame).
        # The generic gate below rejects such entries, so a scrambled rva_map
        # slot snaps onto the *previous* function's epilogue tail (the
        # 0x195d2 -> 0x2ff99 cmd case).  The preserved immediate is an exact,
        # collision-free fingerprint of the real entry.
        if x86[:4] == b'\x83\x7c\x24\x04' and len(x86) >= 5:   # cmp [esp+4], imm8
            ib = x86[4]
            # Prefer the REX.W form.  Bare ``83 F9 ib`` also matches the *tail*
            # of ``48 83 F9 ib`` (mid-instruction) — never accept that alone
            # unless Capstone agrees *off* is a real insn start.
            if x64[:4] == bytes((0x48, 0x83, 0xf9, ib)):
                return True
            if x64[:3] == bytes((0x83, 0xf9, ib)):
                if HAS_CAPSTONE:
                    md = Cs(CS_ARCH_X86, CS_MODE_64)
                    ins = list(md.disasm(bytes(out[off:off + 8]), off, count=1))
                    return bool(ins and ins[0].address == off
                                and ins[0].mnemonic == 'cmp')
                return False
            return False
        if x86[:4] == b'\x81\x7c\x24\x04' and len(x86) >= 8:   # cmp [esp+4], imm32
            im = x86[4:8]
            return ((x64[:3] == b'\x48\x81\xf9' and x64[3:7] == im)
                    or (x64[:2] == b'\x81\xf9' and x64[2:6] == im))
        # ── Universal: x86 CALL/JMP must map to x64 CALL/JMP ──
        # A CALL/JMP that maps to a non-control-transfer instruction
        # (e.g. a function prologue like sub/push) is a swallowed entry
        # whose real body was placed elsewhere by the pipeline.
        x86_cls = self._opcode_class(x86)
        x64_cls = self._opcode_class(x64)
        if x86_cls in ('CALL', 'JMP') and x64_cls not in ('CALL', 'JMP', None):
            return False
        if not self._x64_entry_prologue_ok(out, off):
            return False
        if x86[:3] == b'\x55\x8b\xec':
            if x64[:4] != b'\x55\x48\x89\xe5':
                return False
            if off + 8 <= len(out) and out[off + 4:off + 8] == b'\xff\xff\xff\xff':
                return False
            # Match stack reservation when x86 does sub esp, imm.
            if x86[3:5] == b'\x83\xec' and off + 10 <= len(out):
                x86_imm = x86[5]
                if out[off + 4:off + 7] == b'\x48\x83\xec':
                    x64_imm = out[off + 7]
                    if abs(x64_imm - (x86_imm + 4)) > 8:
                        return False
                elif out[off + 4:off + 7] == b'\x48\x81\xec':
                    pass
            return True
        if x86[:3] == b'\x53\x56\x57':
            # push ebx/esi/edi -> push rbx/rsi/rdi are byte-identical (low regs
            # need no REX), so a genuine entry MUST contain that exact push run
            # right at the start, optionally behind an align-stub lead
            # (push r13 = 41 55).  Crucially, reject a bare 48-prefixed opener
            # such as ``mov rsp,rbp`` (48 89 ec): that is the *previous*
            # function's epilogue tail, which rva_map occasionally points a few
            # bytes early into.  Accepting it (old behaviour allowed 0x48)
            # mis-snapped frameless 3-push entries onto the wrong function.
            x64b = bytes(x64)
            if x64b[:3] == b'\x53\x56\x57':
                return True
            if x64b[:2] == b'\x41\x55' and b'\x53\x56\x57' in x64b[:12]:
                return True
            return False
        if x86[0] in (0x5b, 0x5d, 0x5e, 0x5f, 0x58, 0x59, 0x5a, 0x5c):
            return x64[0] == x86[0] or (x64[0] == 0x41 and x64[1] == x86[0] + 0x48)
        if x86[0] in (0xC3, 0xC2):
            return x64[:len(x86)] == x86[:len(x64)]
        # A real (non-ret) x86 function must not map to a bare ``ret`` (C3) —
        # that means the entry was swallowed into a neighbouring epilogue tail
        # (e.g. call 0x6711 resolved into 0x670d's ``pop ebx; ret``). Reject so
        # heal/reconcile re-translates the real body.
        if x64[:1] in (b'\xc3', b'\xc2', b'\xc9', b'\x90', b'\xcc'):
            return False  # ret / ret imm16 / leave / nop / int3 — padding or epilogue
        if (x64[:2] == b'\x41\x5d'
                or x64[:3] in (b'\x4c\x89\xec', b'\x48\x89\xec')):
            return False  # pop r13 / mov rsp,r13 / mov rsp,rbp — epilogue tails
        # ── Universal first-byte opcode-class gate ──
        # When the x86 function's first instruction is a control-flow op
        # (CALL/E8, JMP/E9, Jcc/0F+7x, RET/C3) or a data-movement op
        # (PUSH/50-57+68+FF, POP/58-5F, LEA/8D), the x64 at the mapped
        # position MUST belong to the same opcode class.  A mismatch means
        # the entry was swallowed into a different function's body.
        # This catches the common case where ``call imm32`` entries land
        # on another function's ``sub rsp`` / ``push rbx`` prologue.
        x86_cls = self._opcode_class(x86[:3])
        x64b = x64[1:] if x64[0] == 0x48 else x64   # skip REX.W
        x64_cls = self._opcode_class(x64b[:4])
        if x86_cls is not None and x64_cls is not None and x86_cls != x64_cls:
            # Only reject when the x86 is clearly a control-flow op
            # (CALL or JMP) and the x64 is something entirely different.
            # PUSH/POP/LEA/MOV/ARITH mismatches can be legitimate
            # translator transformations (push→mov to reg, lea→arithmetic,
            # etc.) and rejecting them causes excessive re-translation.
            if x86_cls in ('CALL', 'JMP') and x64_cls not in ('CALL', 'JMP'):
                return False
        # Frameless stdcall/cdecl: mov ecx,[esp+4] (wcslen-style helpers).
        if x86[:4] == b'\x8b\x4c\x24\x04':
            if x64[:3] == b'\x48\x89' or x64[0] == 0x55:
                return False
            if x64[:3] == b'\x49\xbb' or x64[:2] == b'\x5b\xc3':
                return False
            if x64[:1] == b'\x5b':
                return False
            if x64[:2] in (b'\x85\xc9', b'\x48\x89', b'\x8b\xc9'):
                return True
            if x64[:4] in (b'\x85\xc9\x89\xc8', b'\x85\xc9\x8b\xc1'):
                return True
            if x64[:1] == b'\x90':
                return True
            return False
        if x64[0] == 0x66 and off + 3 < len(out) and out[off + 1] == 0xc7:
            return False  # mov word — interior store, not entry
        gva = self._pure_x86_global_store_va_from_head(x86)
        if gva is not None:
            exp = self._relocate_imm(gva) & 0xFFFFFFFFFFFFFFFF
            hl = self._pure_frameless_shadow_homes_len_at(out, off)
            body = off + hl
            if not self._pure_x64_region_has_va(out, off, 48 + hl, exp):
                return False
            # Reject landing on the post-home movabs — callers must hit homes.
            if (hl == 0
                    and self._pure_frameless_shadow_homes_len_before(out, off)):
                return False
            if body + 10 > len(out):
                return False
            if out[body:body + 2] not in (b'\x49\xbb', b'\x48\xb8'):
                return False
            if int.from_bytes(out[body + 2:body + 10], 'little') != exp:
                return False
            return True
        lva = self._pure_x86_abs_load_va_from_head(x86)
        if lva is not None:
            return self._pure_abs_load_entry_matches(out, off, x86, lva)
        return self._x64_entry_prologue_ok(out, off)

    def _pure_abs_load_entry_matches(self, out: bytearray, off: int,
                                     x86: bytes, lva: int) -> bool:
        """True when *off* is a real translation of an abs32-load prologue."""
        if off < 0 or off + 13 > len(out):
            return False
        exp = self._relocate_imm(lva) & 0xFFFFFFFFFFFFFFFF
        if out[off:off + 2] not in (b'\x49\xbb', b'\x48\xb8'):
            return False
        if struct.unpack_from('<Q', out, off + 2)[0] != exp:
            return False
        # movabs must be followed by a load through that register — not
        # ``push r13`` / unrelated code that merely shares a nearby VA.
        b0 = out[off + 10]
        if b0 in (0x41, 0x45, 0x49, 0x4D):
            if out[off + 11] != 0x8B:
                return False
        elif b0 != 0x8B:
            return False
        # Discriminate helpers that load the *same* global but then diverge
        # (cmd e846: ``cmp eax,0x3a4;…;ret`` vs GetACP switch: ``sub eax,0x3a4;
        # …;push locale``).  Without this, find_sane snaps every abs-load of
        # that VA onto the first translated twin and execute jumps into .data.
        x86_next = 6 if x86[0] == 0x8B else 5
        if len(x86) > x86_next:
            nxt = x86[x86_next]
            body = bytes(out[off + 10:off + 48])  # after movabs
            # ``cmp eax/r32, imm`` (0x3D / 0x81 /F8 / 0x83 /F8)
            if nxt in (0x3D, 0x81, 0x83):
                has_cmp = (
                    b'\x3d' in body
                    or b'\x48\x3d' in body
                    or b'\x81\xf8' in body
                    or b'\x48\x81\xf8' in body
                    or b'\x83\xf8' in body
                    or b'\x48\x83\xf8' in body
                    or b'\x39' in body[:20]  # cmp r/m, r
                    or b'\x3b' in body[:20]  # cmp r, r/m
                )
                # Reject the sub-imm dispatch idiom used by the GetACP twin.
                has_sub_imm = (
                    b'\x48\x2d' in body[:24]
                    or (len(body) > 0 and body[0] == 0x2D)
                )
                if has_sub_imm and not has_cmp:
                    return False
                if nxt == 0x3D and not has_cmp:
                    return False
            # ``sub eax, imm32`` (0x2D) — require a matching sub, not cmp-only.
            if nxt == 0x2D:
                has_sub = (
                    b'\x48\x2d' in body[:24]
                    or (len(body) > 0 and body[0] == 0x2D)
                    or b'\x48\x83\xe8' in body[:24]  # sub rax, imm8
                    or b'\x83\xe8' in body[:24]
                )
                if not has_sub:
                    return False
        # When x86 continues with ``cmp word ptr [reg], 0``, demand a matching
        # multi-block shape (cmp + jcc) and reject the tiny ``setne al; ret``
        # helpers that load the same global (cmd 0xB186 vs 0x33BF5 stub).
        x86_next = 6 if x86[0] == 0x8B else 5
        if (len(x86) >= x86_next + 4
                and x86[x86_next:x86_next + 4] == b'\x66\x83\x39\x00'):
            window = bytes(out[off:off + 96])
            if b'\x0f\x95\xc0' in window[:64]:  # setne al
                return False
            has_cmp = (
                b'\x66\x83\x39\x00' in window
                or b'\x66\x83\x38\x00' in window
                or b'\x66\x39\x01' in window
                or b'\x66\x39\x00' in window
                or b'\x66\x39\xc8' in window
                or b'\x66\x39\xc1' in window
            )
            has_jcc = False
            for i in range(min(80, len(window) - 2)):
                if window[i] == 0x75 or window[i:i + 2] in (b'\x0f\x85', b'\x0f\x84'):
                    has_jcc = True
                    break
            if not (has_cmp and has_jcc):
                return False
        return True

    @staticmethod
    def _pure_mapping_is_swallowed_slot(out: bytearray, off: int) -> bool:
        """True when *off* points at an epilogue/thunk slot, not real translated entry."""
        if off < 0 or off >= len(out):
            return True
        head = out[off:off + 4]
        if head[:2] == b'\x41\x5d':  # pop r13 (+ jmp)
            return True
        if head[:3] == b'\x4c\x89\xec':  # mov rsp, r13
            return True
        if head[:2] == b'\x66\xc7':  # mov word — mid-function store
            return True
        if head[0] == 0xe9:  # jmp (epilogue skip)
            return True
        # Bare / near-bare epilogue: pop*; ret  or  xor eax,eax; pop*; ret
        if head[0] in (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0xC3):
            return True
        if head[0] == 0xC2:
            return True
        if head[:2] == b'\x31\xc0':  # xor eax,eax — common success-return before pops
            return True
        if head[:3] == b'\x48\x31\xc0':  # xor rax,rax
            return True
        # ``mov eax, e*; pop+; [leave]; ret`` — prior function epilogue head
        # (cmd ``fbe4`` collapsed onto ``mov eax,ebx; pop rsi; pop rbx; leave; ret``).
        if (head[0] == 0x89 and head[1] in (0xD8, 0xF0, 0xF8, 0xC8, 0xD0)
                and off + 6 <= len(out)):
            j = off + 2
            pops = 0
            while (j < len(out) and j < off + 10
                   and out[j] in (0x58, 0x59, 0x5A, 0x5B,
                                  0x5C, 0x5D, 0x5E, 0x5F)):
                pops += 1
                j += 1
            if pops:
                if j < len(out) and out[j] == 0xC9:
                    j += 1
                if j < len(out) and out[j] in (0xC3, 0xC2):
                    return True
        # Epilogue global-store tail before adjacent fn (movabs r11; mov [r11], rax).
        if head[:2] == b'\x49\xbb' and off + 12 <= len(out):
            tail = out[off + 10:off + 13]
            if tail[:1] == b'\x5b' or tail[:2] == b'\x5b\xc3':
                return True
        if HealingMixin._pure_is_corrupt_x86_hybrid(out, off):
            return True
        if off + 2 <= len(out) and out[off:off + 2] == b'\x48\xb8':
            for back in range(1, min(24, off) + 1):
                if out[off - back:off - back + 4] == b'\x48\x83\xe4\xf0':
                    return True
        return False

    def _pure_heal_entry_rvas(self, out: bytearray,
                              rva_map: Dict[int, int],
                              text_data: bytes, text_rva: int) -> Set[int]:
        """RVAs needing re-translation: E8 call targets (+ swallowed fn entries) failing sanity."""
        entries: Set[int] = set()
        cf = self._x86_cf
        if cf:
            for tgt in cf.call_targets:
                if tgt in cf.interior_labels or tgt in cf.epilogue_labels:
                    continue
                off = rva_map.get(tgt)
                if off is None:
                    entries.add(tgt)
                    continue
                if not self._pure_mapped_entry_sane(
                        out, off, tgt, text_data, text_rva):
                    entries.add(tgt)
        for func in self._fn_entry_rvas or ():
            off = rva_map.get(func)
            if off is None:
                entries.add(func)
                continue
            if not self._pure_mapping_is_swallowed_slot(out, off):
                continue
            if not self._pure_mapped_entry_sane(
                    out, off, func, text_data, text_rva):
                entries.add(func)
        return entries

    def _pure_translation_fingerprint(self, chunk_out: bytes) -> bytes:
        """Long enough prefix to avoid aliasing different EBP-frame helpers."""
        return chunk_out[:min(32, len(chunk_out))]

    def _pure_find_existing_translation(self, out: bytearray, head: bytes,
                                        func_rva: int, text_data: bytes,
                                        text_rva: int) -> Optional[int]:
        """Locate an already-emitted copy of *head* that matches the x86 entry."""
        sig = self._pure_translation_fingerprint(head)
        if len(sig) < 16:
            return None
        pos = 0
        while True:
            j = out.find(sig, pos)
            if j < 0:
                return None
            if self._pure_mapped_entry_sane(out, j, func_rva, text_data, text_rva):
                return j
            pos = j + 1

    def _pure_global_store_infer_ok(self, out: bytearray, off: int,
                                    func_rva: int, text_data: bytes,
                                    text_rva: int) -> bool:
        """Reject interior-map guesses for ``and/mov [abs]`` prologue functions."""
        func_off = func_rva - text_rva
        if func_off < 0 or func_off + 16 > len(text_data):
            return True
        gva = self._pure_x86_global_store_va_from_head(
            text_data[func_off:func_off + 16])
        if gva is None:
            return True
        exp = self._relocate_imm(gva)
        return self._pure_x64_region_has_va(out, off, 48, exp)

    def _pure_force_fresh_translation(self, text_data: bytes, text_rva: int,
                                      func_rva: int) -> bool:
        """True when heal must append a new blob, not reuse a fingerprint match."""
        func_off = func_rva - text_rva
        if func_off < 0 or func_off + 16 > len(text_data):
            return False
        x86 = text_data[func_off:func_off + 16]
        if x86[:4] == b'\x8b\x4c\x24\x04':  # frameless wcslen-style
            return True
        return self._pure_x86_global_store_va_from_head(x86) is not None

    def _pure_accept_inferred_entry(self, out: bytearray, off: int,
                                    func_rva: int, text_data: bytes,
                                    text_rva: int) -> bool:
        if not self._pure_mapped_entry_sane(
                out, off, func_rva, text_data, text_rva):
            return False
        if not self._pure_global_store_infer_ok(
                out, off, func_rva, text_data, text_rva):
            return False
        return True

    def _pure_call_e8_sites_near_anchor(self, out: bytearray,
                                        anchor: int,
                                        span: int = 96) -> List[int]:
        """E8 call sites near an x86 rva_map anchor (includes align-stub calls)."""
        lo = max(0, anchor)
        hi = min(len(out) - 5, anchor + span)
        sites: List[int] = []
        seen: Set[int] = set()
        for i in range(lo, hi):
            if out[i] != 0xE8 or i in seen:
                continue
            if not self._pure_branch_site_ok(out, i):
                continue
            seen.add(i)
            sites.append(i)
        pro, epi = self._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        scan_lo = max(0, lo - 16)
        scan_hi = min(hi + 40, len(out) - pl - el - 5)
        for scan in range(scan_lo, scan_hi):
            if out[scan:scan + pl] != pro:
                continue
            j = scan + pl
            if j in seen or out[j] != 0xE8:
                continue
            if out[j + 5:j + 5 + el] != epi:
                continue
            if not self._pure_branch_site_ok(out, j):
                continue
            seen.add(j)
            sites.append(j)
        return sites

    def _pure_heal_swallowed_entries(self, out: bytearray, rva_map: Dict[int, int],
                                     text_data: bytes, text_rva: int,
                                     entry_rvas: Set[int],
                                     deferred_branches: Optional[List[Tuple[int, int, str]]] = None) -> int:
        """Re-translate function entries that mega-chunks mapped to non-code slots."""
        if not self._cmd_no_hacks:
            return 0
        if deferred_branches is None:
            deferred_branches = []
        healed = 0
        relink: Dict[int, int] = {}
        _dbg = self._dbg_rva
        for func_rva in sorted(entry_rvas):
            off = rva_map.get(func_rva)
            if func_rva == _dbg:
                snap_dbg = self._pure_find_sane_entry_for_x86(
                    out, func_rva, rva_map, text_data, text_rva)
                chk_dbg = self._pure_chkstk_prologue_entry_for_x86(
                    out, func_rva, text_data, text_rva, rva_map)
                print(f"        [DBG heal {func_rva:#x}] off={off!r} "
                      f"sane={self._pure_mapped_entry_sane(out, off, func_rva, text_data, text_rva) if off is not None else None} "
                      f"snap={snap_dbg!r} chk={chk_dbg!r} "
                      f"ck={self._pure_chkstk_entry_off(out)!r}")
            if (off is not None
                    and self._pure_mapped_entry_sane(
                        out, off, func_rva, text_data, text_rva)):
                continue
            inferred = self._pure_infer_entry_from_interior_map(
                out, func_rva, rva_map, text_data, text_rva)
            if (inferred is not None
                    and not self._pure_accept_inferred_entry(
                        out, inferred, func_rva, text_data, text_rva)):
                inferred = None
            if inferred is not None:
                if off != inferred:
                    old_off = off
                    rva_map[func_rva] = inferred
                    if old_off is not None and old_off != inferred:
                        relink[old_off] = inferred
                    healed += 1
                continue
            # Prefer repointing onto an already-emitted *correct* translation
            # before appending a fresh blob.  A large-frame ``mov eax,imm; call
            # __chkstk`` entry whose only fault is a collapsed rva_map slot
            # already has a valid body elsewhere in ``out``; re-translating it
            # would emit a duplicate, and for SEH functions the duplicate's
            # entry gets mis-anchored onto its leading scope table (the
            # 0xA4E7 switch-parser case).  Universal: the snap is gated by the
            # same prologue sanity check, so it only fires on a real match.
            snap = self._pure_find_sane_entry_for_x86(
                out, func_rva, rva_map, text_data, text_rva)
            if (snap is not None and 0 <= snap < len(out)
                    and self._pure_mapped_entry_sane(
                        out, snap, func_rva, text_data, text_rva)):
                if off != snap:
                    rva_map[func_rva] = snap
                    if off is not None and off != snap:
                        relink[off] = snap
                    healed += 1
                continue
            old_off = off
            func_bytes = self._extract_function_bytes(
                func_rva, text_data, text_rva)
            if len(func_bytes) < 4:
                continue
            chunk_out, chunk_map = self._translate_function(
                func_rva, func_bytes, False, 0, chunk_base=0,
                section_rva=text_rva, global_rva_map=rva_map,
                deferred_branches=deferred_branches)
            if not chunk_out:
                continue
            existing = self._pure_find_existing_translation(
                out, chunk_out, func_rva, text_data, text_rva)
            if existing is not None:
                base = existing
            else:
                base = len(out)
                out += chunk_out
                out += b'\x90' * ((4 - len(out) % 4) % 4)
                self._note_code_span(base, len(chunk_out))
            rva_map[func_rva] = base
            # Use chunk_map's precise offset for the function entry
            # (materialized epilogue prepended before the body).
            func_entry_va = self.old_base + func_rva
            func_body_off = chunk_map.get(func_entry_va, 0)
            _dbg_tgt = (int(os.environ['DBG_TGT'], 16)
                        if os.environ.get('DBG_TGT') else 0)
            if _dbg_tgt and func_rva <= _dbg_tgt < func_rva + len(func_bytes):
                print(f'[MMF] chunk x86 0x{func_rva:X}+0x{len(func_bytes):X} '
                      f'base=0x{base:X} entry=0x{base + func_body_off:X}',
                      flush=True)
            if func_body_off:
                # Only skip the prefix when it is a materialized epilogue
                # (contains ``ret``).  Injected register-save prologues
                # (push rsi / push rdi / xor reg,reg) must NOT be skipped
                # — otherwise the epilogue's ``pop rdi; pop rsi; ret`` pops
                # values that were never pushed, corrupting the stack.
                prefix = chunk_out[:func_body_off]
                if b'\xc3' in prefix or b'\xc2' in prefix:
                    rva_map[func_rva] = base + func_body_off
                # else: keep rva_map[func_rva] = base so injected prologue runs
            for old_va, rel in chunk_map.items():
                old_r = old_va - self.old_base
                if old_r == func_rva:
                    continue
                if old_r not in rva_map:
                    rva_map[old_r] = base + rel
                elif self._pure_off_in_zero_hole(out, rva_map[old_r]):
                    rva_map[old_r] = base + rel
            if old_off is not None and old_off != base:
                relink[old_off] = base
            healed += 1
        if relink:
            healed += self._relink_branch_targets(out, relink)
        return healed

    def _pure_repair_call_targets(self, out: bytearray, rva_map: Dict[int, int],
                                  text_data: bytes, text_rva: int) -> int:
        """Re-resolve E8 rel32 using x86 source + healed rva_map (pure mode)."""
        if not self._cmd_no_hacks or not HAS_CAPSTONE:
            return 0
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        fixed = 0

        def _old_rva_for_out_off(off: int) -> Optional[int]:
            candidates = [(mapped, rva) for rva, mapped in rva_map.items()
                          if mapped <= off]
            if not candidates:
                return None
            return max(candidates, key=lambda x: x[0])[1]

        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._pure_branch_site_ok(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            old_rva = _old_rva_for_out_off(i)
            if old_rva is None:
                continue
            off_in_sec = old_rva - text_rva
            if off_in_sec < 0 or off_in_sec >= len(text_data):
                continue
            start = max(0, off_in_sec - 8)
            found_target = None
            for insn in md32.disasm(text_data[start:off_in_sec + 8],
                                    self.old_base + text_rva + start, count=16):
                if insn.address - self.old_base != old_rva:
                    continue
                if insn.mnemonic != 'call':
                    break
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    found_target = (insn.operands[0].imm - self.old_base) & 0xFFFFFFFF
                break
            if found_target is None:
                if (0 <= tgt < len(out)
                        and not self._x64_entry_prologue_ok(out, tgt)):
                    entry = self._find_enclosing_function_entry(out, tgt, rva_map)
                    if entry is not None and entry != tgt:
                        struct.pack_into('<i', out, i + 1, entry - (i + 5))
                        fixed += 1
                continue
            new_tgt = self._pure_resolve_x86_call_target(
                out, found_target, rva_map, text_data, text_rva)
            if new_tgt is None:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            if i + 5 + rel == new_tgt:
                continue
            struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
            fixed += 1
        return fixed

    @staticmethod
    def _pure_off_in_movabs_imm(out: bytearray, i: int) -> bool:
        """True when byte *i* lies inside a 64-bit ``movabs`` immediate (not a real opcode).

        A stray ``0xE8`` (or ``0xE9``/``0x0F 8x``) byte that is really part of a
        ``movabs r64, imm64`` operand must never be treated as a branch opcode —
        rewriting it shreds the loaded address (e.g. an IAT slot VA).
        """
        for back in range(2, 10):
            p = i - back
            if p < 0:
                break
            if out[p] in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= out[p + 1] <= 0xBF:
                # immediate occupies p+2 .. p+9
                if p + 2 <= i <= p + 9:
                    return True
        return False

    @staticmethod
    def _pure_off_in_mov_r64_imm32(out: bytearray, i: int) -> bool:
        """True when *i* lies inside ``mov r64, imm32`` (``48 C7 C0+r imm32``).

        cmd ``db0b`` (``push 0x50; call alloc``) emits ``mov rcx, 0x50`` at the
        thunk entry; rva_map sometimes tips onto the imm32 (``50 00 00 00``),
        so callers execute ``push rax; add [rax],al`` and return garbage that
        is later used as a heap object pointer (univ159 read @ 0xEC458D4C).
        """
        for back in range(3, 7):
            p = i - back
            if p < 0:
                break
            if (out[p] in (0x48, 0x49)
                    and out[p + 1] == 0xC7
                    and (out[p + 2] & 0xF8) == 0xC0
                    and p + 3 <= i <= p + 6):
                return True
        return False

    @staticmethod
    def _pure_off_in_imm_operand(out: bytearray, i: int) -> bool:
        """True when *i* is inside movabs imm64 or mov-r64-imm32."""
        return (HealingMixin._pure_off_in_movabs_imm(out, i)
                or HealingMixin._pure_off_in_mov_r64_imm32(out, i))

    def _pure_insn_start_set(self, out: bytearray) -> Optional[Set[int]]:
        """Offsets in *out* that begin a real x64 instruction (pure mode).

        Built by linear disassembly seeded from every mapped function/instruction
        offset. Used to reject ``0xE8``/``0xE9`` bytes that are actually operand
        bytes (movabs immediates, ``[rbp-0x18]`` disp8 = 0xE8, disp32 tails, …)
        so branch-repair passes never shred a non-branch instruction.

        Returns ``None`` when capstone is unavailable (callers fall back).
        Cached and invalidated whenever ``len(out)`` changes (rel32 edits keep
        instruction boundaries, so the cache stays valid across repair passes).
        """
        if not HAS_CAPSTONE:
            return None
        cache = getattr(self, '_pure_insn_starts_cache', None)
        if cache is not None and cache[0] == len(out):
            return cache[1]
        starts: Set[int] = set()
        marked = bytearray(len(out))
        code = bytes(out)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        seeds = {0}
        seeds.update(v for v in self.rva_map.values() if 0 <= v < len(out))
        for s in sorted(seeds):
            if s < 0 or s >= len(out) or marked[s]:
                continue
            for ins in md.disasm(code[s:], s):
                a = ins.address
                if a >= len(out) or marked[a]:
                    break
                # Reject "instructions" that are just zero padding (``00 00``
                # decodes as ``add [rax], al`` — technically valid but always
                # crashes when RAX == 0).  Real translated code never starts
                # with NUL bytes, so this only filters inter-function gaps.
                if code[a] == 0x00 and a not in seeds:
                    break
                marked[a] = 1
                starts.add(a)
                # Never seed/accept an offset that falls inside a movabs
                # immediate — Capstone can desync onto the ``0xE8`` inside a
                # relocated data VA and treat it as a real CALL.
                if (a + 10 <= len(out)
                        and code[a] in (0x48, 0x49, 0x4C, 0x4D)
                        and 0xB8 <= code[a + 1] <= 0xBF):
                    for _bi in range(a + 2, a + 10):
                        marked[_bi] = 1
        self._pure_insn_starts_cache = (len(out), starts)
        return starts

    def _pure_branch_site_ok(self, out: bytearray, i: int) -> bool:
        """True when *i* is a real branch instruction start, not an operand byte.

        Movabs-immediate rejection is unconditional: Capstone linear sweeps can
        desync and mark an ``0xE8`` *inside* a relocated data VA as an insn
        start (cmd ``movabs rcx, 0x8005e8a0`` → shredded to ``0x1599de8a0``).
        """
        if self._pure_off_in_imm_operand(out, i):
            return False
        starts = self._pure_insn_start_set(out)
        if starts is None:
            return True
        return i in starts

    def _pure_repair_calls_from_x86_source(self, out: bytearray,
                                           rva_map: Dict[int, int],
                                           text_data: bytes,
                                           text_rva: int) -> int:
        """Fix x64 E8 sites anchored at each x86 ``call rel32`` (handles prologue skew)."""
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        paired_sites: Set[int] = set()
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (text_rva + off + 5 + rel) & 0xFFFFFFFF
            anchor = rva_map.get(x86_rva)
            if anchor is None:
                continue
            if anchor < 0 or anchor >= len(out):
                continue
            hint = rva_map.get(tgt_x86)
            new_tgt = None
            if hint is not None:
                hint = self._refine_shim_target_off(out, tgt_x86, hint)
                if (self._pure_call_target_plausible(out, hint)
                        and self._pure_mapped_entry_sane(
                            out, hint, tgt_x86, text_data, text_rva)):
                    new_tgt = hint
            if new_tgt is None:
                new_tgt = self._pure_resolve_x86_call_target(
                    out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                continue
            sites = [s for s in self._pure_call_e8_sites_near_anchor(out, anchor)
                     if s not in paired_sites]
            if not sites:
                continue
            for i in sorted(sites, key=lambda s: abs(s - anchor)):
                cur_rel = struct.unpack_from('<i', out, i + 1)[0]
                cur_idx = i + 5 + cur_rel
                if cur_idx == new_tgt:
                    paired_sites.add(i)
                    break
                # Only repair *clearly broken* targets here. A "wrong but
                # plausible" target (another function's valid entry) must NOT be
                # rewritten by this window heuristic — anchors are skewed in
                # mega-chunks, so a later x86 call can otherwise grab an earlier
                # call's E8 site. Order-based correlation handles those cases.
                bad_tgt = (
                    self._pure_mapping_is_swallowed_slot(out, cur_idx)
                    or self._pure_is_corrupt_x86_hybrid(out, cur_idx)
                    or not self._pure_call_target_plausible(out, cur_idx)
                    or not self._pure_mapped_entry_sane(
                        out, cur_idx, tgt_x86, text_data, text_rva))
                if not bad_tgt and cur_idx != new_tgt:
                    if self._pure_mapped_entry_sane(
                            out, new_tgt, tgt_x86, text_data, text_rva):
                        cur_fn = self._pure_fn_entry_x86_for_x64_off(
                            rva_map, cur_idx, self._fn_entry_rvas or set())
                        if cur_fn != tgt_x86:
                            bad_tgt = True
                if not bad_tgt:
                    continue
                struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
                paired_sites.add(i)
                fixed += 1
                break
        return fixed

    def _pure_reanchor_data_movabs_from_x86_pushes(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Re-sync movabs loads/stores with x86 absolute data-pointer insns.

        E8 bytes inside movabs immediates (e.g. 0x8004E874 contains 0xE8) must
        never be treated as call opcodes, but when they are the rel32 write can
        corrupt a *nearby* movabs. Re-anchor from the x86 source via rva_map.
        """
        if not self._cmd_no_hacks or not rva_map:
            return 0
        fixed = 0
        n = len(text_data)
        # Sorted translated-block starts: a reanchor scan for one x86 insn must
        # never cross into the *next* translated block, or it clobbers a
        # neighbour's movabs (cmd 0xC67E ``cmp [0x1cf64]`` was overwritten by the
        # 0xC6A2 ``push 0x1fb00`` whose value went into call-arg marshalling and
        # left no movabs of its own).
        import bisect as _bisect
        tr = int(text_rva or 0)

        def _map_to_off(v: int) -> Optional[int]:
            """Live rva_map stores blob offsets; DUMP_RVA_MAP stores final RVAs."""
            v = int(v)
            if 0 <= v < len(out):
                return v
            if tr and v >= tr and (v - tr) < len(out):
                return v - tr
            return None

        # Block starts: live blob offs, with dumped-RVA values folded in.
        _blk_starts = sorted({
            o for v in rva_map.values()
            for o in (_map_to_off(int(v)),)
            if o is not None
        })

        def _scan_hi(anchor: int, default_hi: int) -> int:
            # Cap the scan at the next translated block start, but only when that
            # leaves room for a full ``movabs`` (10 bytes) belonging to this insn;
            # coarse/interleaved rva_map entries closer than that are not trusted
            # (cmd 0x14E9B ``push 0x1d28`` mapped inside the prior call-align
            # stub with the next snap only 7 bytes ahead — must skip noise).
            # Also skip rva_map tips that land *inside* a movabs (cmd AutoRun
            # ``push 0x1890`` at 0xA400: neighbour 0xA3DA mapped to mid-imm of
            # the prior word-store movabs → hi cut before the push's own movabs
            # left rdx=0x5e868 empty .data).
            def _inside_movabs(off: int) -> bool:
                for back in range(1, 10):
                    p = off - back
                    if p < 0:
                        break
                    if (out[p] in (0x48, 0x49, 0x4C, 0x4D)
                            and 0xB8 <= out[p + 1] <= 0xBF
                            and p < off < p + 10):
                        return True
                return False

            j = _bisect.bisect_right(_blk_starts, anchor)
            while j < len(_blk_starts):
                nxt = _blk_starts[j]
                if nxt >= default_hi:
                    break
                if anchor + 14 <= nxt and not _inside_movabs(nxt):
                    return nxt
                j += 1
            return default_hi

        # All correctly-relocated non-exec abs VAs in this image.  Collapsed
        # rva_map anchors make several x86 abs ops share one scan window; a
        # later op must not overwrite an earlier op's already-correct movabs
        # (cmd 0xADAD: ``and word [fbe2],0`` then ``mov [21820],eax`` — the
        # store reanchor stole the and's movabs → More? / empty parse buffer).
        _foreign_ok: Set[int] = set()
        if self._old_to_new_section:
            _img_end = self.old_base + self.pe.image_size
            for _off in range(max(0, n - 5)):
                _b0 = text_data[_off]
                _imm: Optional[int] = None
                if _b0 == 0x68:
                    _imm = struct.unpack_from('<I', text_data, _off + 1)[0]
                elif _b0 == 0xC6 and _off + 7 <= n and text_data[_off + 1] == 0x05:
                    _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
                elif _b0 == 0xC7 and _off + 10 <= n and text_data[_off + 1] == 0x05:
                    _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
                elif _b0 in (0xA0, 0xA1, 0xA2, 0xA3) and _off + 5 <= n:
                    _imm = struct.unpack_from('<I', text_data, _off + 1)[0]
                elif (_off + 6 <= n and text_data[_off:_off + 2] == b'\x66\xa3'):
                    # mov word ptr [moffs16], ax
                    _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
                elif (_off + 7 <= n and text_data[_off] == 0x66
                        and text_data[_off + 1] == 0x89
                        and (text_data[_off + 2] & 0xC7) == 0x05):
                    # mov word ptr [abs], r16
                    _imm = struct.unpack_from('<I', text_data, _off + 3)[0]
                elif _b0 in (0x89, 0x8B) and _off + 6 <= n and (
                        text_data[_off + 1] & 0xC7) == 0x05:
                    _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
                elif (_b0 in (0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39)
                        and _off + 6 <= n
                        and (text_data[_off + 1] & 0xC7) == 0x05):
                    _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
                elif _b0 in (0x80, 0x83) and _off + 7 <= n and text_data[_off + 1] == 0x25:
                    _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
                elif _off + 8 <= n and text_data[_off:_off + 3] == b'\x66\x83\x25':
                    _imm = struct.unpack_from('<I', text_data, _off + 3)[0]
                elif 0xB8 <= _b0 <= 0xBF and _off + 5 <= n:
                    _imm = struct.unpack_from('<I', text_data, _off + 1)[0]
                if _imm is None or not (self.old_base <= _imm < _img_end):
                    continue
                _or = _imm - self.old_base
                _sec = self.pe.section_for_rva(_or)
                if not _sec or (_sec['flags'] & 0x20000000):
                    continue
                _foreign_ok.add(
                    self._relocate_imm(_imm, 0, 0) & 0xFFFFFFFFFFFFFFFF)

        def _try_fix(x86_off: int, imm32: int) -> None:
            nonlocal fixed
            if not (self.old_base <= imm32 < self.old_base + self.pe.image_size):
                return
            old_rva = imm32 - self.old_base
            sec = self.pe.section_for_rva(old_rva)
            if not sec:
                return
            code_va = bool(sec['flags'] & 0x20000000)
            if code_va:
                # Non-embedded code VAs (``push <fn>``) are owned by
                # ``_pure_resync_code_pointer_movabs``.  Only reanchor
                # embedded .text *data* through this path.
                embedded = getattr(self, '_embedded_text_refs', set())
                in_embed = old_rva in embedded
                if not in_embed:
                    for start, end in self._merge_embedded_ref_spans(
                            embedded, text_data, text_rva):
                        if start <= old_rva < end:
                            in_embed = True
                            break
                if not in_embed:
                    # Still reclaim ``push``/``mov r32,imm`` of .text when the
                    # movabs tip is a foreign .data VA (AutoRun 0x1890 after
                    # purge/miss).  Function-pointer resync handles the rest.
                    if not (len(text_data) > x86_off and (
                            text_data[x86_off] == 0x68
                            or 0xB8 <= text_data[x86_off] <= 0xBF)):
                        return
            exp = self._relocate_imm(imm32, 0, 0) & 0xFFFFFFFFFFFFFFFF
            # Embedded / .text string pushes: prefer a landing whose bytes
            # match the x86 source (rva_map can sit a few bytes early inside
            # a rematerialized KERNEL32.DLL|AutoRun blob).
            if code_va and text_rva <= old_rva < text_rva + n:
                src_off = old_rva - text_rva
                chunk = text_data[src_off:src_off + 4]
                if len(chunk) == 4:
                    nb = int(self.new_base or 0)
                    text_new = int(self._old_to_new_section.get(text_rva, text_rva))
                    def _blob_of(va: int) -> Optional[int]:
                        rel = (va - nb - text_new) & 0xFFFFFFFFFFFFFFFF
                        if rel < len(out):
                            return int(rel)
                        return None
                    bo = _blob_of(exp)
                    if bo is None or out[bo:bo + 4] != chunk:
                        raw = rva_map.get(old_rva)
                        base = _map_to_off(int(raw)) if raw is not None else None
                        hit = None
                        if base is not None:
                            for delta in range(-16, 64):
                                p = base + delta
                                if 0 <= p + 4 <= len(out) and bytes(out[p:p + 4]) == chunk:
                                    hit = p
                                    break
                        if hit is None:
                            # Fall back: search rematerialized orphan blobs.
                            for blob_start, blob_size in getattr(
                                    self, '_orphan_blob_out_ranges', []):
                                for p in range(blob_start,
                                               blob_start + max(blob_size - 3, 0)):
                                    if bytes(out[p:p + 4]) == chunk:
                                        hit = p
                                        break
                                if hit is not None:
                                    break
                        if hit is not None:
                            exp = (nb + text_new + hit) & 0xFFFFFFFFFFFFFFFF
            x86_rva = (text_rva + x86_off) & 0xFFFFFFFF
            raw_anchor = rva_map.get(x86_rva)
            if raw_anchor is None:
                return
            anchor = _map_to_off(int(raw_anchor))
            if anchor is None:
                return
            hi = _scan_hi(anchor, min(anchor + 128, len(out) - 10))
            xb = text_data[x86_off:x86_off + 8]

            def _consumer_ok(scan: int) -> Optional[bool]:
                """Whether bytes after movabs match this x86 abs op's emitter.

                ``True`` = definite match (safe to rewrite even if ``got`` is
                another insn's correct VA — the value was stolen).  ``False`` =
                definite mismatch.  ``None`` = no fingerprint (fall through).
                """
                after = scan + 10
                if after + 4 > len(out):
                    return False
                if len(xb) >= 3 and xb[:3] == b'\x66\x83\x25':
                    # and word ptr [r11], imm8
                    return out[after:after + 3] == b'\x66\x41\x83'
                if len(xb) >= 2 and xb[0] == 0x83 and xb[1] == 0x25:
                    return out[after:after + 2] == b'\x41\x83'
                if len(xb) >= 2 and xb[0] == 0x80 and xb[1] == 0x25:
                    return out[after:after + 2] == b'\x41\x80'
                if len(xb) >= 2 and xb[:2] == b'\x66\xa3':
                    # mov word ptr [abs], ax → movabs; mov word [r11], ax
                    return (out[after:after + 3] == b'\x66\x41\x89'
                            or out[after:after + 2] == b'\x66\x89')
                if (len(xb) >= 3 and xb[0] == 0x66 and xb[1] == 0x89
                        and (xb[2] & 0xC7) == 0x05):
                    # mov word ptr [abs], r16
                    return (out[after:after + 3] == b'\x66\x41\x89'
                            or out[after:after + 2] == b'\x66\x89')
                if len(xb) >= 1 and xb[0] == 0xA3:
                    # mov dword ptr [r11], r32
                    return out[after] == 0x41 and out[after + 1] == 0x89
                if len(xb) >= 2 and xb[0] == 0x89 and (xb[1] & 0xC7) == 0x05:
                    return out[after] == 0x41 and out[after + 1] == 0x89
                # ALU r/m32,r32 with abs disp (``or [abs],esi`` → ``or [r11],esi``)
                if (len(xb) >= 2 and xb[0] in (
                        0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39)
                        and (xb[1] & 0xC7) == 0x05):
                    return out[after] == 0x41 and out[after + 1] == xb[0]
                if len(xb) >= 2 and xb[0] in (0xC6, 0xC7) and xb[1] == 0x05:
                    return out[after] in (0x41, 0xC6, 0xC7)
                return None

            # Consumer fingerprints that uniquely identify the x86 op class
            # (``and word`` vs ``mov [abs],eax``).  Non-unique classes (plain
            # A3 stores) must not rewrite a neighbour's already-correct VA.
            # ``or [abs],r32`` is unique enough to reclaim a stolen movabs
            # (cmd 0xB287 left as rsrc VA 0x8b820).  Do NOT treat ``cmp [abs]``
            # (0x39) as unique — many sites share ``41 39`` and reclaim steals
            # (univ93 smashed 0x22844 / getchar cmps → More?).
            # Word abs stores are unique enough (few sites; collapsed anchors
            # otherwise leave ``0x5e868`` on ``mov [c7e8],ax`` / AutoRun push).
            _unique_consumer = (
                (len(xb) >= 3 and xb[:3] == b'\x66\x83\x25')
                or (len(xb) >= 2 and xb[0] in (0x80, 0x83) and xb[1] == 0x25)
                or (len(xb) >= 2 and xb[0] == 0x09 and (xb[1] & 0xC7) == 0x05)
                or (len(xb) >= 2 and xb[:2] == b'\x66\xa3')
                or (len(xb) >= 3 and xb[0] == 0x66 and xb[1] == 0x89
                    and (xb[2] & 0xC7) == 0x05)
            )

            def _apply(scan: int) -> bool:
                nonlocal fixed
                got = struct.unpack_from('<Q', out, scan + 2)[0]
                if got == exp:
                    return True
                if self._imm_is_pe64_idata_cell(got) and got != exp:
                    return False
                if (not code_va and sec and not (sec['flags'] & 0x20000000)
                        and self._pure_old_iat_for_imm(got)
                        and self._imm_is_pe64_idata_cell(got)):
                    return False
                struct.pack_into('<Q', out, scan + 2, exp)
                fixed += 1
                return True

            def _is_abs_mem_consumer(scan: int) -> bool:
                """True if movabs feeds abs ``mov/alu [r11]`` or ``mov r,[r11]``."""
                after = scan + 10
                if after + 3 > len(out):
                    return False
                # word store/load/and via r11
                if out[after:after + 3] in (
                        b'\x66\x41\x89', b'\x66\x41\x83', b'\x66\x41\x8b',
                        b'\x66\x41\x39', b'\x66\x41\x3b'):
                    return True
                if out[after:after + 2] in (
                        b'\x66\x89', b'\x66\x8b',
                        b'\x41\x89', b'\x41\x8b',
                        b'\x41\x83', b'\x41\x80',
                        b'\x41\x39', b'\x41\x3b'):
                    return True
                if out[after] == 0x41 and out[after + 1] in (
                        0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39):
                    return True
                return False

            # Pass 1: consumer-matched movabs (repairs stolen immediates).
            for scan in range(anchor, hi):
                if out[scan] not in (0x48, 0x49, 0x4C, 0x4D):
                    continue
                if not (0xB8 <= out[scan + 1] <= 0xBF):
                    continue
                if self._movabs_is_abs_load_pair(out, scan):
                    continue
                if _consumer_ok(scan) is not True:
                    continue
                got = struct.unpack_from('<Q', out, scan + 2)[0]
                if (not _unique_consumer and not code_va
                        and got in _foreign_ok and got != exp):
                    continue
                if _apply(scan):
                    return

            # Pass 2: first free movabs that is not another abs insn's VA.
            for scan in range(anchor, hi):
                if out[scan] not in (0x48, 0x49, 0x4C, 0x4D):
                    continue
                if not (0xB8 <= out[scan + 1] <= 0xBF):
                    continue
                # A movabs immediately consumed by ``mov reg,[reg]`` is an
                # absolute *load* (cmd 0x14E92 ``mov eax,[0x264c0]``), owned by
                # _try_fix_abs_load.  A push/store (0x68/0xC7/…) anchored just
                # before it must NOT hijack that load's movabs — skip it and keep
                # scanning for this site's own movabs (cmd 0x14E9B push 0x1d28).
                if self._movabs_is_abs_load_pair(out, scan):
                    continue
                if _consumer_ok(scan) is False:
                    continue
                # Non-store sites must not rewrite a neighbouring abs-store
                # movabs (collapsed rva_map windows around AutoRun / c7e8).
                if not _unique_consumer and _is_abs_mem_consumer(scan):
                    continue
                got = struct.unpack_from('<Q', out, scan + 2)[0]
                if got == exp:
                    break
                # Already-correct relocate of a *different* abs insn — keep
                # scanning (collapsed rva_map shared window).
                # Exception: .text string pushes whose movabs landed on a real
                # .data VA (foreign_ok) must reclaim — AutoRun ``push 0x1890``
                # was left as ``0x5e868`` after word-store tips collapsed.
                if got in _foreign_ok and got != exp:
                    if code_va and not _is_abs_mem_consumer(scan):
                        if _apply(scan):
                            break
                    continue
                if _apply(scan):
                    break

        def _try_fix_abs_load(x86_off: int, imm32: int) -> None:
            """Match movabs used for ``mov accum,[abs]`` (A0/A1/A2), not push/C7 slots."""
            nonlocal fixed
            if not (self.old_base <= imm32 < self.old_base + self.pe.image_size):
                return
            old_rva = imm32 - self.old_base
            sec = self.pe.section_for_rva(old_rva)
            if not sec or (sec['flags'] & 0x20000000):
                return
            x86_rva = (text_rva + x86_off) & 0xFFFFFFFF
            raw_anchor = rva_map.get(x86_rva)
            if raw_anchor is None:
                return
            exp = self._relocate_imm(imm32, 0, 0) & 0xFFFFFFFFFFFFFFFF
            # Prefer live blob-off; if that misses, also try dumped-RVA form
            # (DUMP_RVA_MAP stores final RVAs = text_new + blob_off).
            anchors: List[int] = []
            a0 = _map_to_off(int(raw_anchor))
            if a0 is not None:
                anchors.append(a0)
            if tr and int(raw_anchor) >= tr:
                a1 = int(raw_anchor) - tr
                if 0 <= a1 < len(out) and a1 not in anchors:
                    anchors.append(a1)
            for anchor in anchors:
                if anchor < 0 or anchor >= len(out) - 14:
                    continue
                hi = _scan_hi(anchor, min(anchor + 128, len(out) - 14))
                for scan in range(anchor, hi):
                    if not self._movabs_is_abs_load_pair(out, scan):
                        continue
                    got = struct.unpack_from('<Q', out, scan + 2)[0]
                    if got == exp:
                        return
                    if self._imm_is_pe64_idata_cell(got) and got != exp:
                        break
                    struct.pack_into('<Q', out, scan + 2, exp)
                    fixed += 1
                    return

        for off in range(n - 5):
            b0 = text_data[off]
            if b0 == 0x68:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 1)[0])
            elif b0 == 0xC6 and off + 7 <= n and text_data[off + 1] == 0x05:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 == 0xC7 and off + 10 <= n and text_data[off + 1] == 0x05:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 == 0x88 and off + 6 <= n and text_data[off + 1] == 0x1D:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 == 0x38 and off + 6 <= n and text_data[off + 1] == 0x1D:
                # cmp byte ptr [abs], bl  (cmd CRT locale/codepage init)
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 in (0xA0, 0xA1, 0xA2) and off + 5 <= n:
                # A0/A1/A2: accum,[abs] — match movabs+load pair (cmd 0x14E92).
                _try_fix_abs_load(off, struct.unpack_from('<I', text_data, off + 1)[0])
            elif b0 == 0xA3 and off + 5 <= n:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 1)[0])
            elif off + 6 <= n and text_data[off:off + 2] == b'\x66\xa3':
                # mov word ptr [moffs16], ax (cmd AutoRun locale path)
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif (off + 7 <= n and b0 == 0x66 and text_data[off + 1] == 0x89
                    and (text_data[off + 2] & 0xC7) == 0x05):
                # mov word ptr [abs], r16
                _try_fix(off, struct.unpack_from('<I', text_data, off + 3)[0])
            elif b0 in (0x89, 0x8B) and off + 6 <= n:
                modrm = text_data[off + 1]
                if (modrm & 0xC7) == 0x05:
                    _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif (b0 in (0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39)
                    and off + 6 <= n
                    and (text_data[off + 1] & 0xC7) == 0x05):
                # add/or/adc/sbb/and/sub/xor/cmp dword [abs], r32
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 == 0x80 and off + 7 <= n and text_data[off + 1] == 0x25:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 == 0x83 and off + 7 <= n and text_data[off + 1] == 0x25:
                _try_fix(off, struct.unpack_from('<I', text_data, off + 2)[0])
            elif off + 8 <= n and text_data[off:off + 3] == b'\x66\x83\x25':
                _try_fix(off, struct.unpack_from('<I', text_data, off + 3)[0])
            elif 0xB8 <= b0 <= 0xBF and off + 5 <= n:
                # mov r32, imm32 — absolute data address materialization
                # (cmd 0x19578 ``mov edx, 0x4ad22867``).
                _try_fix(off, struct.unpack_from('<I', text_data, off + 1)[0])
        return fixed

    def _pure_fix_abs_load_twin_code_movabs(
            self, out: bytearray,
            text_data: bytes, text_rva: int,
            rva_map: Optional[Dict[int, int]] = None) -> int:
        """Un-hijack abs-load movabs that shares a code VA with the next push.

        x86 ``mov eax,[data]; test; jcc; push <fn>; call eax`` sometimes emits
        both PE64 ``movabs`` with the *code* entry VA.  The load then reads
        machine code as a function pointer (cmd 0x14E92 → call 0x200009).

        Shape (no precise load-site map required)::

            movabs rN, X          ; X wrongly in .text
            mov    eax, [rN]
            test   eax, eax
            jcc    …
            movabs rM, X          ; same X — the push <fn>
            …
            call   r64
        """
        if not self._cmd_no_hacks:
            return 0
        pe = self.pe
        if pe is None or not self._old_to_new_section:
            return 0
        nb = int(self.new_base or 0)
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))
        text_end = text_new + len(out)
        rva_map = rva_map or getattr(self, 'rva_map', None) or {}
        fixed = 0
        n = len(text_data)

        def _code_va(code_imm: int) -> Optional[int]:
            c_rva = (code_imm - self.old_base) & 0xFFFFFFFF
            if self._final_rva and c_rva in self._final_rva:
                return (nb + self._final_rva[c_rva]) & 0xFFFFFFFFFFFFFFFF
            raw = rva_map.get(c_rva)
            if raw is None:
                return self._relocate_imm(code_imm, 0, 0) & 0xFFFFFFFFFFFFFFFF
            rv = int(raw)
            # Live map: blob offset.  Without _final_rva, assume blob.
            if 0 <= rv < len(out):
                return (nb + text_new + rv) & 0xFFFFFFFFFFFFFFFF
            if rv >= text_new and (rv - text_new) < len(out):
                return (nb + rv) & 0xFFFFFFFFFFFFFFFF
            return (nb + rv) & 0xFFFFFFFFFFFFFFFF

        # x86 sites: A1 [data] … push imm … call eax/edx/esi/edi
        sites: List[Tuple[int, int]] = []  # (data_imm, code_va_exp)
        for off in range(n - 10):
            if text_data[off] != 0xA1:
                continue
            data_imm = struct.unpack_from('<I', text_data, off + 1)[0]
            if not (self.old_base <= data_imm < self.old_base + pe.image_size):
                continue
            d_rva = data_imm - self.old_base
            dsec = pe.section_for_rva(d_rva)
            if not dsec or (dsec['flags'] & 0x20000000):
                continue
            window = text_data[off + 5:off + 5 + 0x18]
            pi = window.find(b'\x68')
            if pi < 0 or pi + 5 > len(window):
                continue
            code_imm = struct.unpack_from('<I', window, pi + 1)[0]
            if not (self.old_base <= code_imm < self.old_base + pe.image_size):
                continue
            c_rva = code_imm - self.old_base
            csec = pe.section_for_rva(c_rva)
            if not csec or not (csec['flags'] & 0x20000000):
                continue
            after = window[pi + 5:pi + 5 + 8]
            if not any(after[j:j + 2] in (b'\xff\xd0', b'\xff\xd2', b'\xff\xd6',
                                            b'\xff\xd7', b'\xff\xd3')
                       for j in range(len(after) - 1)):
                continue
            cva = _code_va(code_imm)
            if cva is not None:
                sites.append((data_imm, int(cva)))

        if not sites:
            return 0

        # Also accept dumped-RVA form of code VA (nb + final_rva without text_new).
        site_by_x: Dict[int, int] = {}
        for data_imm, cva in sites:
            site_by_x[cva] = data_imm
            # dumped map may store final RVA directly as movabs imm - nb
            if cva >= nb:
                site_by_x[cva] = data_imm
                rva_only = cva - nb
                site_by_x[(nb + rva_only) & 0xFFFFFFFFFFFFFFFF] = data_imm

        i = 0
        while i + 40 < len(out):
            if out[i] not in (0x48, 0x49, 0x4C, 0x4D):
                i += 1
                continue
            if not (0xB8 <= out[i + 1] <= 0xBF):
                i += 1
                continue
            if not self._movabs_is_abs_load_pair(out, i):
                i += 1
                continue
            x = struct.unpack_from('<Q', out, i + 2)[0]
            if not (nb + text_new <= x < nb + text_end):
                i += 1
                continue
            twin = None
            for j in range(i + 12, min(i + 48, len(out) - 12)):
                if out[j] not in (0x48, 0x49, 0x4C, 0x4D):
                    continue
                if not (0xB8 <= out[j + 1] <= 0xBF):
                    continue
                if self._movabs_is_abs_load_pair(out, j):
                    continue
                if struct.unpack_from('<Q', out, j + 2)[0] != x:
                    continue
                for k in range(j + 10, min(j + 28, len(out) - 1)):
                    if out[k] == 0xFF and 0xD0 <= out[k + 1] <= 0xD7:
                        twin = j
                        break
                if twin is not None:
                    break
            if twin is None:
                i += 1
                continue
            data_imm = site_by_x.get(int(x))
            if data_imm is None:
                # Match when X equals dumped final VA for any site code target.
                for di, cva in sites:
                    if int(cva) == int(x) or abs(int(cva) - int(x)) <= 0x20:
                        data_imm = di
                        break
                    # live blob→VA vs dumped RVA→VA
                    if (int(x) - nb) == (int(cva) - nb):
                        data_imm = di
                        break
            if data_imm is None:
                i += 1
                continue
            data_exp = self._relocate_imm(data_imm, 0, 0) & 0xFFFFFFFFFFFFFFFF
            if data_exp == x:
                i += 10
                continue
            struct.pack_into('<Q', out, i + 2, data_exp)
            fixed += 1
            i += 10
        return fixed

    def _pure_fix_shifted_data_movabs(
            self, out: bytearray, text_data: bytes, text_rva: int) -> int:
        """Correct data ``movabs`` immediates shifted by section-layout drift.

        Post-repair CALL/Jcc sweeps sometimes rewrite an ``0xE8`` byte that is
        really inside a relocated VA (e.g. ``0x8006E866`` contains ``E8``), or
        an earlier headroom plan leaves ``exp+N*0x1000`` stale immediates while
        ``.data`` lands at the compact RVA.  Collapsed ``rva_map`` anchors make
        the site-local re-anchor miss.

        Only rewrite a movabs when:
        - its value is *not* already a known-good relocated data VA, and
        - it does *not* fall inside the correct PE64 data/rsrc section span, and
        - it matches ``new_base + aligned_base + section_offset`` for a known
          x86 absolute data operand (same section offset, wrong section base).
        """
        if not self._cmd_no_hacks or not self._old_to_new_section:
            return 0
        pe = self.pe
        if pe is None:
            return 0
        old_base = self.old_base
        new_base = self.new_base
        img_end = old_base + pe.image_size

        # old_sec_vaddr → (new_sec_vaddr, sec_size, {offset: exp_va})
        sec_info: Dict[int, Tuple[int, int, Dict[int, int]]] = {}
        for old_sec, new_sec in self._old_to_new_section.items():
            osec = pe.section_for_rva(old_sec)
            if not osec or (osec['flags'] & 0x20000000):
                continue
            sz = max(osec.get('vsize', 0), osec.get('raw_sz', 0), 1)
            sec_info[old_sec] = (new_sec, sz, {})

        def _note(imm32: int) -> None:
            if not (old_base <= imm32 < img_end):
                return
            old_rva = imm32 - old_base
            sec = pe.section_for_rva(old_rva)
            if not sec or (sec['flags'] & 0x20000000):
                return
            old_sec = sec['vaddr']
            info = sec_info.get(old_sec)
            if info is None:
                return
            new_sec, sz, offsets = info
            off = old_rva - old_sec
            exp = (new_base + new_sec + off) & 0xFFFFFFFFFFFFFFFF
            offsets[off] = exp

        n = len(text_data)
        for off in range(max(0, n - 5)):
            b0 = text_data[off]
            if b0 == 0x68:
                _note(struct.unpack_from('<I', text_data, off + 1)[0])
            elif b0 == 0xC6 and off + 7 <= n and text_data[off + 1] == 0x05:
                _note(struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 == 0xC7 and off + 10 <= n and text_data[off + 1] == 0x05:
                _note(struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 in (0x88, 0x38) and off + 6 <= n and text_data[off + 1] == 0x1D:
                _note(struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 in (0xA0, 0xA1, 0xA2, 0xA3) and off + 5 <= n:
                _note(struct.unpack_from('<I', text_data, off + 1)[0])
            elif off + 6 <= n and text_data[off:off + 2] == b'\x66\xa3':
                _note(struct.unpack_from('<I', text_data, off + 2)[0])
            elif (off + 7 <= n and b0 == 0x66 and text_data[off + 1] == 0x89
                    and (text_data[off + 2] & 0xC7) == 0x05):
                _note(struct.unpack_from('<I', text_data, off + 3)[0])
            elif b0 in (0x89, 0x8B) and off + 6 <= n:
                if (text_data[off + 1] & 0xC7) == 0x05:
                    _note(struct.unpack_from('<I', text_data, off + 2)[0])
            elif b0 in (0x80, 0x83) and off + 7 <= n and text_data[off + 1] == 0x25:
                _note(struct.unpack_from('<I', text_data, off + 2)[0])
            elif off + 8 <= n and text_data[off:off + 3] == b'\x66\x83\x25':
                _note(struct.unpack_from('<I', text_data, off + 3)[0])
            elif 0xB8 <= b0 <= 0xBF and off + 5 <= n:
                _note(struct.unpack_from('<I', text_data, off + 1)[0])

        expected: Set[int] = set()
        known_wrong_bases: Set[int] = set()
        legit_bases: Set[int] = set()
        old_sec_bases = list(sec_info.keys())
        for old_sec, (new_sec, _sz, offsets) in sec_info.items():
            expected.update(offsets.values())
            legit_bases.add(new_sec)
            # Drift lands on CODE_GROWTH_HEADROOM (64 KiB) multiples, not
            # every page — page stride false-matches .idata cells.  Both
            # over-shift (``data + N*64K``) and under-shift (``data - N*64K``,
            # e.g. cmd store to 0x4E820 instead of 0x6E820) occur.
            for k in range(1, 32):
                known_wrong_bases.add(new_sec + k * 0x10000)
                known_wrong_bases.add(new_sec - k * 0x10000)
            # Forgot section-relative offset: ``new_sec + old_rva`` instead of
            # ``new_sec + (old_rva - old_sec)`` (cmd 0x19558 store → 0x7a866
            # in read-only .rsrc instead of 0x5e866 in .data).
            for other_old in old_sec_bases:
                known_wrong_bases.add(new_sec + other_old)
        idata_rva = int(getattr(self, '_idata_rva', 0) or 0)
        idata_hi = idata_rva
        if idata_rva:
            legit_bases.add(idata_rva)
            # Prefer the real .idata blob length; a fixed 0x20000 window
            # swallows post-.idata drift VAs (cmd 0x9e869) and blocks fixes.
            blob = getattr(self, '_idata_blob', None) or b''
            idata_hi = idata_rva + max(len(blob), 0x2000)
        # Real section bases must never count as "drift" — otherwise a
        # legitimate .rsrc/.idata movabs matches ``.data + N*page`` and gets
        # rewritten to a .data VA (cmd IAT cells at 0x954xx → 0x684xx).
        known_wrong_bases -= legit_bases
        if not expected:
            return 0

        fixed = 0
        i = 0
        while i < len(out) - 10:
            if (out[i] in (0x48, 0x49, 0x4C, 0x4D)
                    and 0xB8 <= out[i + 1] <= 0xBF):
                got = struct.unpack_from('<Q', out, i + 2)[0]
                if got not in expected:
                    exp = None
                    # Unrelocated x86 image VA still sitting in a movabs.
                    if old_base <= got < img_end:
                        old_rva = int(got - old_base)
                        sec = pe.section_for_rva(old_rva)
                        if sec and not (sec['flags'] & 0x20000000):
                            info = sec_info.get(sec['vaddr'])
                            if info:
                                exp = info[2].get(old_rva - sec['vaddr'])
                    # Wrong section base (headroom/shift drift), same section offset.
                    if exp is None and got >= new_base:
                        gr = int(got - new_base)
                        best = None
                        best_dist = None
                        for old_sec, (new_sec, sz, offsets) in sec_info.items():
                            in_span = new_sec <= gr < new_sec + sz
                            if in_span:
                                # Inside the real section but not an expected
                                # abs VA — often ``new_sec + (old_rva & 0xFFFF)``
                                # (cmd CS slot 0x5a87c vs correct 0x5e87c).
                                # Require *got* itself be the truncated encoding
                                # so a correct ``new_sec+off`` is never rewritten
                                # via a spurious ``(old_sec+other_off)&0xFFFF`` hit.
                                off_got = gr - new_sec
                                for off, cand in offsets.items():
                                    old_rva_full = old_sec + off
                                    trunc = old_rva_full & 0xFFFF
                                    if (off_got == trunc and off_got != off
                                            and gr == new_sec + trunc):
                                        if best is None or 0 < (best_dist or 1):
                                            best, best_dist = cand, 0
                                continue
                            for off, cand in offsets.items():
                                if gr < off:
                                    continue
                                # Exact ``new_sec + old_rva`` (forgot subtract).
                                if gr == (new_sec + old_sec + off):
                                    if best is None or 0 < (best_dist or 1):
                                        best, best_dist = cand, 0
                                    continue
                                base_guess = gr - off
                                if base_guess not in known_wrong_bases:
                                    continue
                                dist = abs(base_guess - new_sec)
                                if dist > 0x100000:
                                    continue
                                if best is None or dist < best_dist:
                                    best, best_dist = cand, dist
                        # Never rewrite a genuine .idata cell VA.
                        if (best is not None and idata_rva
                                and idata_rva <= gr < idata_hi):
                            best = None
                        exp = best
                    # E8-as-CALL shred: a CALL heal rewrote the rel32 that
                    # overlaps a movabs imm whose 2nd byte is 0xE8 (e.g.
                    # ``0x8005e860`` → ``0x8006a860`` when the ``E8`` and the
                    # following dword were replaced by a 5-byte CALL).  Recover
                    # when low byte matches (imm[0] rarely clobbered) and the
                    # expected VA still contains ``E8`` at byte 1.
                    if exp is None and got not in expected:
                        in_new = new_base <= got < new_base + pe.image_size
                        in_old = old_base <= got < img_end
                        if not in_old:
                            got16 = got & 0xFFFF
                            matches = [
                                c for c in expected
                                if (c & 0xFFFF) == got16
                                and ((c >> 8) & 0xFF) == 0xE8
                                and c != got
                            ]
                            if len(matches) == 1:
                                exp = matches[0]
                            elif not matches:
                                # Low-16 diverged (E8 opcode byte overwritten).
                                # Fall back: same low 8 bits, expected had E8,
                                # and the corrupted VA is within 128 KiB.
                                soft = [
                                    c for c in expected
                                    if (c & 0xFF) == (got & 0xFF)
                                    and ((c >> 8) & 0xFF) == 0xE8
                                    and c != got
                                    and abs(int(c) - int(got)) < 0x20000
                                ]
                                if len(soft) == 1:
                                    exp = soft[0]
                    if exp is not None and exp != got:
                        struct.pack_into('<Q', out, i + 2, exp)
                        fixed += 1
            i += 1
        if fixed:
            self._pure_insn_starts_cache = None
        return fixed

    def _pure_resync_code_pointer_movabs(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Force ``movabs`` of code VAs onto reconciled function entries.

        ``push <fn>`` / ``mov r32, <fn>`` (atexit, SetUnhandledExceptionFilter,
        …) are relocated once during translate.  If ``rva_map[fn]`` later snaps
        off a swallowed epilogue onto the real body, the already-emitted
        ``movabs`` still holds the epilogue VA and the registered callback
        returns into garbage (cmd 0x9E65 → xor/pop/ret instead of ``cmp rcx``).
        """
        if not self._cmd_no_hacks or not rva_map:
            return 0
        pe = self.pe
        if pe is None:
            return 0
        old_base = self.old_base
        new_base = self.new_base
        text_end = text_rva + len(text_data)
        text_new = self._old_to_new_section.get(text_rva, text_rva)
        # wrong VA → correct VA
        patch: Dict[int, int] = {}

        def _blob_off(v: int) -> int:
            if 0 <= v < len(out):
                return v
            if v >= text_new and (v - text_new) < len(out):
                return v - text_new
            return v

        def _note_code_va(imm32: int) -> None:
            if not (old_base <= imm32 < old_base + pe.image_size):
                return
            old_rva = imm32 - old_base
            if not (text_rva <= old_rva < text_end):
                return
            raw = rva_map.get(old_rva)
            if raw is None:
                return
            off = _blob_off(raw)
            if not (0 <= off < len(out)):
                return
            if self._final_rva and old_rva in self._final_rva:
                exp = (new_base + self._final_rva[old_rva]) & 0xFFFFFFFFFFFFFFFF
            else:
                exp = (new_base + text_new + off) & 0xFFFFFFFFFFFFFFFF
            patch[imm32] = exp
            patch[new_base + old_rva] = exp
            # Stale landings: any VA in the 32 bytes *before* the real entry
            # (previous function's epilogue / nop pad) that the floor-map or
            # pre-reconcile slot produced.
            for back in range(1, 32):
                stale_off = off - back
                if stale_off < 0:
                    break
                stale = (new_base + text_new + stale_off) & 0xFFFFFFFFFFFFFFFF
                if stale != exp:
                    patch[stale] = exp

        n = len(text_data)
        for i in range(max(0, n - 5)):
            b0 = text_data[i]
            if b0 == 0x68:
                _note_code_va(struct.unpack_from('<I', text_data, i + 1)[0])
            elif 0xB8 <= b0 <= 0xBF:
                _note_code_va(struct.unpack_from('<I', text_data, i + 1)[0])

        if not patch:
            return 0
        good = {v for v in patch.values()}
        for va in good:
            patch.pop(va, None)

        fixed = 0
        i = 0
        while i < len(out) - 10:
            if (out[i] in (0x48, 0x49, 0x4C, 0x4D)
                    and 0xB8 <= out[i + 1] <= 0xBF):
                got = struct.unpack_from('<Q', out, i + 2)[0]
                if got not in good:
                    exp = patch.get(got)
                    if exp is not None and exp != got:
                        struct.pack_into('<Q', out, i + 2, exp)
                        fixed += 1
            i += 1
        if fixed:
            self._pure_insn_starts_cache = None
        return fixed

    def _pure_purge_mismapped_embedded_refs(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int, refs: Set[int]) -> int:
        """Drop rva_map slots where translated code replaced embedded .text data."""
        purged = 0
        for old_rva in sorted(refs):
            off = old_rva - text_rva
            if off < 0 or off >= len(text_data):
                continue
            size = _embedded_text_blob_size(text_data, off)
            probe = min(size, 8)
            x86_chunk = text_data[off:off + probe]
            mismatch = False
            anchor = rva_map.get(old_rva)
            if anchor is None:
                for r in range(old_rva, old_rva + size):
                    a = rva_map.get(r)
                    if a is None:
                        continue
                    rel = r - old_rva
                    if a >= len(out) or out[a] != text_data[off + rel]:
                        mismatch = True
                        break
            elif anchor + probe > len(out):
                mismatch = True
            else:
                mismatch = bytes(out[anchor:anchor + probe]) != x86_chunk
            if not mismatch:
                continue
            for r in range(old_rva, old_rva + size):
                if rva_map.pop(r, None) is not None:
                    purged += 1
        return purged

    def _pure_finalize_embedded_text_data(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int, refs: Set[int]) -> int:
        """Append x86 .text wchar/ascii literals after all layout heals.

        Function-driven translation maps these RVAs onto emitted code bytes.
        Purge + orphan materialize must run last so ``_final_rva`` and movabs
        re-anchors resolve ``push imm32`` locale tables (``.OCP``, ``Sun``, …).

        MSVC EH3 scope-table RVAs are excluded from remapping — they must stay
        under ``_force_rematerialize_scope_tables`` or SEH pushes land in UTF-16.
        """
        if not refs:
            return 0
        scope_rvas: Set[int] = set()
        if self.pe is not None:
            for s, sz in _scope_table_spans(text_data, text_rva, self.pe):
                scope_rvas.update(range(s, s + sz))
        added = 0
        for start_rva, end_rva in self._merge_embedded_ref_spans(
                refs, text_data, text_rva):
            off = start_rva - text_rva
            size = end_rva - start_rva
            raw = text_data[off:off + size]
            for r in range(start_rva, end_rva):
                if r in scope_rvas:
                    continue
                rva_map.pop(r, None)
            base: Optional[int] = None
            for blob_start, blob_size in self._orphan_blob_out_ranges:
                if (blob_start + blob_size <= len(out)
                        and blob_size >= size
                        and bytes(out[blob_start:blob_start + size]) == raw):
                    base = blob_start
                    break
            if base is None:
                pad = (4 - len(out) % 4) % 4
                if pad:
                    out += b'\x00' * pad
                base = len(out)
                out += raw
                pad2 = (4 - len(out) % 4) % 4
                if pad2:
                    out += b'\x00' * pad2
                self._orphan_blob_out_ranges.append((base, size))
                added += 1
            for i in range(size):
                r = start_rva + i
                if r in scope_rvas:
                    continue
                rva_map[r] = base + i
        self._embedded_text_refs = set(refs)
        return added

    def _pure_is_align_stub_call_site(self, out: bytearray, site: int) -> bool:
        """True when *site* is the ``call`` inside a Win64 stack-align stub."""
        pro, epi = self._pure_align_stub_pro_epilogue()
        if site < len(pro) or site + 5 + len(epi) > len(out):
            return False
        if out[site - len(pro):site] != pro:
            return False
        return out[site + 5:site + 5 + len(epi)] == epi

    def _pure_correlate_call_targets(self, out: bytearray,
                                     rva_map: Dict[int, int],
                                     text_data: bytes, text_rva: int) -> int:
        """Re-point direct calls by pairing x86/x64 call sequences per function.

        Mega-chunk translations sometimes collapse an x86 instruction's rva_map
        entry onto a neighbour, so a window/anchor based repair can target a
        *different* (but still valid-looking) function entry. Because call order
        is preserved within a function, the N-th real x64 ``E8`` corresponds to
        the N-th x86 direct ``call``. When the counts match we can authoritatively
        set every target from the x86 source. Conservative: skips any function
        whose call counts differ (ambiguous), so it never mis-pairs.
        """
        if not self._cmd_no_hacks or not HAS_CAPSTONE:
            return 0
        starts = self._pure_insn_start_set(out)
        if starts is None:
            return 0
        fn_rvas = sorted(r for r in (self._fn_entry_rvas or set()) if r in rva_map)
        if not fn_rvas:
            return 0
        x64_entries = sorted(set(rva_map[r] for r in fn_rvas))
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        fixed = 0
        for i, fn in enumerate(fn_rvas):
            foff = fn - text_rva
            if foff < 0 or foff >= len(text_data):
                continue
            x86_end = fn_rvas[i + 1] if i + 1 < len(fn_rvas) else None
            end_off = (x86_end - text_rva) if x86_end is not None else len(text_data)
            end_off = min(end_off, len(text_data))
            if end_off <= foff:
                continue
            x86_calls: List[int] = []
            for ins in md32.disasm(bytes(text_data[foff:end_off]),
                                   self.old_base + fn):
                if (ins.mnemonic == 'call' and ins.operands
                        and ins.operands[0].type == X86_OP_IMM):
                    t = (ins.operands[0].imm - self.old_base) & 0xFFFFFFFF
                    if self._is_alloca_probe_rva(t):
                        continue
                    x86_calls.append(t)
            if not x86_calls:
                continue
            x64_off = rva_map[fn]
            x64_end = len(out)
            for e in x64_entries:
                if e > x64_off:
                    x64_end = e
                    break
            e8_sites: List[int] = []
            k = x64_off
            while k < x64_end - 5:
                if out[k] == 0xE8 and self._pure_branch_site_ok(out, k):
                    if not self._pure_is_align_stub_call_site(out, k):
                        e8_sites.append(k)
                k += 1
            # Pair the N-th x86 direct call with the N-th x64 E8 site. Only
            # rewrite a target when the current one is *provably wrong* for that
            # x86 call AND the wanted one is *provably right* — this tolerates
            # basic-block reordering (mismatched tails are simply skipped) and
            # never mis-pairs reordered calls.
            for site, t86 in zip(e8_sites, x86_calls):
                newt = rva_map.get(t86)
                if newt is not None:
                    newt = self._refine_shim_target_off(out, t86, newt)
                    if not self._pure_mapped_entry_sane(
                            out, newt, t86, text_data, text_rva):
                        resolved = self._pure_resolve_x86_call_target(
                            out, t86, rva_map, text_data, text_rva)
                        if resolved is not None:
                            newt = resolved
                        else:
                            newt = None
                if newt is None:
                    newt = self._pure_resolve_x86_call_target(
                        out, t86, rva_map, text_data, text_rva)
                if newt is None:
                    continue
                if not (0 <= newt < len(out)):
                    continue
                cur_rel = struct.unpack_from('<i', out, site + 1)[0]
                cur = site + 5 + cur_rel
                if cur == newt:
                    continue
                cur_fn_x86 = self._pure_fn_entry_x86_for_x64_off(
                    rva_map, cur, self._fn_entry_rvas or set())
                if not (0 <= cur < len(out)):
                    pass  # out-of-range current → definitely fix
                elif cur_fn_x86 is not None and cur_fn_x86 != t86:
                    pass  # current is a different function's mapped entry
                elif self._pure_mapped_entry_sane(out, cur, t86, text_data, text_rva):
                    continue  # current already looks right for this call
                if not self._pure_mapped_entry_sane(out, newt, t86, text_data, text_rva):
                    continue  # wanted target doesn't match either → don't guess
                struct.pack_into('<i', out, site + 1, newt - (site + 5))
                fixed += 1
        return fixed

    def _pure_snap_calls_off_interior_targets(self, out: bytearray,
                                              rva_map: Dict[int, int]) -> int:
        """Snap E8 rel32 that land inside a mapped function body to its entry."""
        if not self._cmd_no_hacks:
            return 0
        need: Set[int] = set(self._fn_entry_rvas or ())
        cf = self._x86_cf
        if cf:
            need |= cf.call_targets
        entries = sorted({rva_map[r] for r in need if r in rva_map})
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._pure_branch_site_ok(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            for entry in entries:
                if entry == tgt:
                    break
                if not (entry < tgt < entry + 96):
                    continue
                if (self._pure_mapping_is_swallowed_slot(out, tgt)
                        or self._pure_is_corrupt_x86_hybrid(out, tgt)
                        or not self._pure_call_target_plausible(out, tgt)):
                    struct.pack_into('<i', out, i + 1, entry - (i + 5))
                    fixed += 1
                    break
        return fixed

    def _epilogue_inplace_slot_safe(self, out: bytearray, hint: int,
                                    ep_bytes: Optional[bytes] = None) -> bool:
        """True when *hint* may receive an in-place epilogue rewrite.

        Reject tips inside ``movabs`` / ``mov r64,imm32`` immediates and tips
        that are clearly mid-``and rsp, imm8`` (imm already overwritten with
        ``0x5F`` from a slid ``pop rdi``).  Also reject body prefixes
        (``mov rsp,r13`` / ``xor rax,rax`` / mid-REX ``pop r13``) unless
        *ep_bytes* starts with the same prefix — writing a short
        ``pop/leave/ret`` onto those slots swallows the align restore
        (univ261 ``0x2A0EB`` leave-epi / ``0x2B402`` mid-``41 5D``).
        """
        if hint < 0 or hint >= len(out):
            return False
        if self._pure_off_in_imm_operand(out, hint):
            return False
        # ``and rsp, 0x5F`` — imm8 already replaced by slid pop rdi.
        if (hint >= 3 and out[hint - 3:hint + 1] == bytes(
                [0x48, 0x83, 0xE4, 0x5F])):
            return False
        if (hint >= 2 and out[hint - 2:hint + 1] == bytes(
                [0x48, 0x31, 0x5F])):
            return False
        ep = bytes(ep_bytes) if ep_bytes is not None else None

        def _ep_starts(prefix: bytes) -> bool:
            return ep is not None and ep.startswith(prefix)

        # Body before the real pop-tail: only rewrite in-place when the
        # synthesized epi itself begins with the same body bytes.
        for pref in (
                bytes([0x4C, 0x89, 0xEC]),  # mov rsp,r13
                bytes([0x48, 0x89, 0xEC]),  # mov rsp,rbp
                bytes([0x48, 0x31, 0xC0]),  # xor rax,rax
                bytes([0x48, 0x89, 0xE5])):  # mov rbp,rsp (rare)
            if out[hint:hint + len(pref)] == pref and not _ep_starts(pref):
                return False
        # Tip on 2nd byte of ``41 5D`` (pop r13) etc. — looks like ``pop rbp``
        # but rewriting yields ``41 5F 5E 5B C9 C3`` (univ261 ``0x2B402``).
        if (hint >= 1 and out[hint - 1] == 0x41
                and out[hint] in (
                    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F)
                and not _ep_starts(bytes([0x41, out[hint]]))):
            return False
        b0 = out[hint]
        if b0 in (0x58, 0x5B, 0x5D, 0x5E, 0x5F, 0xC9, 0xC3):
            return True
        if b0 == 0x41 and hint + 1 < len(out) and out[hint + 1] in (
                0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D):
            return True  # pop r8..r13
        if out[hint:hint + 3] in (
                bytes([0x48, 0x31, 0xC0]),  # xor rax,rax
                bytes([0x4C, 0x89, 0xEC]),  # mov rsp,r13
                bytes([0x48, 0x89, 0xEC]),  # mov rsp,rbp
                bytes([0x48, 0x89, 0xE5])):  # mov rbp,rsp (rare)
            return True
        return False

    def _materialize_epilogue_label(self, out: bytearray, rva_map: Dict[int, int],
                                    ep_rva: int) -> Optional[int]:
        """Ensure an x86 epilogue label has inline x64 ``pop/leave/ret`` bytes in *out*."""
        cf = self._x86_cf
        if not cf or ep_rva not in cf.epilogue_labels:
            return None
        text_data = getattr(self, '_pure_heal_text', None)
        text_rva = getattr(self, '_pure_heal_text_rva', 0)
        if (self._cmd_no_hacks and text_data is not None
                and self._looks_like_code(text_data, text_rva, ep_rva)):
            off = ep_rva - text_rva
            if 0 <= off < len(text_data):
                ep = _x64_bytes_for_x86_epilogue(text_data, off)
                if ep is not None:
                    _x86_len, ep_bytes = ep
                    if ep_bytes and len(ep_bytes) <= 32:
                        hint = rva_map.get(ep_rva)

                        def _slot_is_sane_epilogue(pos: int) -> bool:
                            if pos < 0 or pos >= len(out):
                                return False
                            if out[pos] in (0x00, 0xCC):
                                return False
                            window = bytes(out[pos:pos + 16])
                            ret_at = window.find(0xC3)
                            if ret_at < 0 or ret_at > 12:
                                return False
                            # Reject leftover stdcall arg-discard ``pop rcx/rdx``
                            # before ret — those eat the return address on x64.
                            if any(b in (0x59, 0x5A) for b in window[:ret_at]):
                                return False
                            return window[0] in (
                                0x58, 0x5B, 0x5D, 0x5E, 0x5F,
                                0xC9, 0xC3, 0x89, 0x8B,
                            )

                        # Rematerialize when missing, scrambled, or not an
                        # exact match for the synthesized epilogue.  Never
                        # plant a trampoline over the old slot — shared hints
                        # caused jmp chains onto the wrong body (cmd 0xD986).
                        # ``_cf_repair_epilogue_branch_targets`` retargets
                        # stale branches after the map update.
                        if (hint is not None and 0 <= hint < len(out)
                                and out[hint:hint + len(ep_bytes)] == ep_bytes):
                            return hint
                        # In-place rewrite when the slot is a real epilogue tail
                        # (possibly with fatal stdcall ``pop rcx`` discards) and
                        # the synthesized bytes fit in the old ret span — keeps
                        # fall-through correct without clobbering the next fn.
                        #
                        # NEVER rewrite when *hint* sits inside another insn's
                        # immediate (univ260): rva_map tipped ``pop edi`` onto
                        # a ``movabs``/``and rsp`` imm byte that happened to
                        # precede a real ``ret``, so this pass wrote
                        # ``5F 5E 5B C3`` mid-imm and NOPed through the old
                        # ret — swallowing the prior insn (execute@NULL).
                        if (hint is not None and 0 <= hint < len(out)
                                and self._epilogue_inplace_slot_safe(
                                    out, hint, ep_bytes)):
                            window = bytes(out[hint:hint + 16])
                            old_ret = window.find(0xC3)
                            if (old_ret >= 0
                                    and out[hint] not in (0x00, 0xCC)
                                    and len(ep_bytes) <= old_ret + 1
                                    and hint + old_ret + 1 <= len(out)):
                                out[hint:hint + len(ep_bytes)] = ep_bytes
                                for k in range(hint + len(ep_bytes),
                                               hint + old_ret + 1):
                                    out[k] = 0x90
                                rva_map[ep_rva] = hint
                                self._note_code_span(hint, len(ep_bytes))
                                return hint
                        if (hint is None or hint < 0 or hint >= len(out)
                                or out[hint] in (0x00, 0xCC)
                                or out[hint:hint + len(ep_bytes)] != ep_bytes
                                or not self._epilogue_inplace_slot_safe(
                                    out, hint, ep_bytes)):
                            base = len(out)
                            out += ep_bytes
                            out += b'\x90' * ((4 - len(out) % 4) % 4)
                            rva_map[ep_rva] = base
                            self._note_code_span(base, len(ep_bytes))
                            return base
                        return hint
                else:
                    hint = rva_map.get(ep_rva)
                    if hint is not None and 0 <= hint < len(out):
                        if self._pure_mapped_entry_sane(
                                out, hint, ep_rva, text_data, text_rva):
                            return hint
                    return None
        # cf.epilogue_labels already holds x64 bytes from
        # _x64_bytes_for_x86_epilogue, which converts stdcall ``ret N`` → ``ret``
        # (caller-cleanup convention). As a safety net, also fix any raw
        # ``ret N`` (C2) tail that slipped through verbatim.
        ep_bytes = cf.epilogue_labels[ep_rva]
        if not ep_bytes or len(ep_bytes) > 32:
            return None
        if len(ep_bytes) >= 3 and ep_bytes[-3] == 0xC2:
            ep_bytes = ep_bytes[:-3] + b'\xc3\x90\x90'
        # Drop any stdcall arg-discard pop rcx/rdx left in cached bytes.
        cleaned = bytearray()
        i = 0
        while i < len(ep_bytes):
            if ep_bytes[i] in (0x59, 0x5A) and 0xC3 in ep_bytes[i:]:
                # skip discard pops up to ret
                while i < len(ep_bytes) and ep_bytes[i] in (0x59, 0x5A):
                    i += 1
                continue
            cleaned.append(ep_bytes[i])
            i += 1
        ep_bytes = bytes(cleaned) if cleaned else ep_bytes
        hint = rva_map.get(ep_rva)
        if hint is not None and 0 <= hint < len(out):
            if out[hint:hint + len(ep_bytes)] == ep_bytes:
                return hint
            for delta in range(0, 20):
                pos = hint + delta
                if pos + 5 > len(out):
                    break
                if out[pos] == 0xE9 and self._pure_off_starts_real_jmp(out, pos):
                    slot = pos
                    pad_end = slot + max(5, len(ep_bytes))
                    out[slot:slot + len(ep_bytes)] = ep_bytes
                    for k in range(slot + len(ep_bytes), pad_end):
                        if k < len(out):
                            out[k] = 0x90
                    rva_map[ep_rva] = slot
                    self._note_code_span(slot, len(ep_bytes))
                    return slot
                if (out[pos] == ep_bytes[0]
                        and pos + len(ep_bytes) <= len(out)
                        and out[pos:pos + len(ep_bytes)] == ep_bytes):
                    rva_map[ep_rva] = pos
                    return pos
            # Keep only an exact match; otherwise append (no trampoline).
            if out[hint:hint + len(ep_bytes)] == ep_bytes:
                return hint
            if out[hint] not in (0x00, 0xCC) and 0xC3 in bytes(out[hint:hint + 12]):
                # Prefer overwrite via cf_repair after map update — still append.
                pass
            else:
                pass
        base = len(out)
        out += ep_bytes
        out += b'\x90' * ((4 - len(out) % 4) % 4)
        rva_map[ep_rva] = base
        self._note_code_span(base, len(ep_bytes))
        return base

    def _snap_branch_targets_to_epilogue_heads(self, out: bytearray,
                                               snap_map: Dict[int, int]) -> int:
        """Redirect branches that land mid pop/ret chain to the canonical epilogue head."""
        if not snap_map:
            return 0
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] in (0xE8, 0xE9):
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                head = snap_map.get(tgt)
                if head is not None and head != tgt:
                    struct.pack_into('<i', out, i + 1, head - (i + 5))
                    fixed += 1
            elif (out[i] == 0x0F and i + 6 < len(out)
                  and 0x80 <= out[i + 1] <= 0x8F):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 6 + rel
                head = snap_map.get(tgt)
                if head is not None and head != tgt:
                    struct.pack_into('<i', out, i + 2, head - (i + 6))
                    fixed += 1
        return fixed

    def _snap_branches_past_epilogues(self, out: bytearray) -> int:
        """Redirect branches that land inside ``pop…; add rsp; ret`` epilogues
        to the function body *after* the ``ret`` + NOP padding.

        This is the counterpart of ``_snap_branch_targets_to_epilogue_heads``:
        that function snaps to the epilogue *head* (first pop), while this one
        snaps *past* the epilogue to the real function body.  Together they
        ensure every branch either correctly enters the shared return sequence
        or correctly enters the function body — never lands mid-epilogue."""
        POP64 = frozenset((0x5B, 0x5D, 0x5E, 0x5F))
        if len(out) < 6:
            return 0

        # Build snap map: any offset inside [epi_start, ret_pos] → body_start
        # Also accept a leading ``mov eax, e[bsi]`` (89 D8/F0/F8/…) before pops.
        MOV_EAX = frozenset((0xD8, 0xF0, 0xF8, 0xC8, 0xD0))
        snap: Dict[int, int] = {}
        i = 0
        while i < len(out) - 2:
            start = i
            if (out[i] == 0x89 and i + 2 < len(out)
                    and out[i + 1] in MOV_EAX
                    and i + 2 < len(out) and out[i + 2] in POP64):
                i += 2
            elif out[i] not in POP64:
                i += 1
                continue
            while i < len(out) and out[i] in POP64:
                i += 1
            if (out[i] == 0x48 and i + 6 < len(out)
                    and out[i + 1] == 0x81 and out[i + 2] == 0xC4):
                i += 7                                         # add rsp, imm32
            # ── mov rsp,rbp (48 89 EC) / mov rsp,r13 (4C 89 EC) ──
            # These are common in x64 translations of shared epilogues
            # where the x86 ``leave`` was expanded to separate mov+pop.
            if i + 3 <= len(out) and bytes(out[i:i + 3]) in (
                    b'\x48\x89\xec', b'\x4c\x89\xec'):
                i += 3
                # After ``mov rsp, rbp/r13`` a trailing ``pop rbp/r13`` may
                # follow before the ``ret`` (the x86 ``leave`` is ``mov rsp,rbp;
                # pop rbp`` — translated literally as two instructions).
                if i < len(out) and out[i] in POP64:
                    i += 1
            if i < len(out) and out[i] == 0xC9:                # leave
                i += 1
            if i >= len(out) or out[i] != 0xC3:
                i = start + 1
                continue
            ret_pos = i
            i += 1
            body = i
            while body < len(out) and out[body] == 0x90:
                body += 1
            if body >= len(out) or out[body] in POP64 or out[body] == 0xC3:
                i = start + 1
                continue
            for pos in range(start, ret_pos + 1):
                snap[pos] = body
            i = ret_pos + 1

        if not snap:
            return 0
        # Only apply to CALL (E8) instructions — JMP (E9) and Jcc (0F 8x)
        # may legitimately target an epilogue for tail-call merging, where
        # the caller wants to reuse the epilogue's frame cleanup but NOT
        # re-enter the function body.  CALL always intends to invoke the
        # function, so redirecting past the epilogue is always correct.
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] == 0xE8:
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                new_tgt = snap.get(tgt)
                if new_tgt is not None and new_tgt != tgt:
                    struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
                    fixed += 1
        return fixed

    def _snap_calls_past_align_prologues(self, out: bytearray,
                                          rva_map: Dict[int, int],
                                          text_data: bytes,
                                          text_rva: int) -> int:
        """Fix CALLs that target their own align-wrapper prologue — the
        infinite-recursion pattern that causes stack overflow.

        Uses the RVA map to re-resolve the correct x86 target.
        """
        if not self._cmd_no_hacks:
            return 0
        AW = self._ALIGN_WRAP  # 13 bytes
        AW_LEN = len(AW)
        EPI = b'\x4c\x89\xec\x41\x5d'  # mov rsp,r13; pop r13 = 5 bytes
        # Build reverse map: x64 blob offset → x86 RVA (all entries)
        rev: Dict[int, int] = {}
        for x86, x64 in rva_map.items():
            rev[x64] = x86 & 0xFFFFFFFF

        fixed = 0
        i = 0
        while i < len(out) - AW_LEN - 5:
            if out[i:i + AW_LEN] != AW:
                i += 1
                continue
            prologue_start = i
            call_pos = i + AW_LEN
            if call_pos + 5 > len(out) or out[call_pos] != 0xE8:
                i += AW_LEN
                continue
            rel = struct.unpack_from('<i', out, call_pos + 1)[0]
            tgt = call_pos + 5 + rel
            # Does this CALL target its own wrapper prologue?
            if not (prologue_start <= tgt < call_pos):
                i += AW_LEN
                continue
            # ── Self-referencing CALL ──
            # Walk BACKWARD from the call to find the x86 source address.
            # Injected wrapper bytes have no RVA map entries; the nearest
            # mapped byte may be thousands of bytes away (the original
            # x86 code was translated at a completely different position).
            # Scan generously — blob is only ~300KB so linear scan is fast.
            x86_call_src = None
            for step in range(1, call_pos + 1):
                candidate = call_pos - step
                if candidate < 0:
                    break
                x86_rva = rev.get(candidate)
                if x86_rva is not None:
                    x86_call_src = x86_rva
                    break
            if x86_call_src is None:
                i += AW_LEN
                continue
            # Validate: find the x86 CALL near the mapped source.
            # The x64 CALL may correspond to an x86 ``push imm; call`` or
            # ``mov reg,imm; call`` sequence — the E8 is not always at the
            # first mapped byte.  Search a small window.
            x86_base = x86_call_src - text_rva
            x86_call_off = None
            x86_call_rva = None
            for delta in range(8):
                off = x86_base + delta
                if 0 <= off < len(text_data) - 5 and text_data[off] == 0xE8:
                    x86_call_off = off
                    x86_call_rva = (x86_call_src + delta) & 0xFFFFFFFF
                    break
            if x86_call_off is None:
                i += AW_LEN
                continue
            x86_rel = struct.unpack_from('<i', text_data, x86_call_off + 1)[0]
            x86_tgt = (x86_call_rva + 5 + x86_rel) & 0xFFFFFFFF
            # Look up x64 for the x86 target
            new_tgt = rva_map.get(x86_tgt)
            if new_tgt is None or new_tgt == tgt:
                i += AW_LEN
                continue
            # Fix the CALL target
            struct.pack_into('<i', out, call_pos + 1,
                             new_tgt - (call_pos + 5))
            fixed += 1
            i = call_pos + 5
        return fixed

    def _snap_calls_past_register_saves(self, out: bytearray) -> int:
        """Fix CALLs targeting AW+5 that skip injected register-save pushes.

        Healed function chunks may carry ``push rsi / push rdi`` (or other
        non-R13 pushes) *before* the align-wrapper.  External callers target
        AW+5 (after ``push r13; mov r13,rsp``) which also skips those saves.
        The function epilogue ``pop rdi; pop rsi; ret`` then pops garbage,
        eventually returning to 0x1.

        Walk backwards from each AW+5 call target past the align-wrapper
        prologue and any register-save pushes found immediately before it.
        Retarget the call to the first such push so the epilogue balances.
        """
        AW_PUSH_R13  = b'\x41\x55'            # push r13
        AW_MOV_R13   = b'\x49\x89\xe5'        # mov r13, rsp
        AW_PROLOGUE  = AW_PUSH_R13 + AW_MOV_R13  # 5 bytes
        AW_SUB       = b'\x48\x83\xec\x20'    # sub rsp, 0x20
        AW_AND       = b'\x48\x83\xe4\xf0'    # and rsp, -16
        # Single-byte push register opcodes (x64): rAX..rDI = 0x50..0x57
        # Exclude push r13 (0x41 0x55) — that's the align-wrapper itself.
        _PUSH_REGS = frozenset(range(0x50, 0x58))

        fixed = 0
        i = 0
        while i < len(out) - 5:
            if out[i] != 0xE8:
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < 8 or tgt >= len(out):
                i += 1
                continue
            # Does the call target land on sub rsp,0x20 or and rsp,-16 ?
            tgt_bytes = out[tgt:tgt + 4]
            if tgt_bytes[:4] != AW_SUB and tgt_bytes[:4] != AW_AND:
                i += 1
                continue
            # Walk backwards from tgt past the align-wrapper prologue
            aw_start = tgt - 5  # push r13; mov r13,rsp (5 bytes)
            if aw_start < 0 or out[aw_start:aw_start + 5] != AW_PROLOGUE:
                i += 1
                continue
            # Now walk backwards from aw_start past any register-save pushes.
            # There may be non-push instructions between the pushes and the
            # align-wrapper (xor, cmp, mov, etc.) — scan past them.
            # Stop ONLY at a ``ret`` or at blob start.
            pos = aw_start
            save_start = None
            while pos > 0:
                b = out[pos - 1]
                if b in (0xC3, 0xC2):          # ret / ret imm — end of prev fn
                    break
                if b in _PUSH_REGS:
                    save_start = pos - 1
                    pos -= 1
                    # Keep walking while we see consecutive pushes
                    while pos > 0 and out[pos - 1] in _PUSH_REGS:
                        pos -= 1
                    save_start = pos   # earliest push found
                    break
                pos -= 1
            if save_start is None:
                i += 1
                continue
            # Retarget the CALL to the first register-save push found
            struct.pack_into('<i', out, i + 1, save_start - (i + 5))
            fixed += 1
            i += 5
        return fixed

    def _fix_mov_direction_swaps(self, out: bytearray,
                                  rva_map: Dict[int, int],
                                  text_data: bytes,
                                  text_rva: int) -> int:
        """Fix x64 ``66 89`` (MOV r/m16,r16 — store) that should be
        ``66 8B`` (MOV r16,r/m16 — load), and ``29``/``2B`` SUB direction.

        The translator occasionally swaps MOV direction for 16-bit
        operations.  Each x64 ``66 89`` is checked against its x86
        source via the RVA map; when the x86 has ``66 8B`` the x64
        opcode is corrected.  The same reverse lookup also repairs
        ``sub r/m,r`` (``29``) that should be ``sub r,r/m`` (``2B``)
        when the x86 source used ``2B`` (cmd parse loop at ``0xAF8C``).
        """
        if text_data is None or not rva_map:
            return 0
        # Build reverse map: x64 offset → nearest x86 RVA
        rev: Dict[int, int] = {}
        for x86_rva, x64_off in rva_map.items():
            rev[x64_off] = x86_rva
        sorted_offs = sorted(rev.keys())

        def _x86_rva_for_x64_off(off: int) -> Optional[int]:
            """Return the x86 RVA whose x64 mapping is nearest to *off*."""
            import bisect
            idx = bisect.bisect_right(sorted_offs, off) - 1
            if idx < 0:
                return None
            nearest_off = sorted_offs[idx]
            if off - nearest_off > 64:   # too far to be reliable
                return None
            return rev[nearest_off]

        fixed = 0
        i = 0
        while i < len(out) - 2:
            if out[i:i + 2] == b'\x66\x89':
                modrm = out[i + 2]
                mod = (modrm >> 6) & 3
                # Only fix memory-destination forms (mod ≠ 11 means memory)
                if mod == 3:
                    i += 3
                    continue
                x86_rva = _x86_rva_for_x64_off(i)
                if x86_rva is None:
                    i += 3
                    continue
                x86_off = x86_rva - text_rva
                if x86_off < 0 or x86_off + 3 > len(text_data):
                    i += 3
                    continue
                x86_bytes = text_data[x86_off:x86_off + 3]
                # Check for 66 8B (16-bit load) in x86
                if x86_bytes[0:2] == b'\x66\x8b':
                    # Fix x64: change 89 → 8B
                    out[i + 1] = 0x8B
                    fixed += 1
                i += 3
                continue
            # sub r/m32, r32 (29 /r) that should be sub r32, r/m32 (2B /r)
            if out[i] == 0x29 and i + 2 < len(out):
                modrm = out[i + 1]
                mod = (modrm >> 6) & 3
                if mod != 3:
                    x86_rva = _x86_rva_for_x64_off(i)
                    if x86_rva is not None:
                        x86_off = x86_rva - text_rva
                        if 0 <= x86_off < len(text_data) - 1:
                            # Scan a small window: heal may shift the site.
                            window = text_data[max(0, x86_off - 4):
                                               min(len(text_data), x86_off + 6)]
                            if b'\x2b' in window and out[i] == 0x29:
                                # Prefer exact modrm match in window.
                                want = bytes([0x2B, modrm])
                                if want in window or any(
                                        window[j] == 0x2B
                                        and j + 1 < len(window)
                                        and (window[j + 1] & 0xC7) == (modrm & 0xC7)
                                        for j in range(len(window) - 1)):
                                    out[i] = 0x2B
                                    fixed += 1
                i += 1
                continue
            i += 1
        return fixed

    def _pure_narrow_packed_data_qword_ops(self, out: bytearray) -> int:
        """Rewrite ``movabs; mov qword [scratch],r`` on packed .data to dword.

        PE32 globals stay 4-byte-packed after remap (preferred base <4GiB).
        Emitting qword stores for x86 ``mov dword [abs],r32`` zeroes the next
        slot — e.g. flag store at ``fbc4`` wiped PWSTR cursor at ``fbc8``.
        Clear REX.W on ``movabs r11/rax/r10; mov/load [reg]`` when the
        immediate lands in a packed data section.

        Never touch IAT/idata slots — those hold host 64-bit function
        pointers; narrowing them truncates to ``0x6485E3E0``-style addresses
        and crashes on ``call rax``.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, 'new_base', 0) or 0)
        if not nb:
            return 0
        ranges: List[Tuple[int, int]] = []
        pe = getattr(self, 'pe', None)
        old_to_new = getattr(self, '_old_to_new_section', None) or {}
        idata_rva = int(getattr(self, '_idata_rva', 0) or 0)
        idata_sz = len(getattr(self, '_idata', b'') or b'')
        # Live IAT slot VAs — authoritative exclusion even when section
        # metadata is missing at heal time.
        iat_vas: Set[int] = set()
        for v in (getattr(self, '_iat_rva_map', None) or {}).values():
            iat_vas.add(nb + int(v))
        try:
            for sec in (pe.sections if pe is not None else ()):
                name = str(getattr(sec, 'name', '') or '')
                if name.startswith('.text') or name.startswith('.idata'):
                    continue
                # Only narrow writable packed data — never rdata/rsrc.
                if name.startswith('.rsrc') or name.startswith('.reloc'):
                    continue
                if not name.startswith('.data') and not name.startswith('.bss'):
                    # PE32 sometimes parks globals in unnamed/CRT sections;
                    # only accept writable non-exec.
                    if not getattr(sec, 'is_writable', False):
                        continue
                    if getattr(sec, 'is_executable', False):
                        continue
                old_rva = int(getattr(sec, 'vaddr', 0) or 0)
                new_rva = int(old_to_new.get(old_rva, old_rva))
                vsz = int(getattr(sec, 'vsize', 0) or 0)
                if vsz <= 0:
                    continue
                lo = nb + new_rva
                hi = lo + vsz
                if idata_rva and idata_sz:
                    i_lo, i_hi = nb + idata_rva, nb + idata_rva + idata_sz
                    if not (hi <= i_lo or lo >= i_hi):
                        if lo < i_lo:
                            ranges.append((lo, i_lo))
                        if i_hi < hi:
                            ranges.append((i_hi, hi))
                        continue
                ranges.append((lo, hi))
        except Exception:
            ranges = []
        if not ranges:
            # Conservative fallback: typical .data band only (not idata ~0x95xxx).
            ranges = [(nb + 0x60000, nb + 0x90000)]

        def _in_packed(va: int) -> bool:
            if va in iat_vas:
                return False
            if idata_rva and idata_sz:
                if nb + idata_rva <= va < nb + idata_rva + idata_sz:
                    return False
            # Also exclude the conventional PE64 .idata window.
            if (nb + 0x90000) <= va < (nb + 0xA0000):
                return False
            return any(lo <= va < hi for lo, hi in ranges)

        fixed = 0
        i = 0
        while i < len(out) - 13:
            if out[i] in (0x48, 0x49) and out[i + 1] in (
                    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
                va = struct.unpack_from('<Q', out, i + 2)[0]
                if not _in_packed(va):
                    i += 1
                    continue
                j = i + 10
                if j + 2 >= len(out):
                    i += 1
                    continue
                rex = out[j]
                op = out[j + 1]
                if (rex & 0xF0) == 0x40 and (rex & 0x08) and op in (0x89, 0x8B):
                    modrm = out[j + 2]
                    mod = (modrm >> 6) & 3
                    rm = modrm & 7
                    if mod == 0 and rm != 4 and rm != 5:
                        out[j] = rex & ~0x08
                        fixed += 1
                        i = j + 3
                        continue
                    if mod == 1 and rm != 4:
                        out[j] = rex & ~0x08
                        fixed += 1
                        i = j + 4
                        continue
            i += 1
        return fixed

    def _pure_fix_int3_omitted_ebp8_store(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Restore ``mov [ebp+N],r32`` swallowed into an INT3/NOP gap.

        Universal (any Win2k PE32): stdcall/frame arg-home stores
        (``[ebp+8]``/``+0xC``/``+0x10``/``+0x14``) are sometimes dropped
        during translate, leaving a lone ``int3``/``nop`` before the next
        ``jmp``/``jcc``/call-align/``sub``.  Drive from the x86 pattern
        (store immediately followed by a branch), then search a window
        around the mapped PE64 site — ``rva_map`` often snaps mid-insn
        RVAs onto a neighbouring prologue, so a pure reverse-nearest
        scan misses the gap.
        """
        if not self._cmd_no_hacks or not text_data or not rva_map:
            return 0
        fixed = 0
        call_align = bytes.fromhex('41554989e5')  # push r13; mov r13,rsp
        tr = int(getattr(self, '_pure_heal_text_rva', None) or text_rva or 0)
        seen_gap: Set[int] = set()

        def _map_to_off(v: int) -> Optional[int]:
            v = int(v)
            if 0 <= v < len(out):
                return v
            if tr and v >= tr and (v - tr) < len(out):
                return v - tr
            return None

        def _hint_offs(v: int) -> List[int]:
            """Live blob-off and dumped-RVA interpretations of a map value."""
            v = int(v)
            outs: List[int] = []
            if 0 <= v < len(out):
                outs.append(v)
            if tr and v >= tr and (v - tr) < len(out):
                o = v - tr
                if o not in outs:
                    outs.append(o)
            return outs

        def _emit_store(reg: int, ebp_disp: int = 8) -> bytes:
            rbp_disp = ebp_disp * 2  # stdcall arg home → Win64 home
            return bytes([0x89, (1 << 6) | (reg << 3) | 5, rbp_disp & 0xFF])

        def _is_gap_pad(off: int) -> bool:
            """Lone INT3/NOP — not part of a multi-byte pad sled."""
            if off < 0 or off >= len(out) or out[off] not in (0xCC, 0x90):
                return False
            if off > 0 and out[off - 1] in (0xCC, 0x90):
                return False
            if (off + 2 < len(out) and out[off + 1] in (0xCC, 0x90)
                    and out[off + 2] in (0xCC, 0x90)):
                return False
            return True

        def _apply_gap(i: int, reg: int, ebp_disp: int) -> bool:
            """Patch gap at *i*; return True if rewritten."""
            if i in seen_gap or not _is_gap_pad(i):
                return False
            stub_at = len(out)
            if out[i + 1:i + 6] == call_align:
                resume = i + 6
                stub = bytearray(_emit_store(reg, ebp_disp))
                stub += call_align
                stub += b'\xe9' + struct.pack(
                    '<i', resume - (stub_at + len(stub) + 5))
                out.extend(stub)
                while len(out) % 16:
                    out.append(0x90)
                out[i:i + 6] = (
                    b'\xe9' + struct.pack('<i', stub_at - (i + 5)) + b'\x90')
                seen_gap.add(i)
                return True
            if out[i + 1] == 0xE9 and i + 6 <= len(out):
                rel = struct.unpack_from('<i', out, i + 2)[0]
                tgt = i + 1 + 5 + rel
                if tgt < 0:
                    return False
                stub = bytearray(_emit_store(reg, ebp_disp))
                stub += b'\xe9' + struct.pack(
                    '<i', tgt - (stub_at + len(stub) + 5))
                out.extend(stub)
                while len(out) % 16:
                    out.append(0x90)
                out[i:i + 6] = (
                    b'\xe9' + struct.pack('<i', stub_at - (i + 5)) + b'\x90')
                seen_gap.add(i)
                return True
            if (out[i + 1] == 0x0F and i + 7 <= len(out)
                    and 0x80 <= out[i + 2] <= 0x8F):
                rel = struct.unpack_from('<i', out, i + 3)[0]
                tgt = i + 1 + 6 + rel
                fall = i + 7
                if tgt < 0:
                    return False
                store = _emit_store(reg, ebp_disp)
                jcc_op = out[i + 1:i + 3]
                stub = bytearray(store)
                stub += jcc_op + struct.pack(
                    '<i', tgt - (stub_at + len(store) + 6))
                stub += b'\xe9' + struct.pack(
                    '<i', fall - (stub_at + len(store) + 6 + 5))
                out.extend(stub)
                while len(out) % 16:
                    out.append(0x90)
                out[i:i + 7] = (
                    b'\xe9' + struct.pack('<i', stub_at - (i + 5))
                    + b'\x90\x90')
                seen_gap.add(i)
                return True
            if (out[i + 1] in (0x29, 0x2B)
                    and i >= 2 and out[i - 2:i] == b'\x89\xf7'):
                site = i - 2
                if site in seen_gap:
                    return False
                sub_bytes = bytearray(out[i + 1:i + 4])
                if sub_bytes[0] == 0x29:
                    sub_bytes[0] = 0x2B
                resume = i + 4
                stub = bytearray(b'\x89\xf7')
                stub += _emit_store(reg, ebp_disp)
                stub += sub_bytes
                stub += b'\xe9' + struct.pack(
                    '<i', resume - (stub_at + len(stub) + 5))
                out.extend(stub)
                while len(out) % 16:
                    out.append(0x90)
                out[site:site + 6] = (
                    b'\xe9' + struct.pack('<i', stub_at - (site + 5)) + b'\x90')
                seen_gap.add(site)
                seen_gap.add(i)
                return True
            # Short jcc after gap: int3; jcc rel8 (4 bytes) → jmp stub (5)
            if (0x70 <= out[i + 1] <= 0x7F) and i + 5 <= len(out):
                rel8 = struct.unpack_from('<b', out, i + 2)[0]
                tgt = i + 1 + 2 + rel8
                fall = i + 3
                store = _emit_store(reg, ebp_disp)
                stub = bytearray(store)
                jcc32 = bytes([0x0F, 0x80 | (out[i + 1] & 0x0F)])
                stub += jcc32 + struct.pack(
                    '<i', tgt - (stub_at + len(store) + 6))
                stub += b'\xe9' + struct.pack(
                    '<i', fall - (stub_at + len(store) + 6 + 5))
                out.extend(stub)
                while len(out) % 16:
                    out.append(0x90)
                out[i:i + 5] = (
                    b'\xe9' + struct.pack('<i', stub_at - (i + 5)))
                seen_gap.add(i)
                return True
            return False

        def _search_and_fix(hint: int, reg: int, ebp_disp: int) -> bool:
            """Structured gaps only (jmp/jcc/align/sub) near *hint*."""
            lo = max(0, hint - 0x20)
            hi = min(len(out) - 3, hint + 0x80)
            for i in range(lo, hi + 1):
                if _apply_gap(i, reg, ebp_disp):
                    return True
            return False

        # ── Pass 1: x86 store immediately followed by a branch ────────────
        # Mid-loop ``mov [ebp+N],r32; jmp/jcc`` is the high-confidence shape:
        # the PE64 site is ``int3; jmp/jcc`` (sometimes with a preserved
        # ``inc r64`` just before the gap).  Broader lone-INT3 rematerialize
        # is unsafe — ``rva_map`` mid-insn snaps can land kilobytes off.
        for fo in range(len(text_data) - 4):
            if text_data[fo] != 0x89:
                continue
            modrm = text_data[fo + 1]
            if (modrm & 0xC7) not in (0x45, 0x5D, 0x75, 0x7D):
                continue
            disp = text_data[fo + 2]
            if disp not in (0x08, 0x0C, 0x10, 0x14):
                continue
            nxt = fo + 3
            b = text_data[nxt]
            is_branch = (
                b in (0xEB, 0xE9)
                or (0x70 <= b <= 0x7F)
                or (b == 0x0F and nxt + 1 < len(text_data)
                    and 0x80 <= text_data[nxt + 1] <= 0x8F)
            )
            if not is_branch:
                continue
            reg = (modrm >> 3) & 7
            x86_rva = text_rva + fo
            hints: List[int] = []
            for key in (x86_rva, (x86_rva - 1) & 0xFFFFFFFF,
                        (x86_rva - 2) & 0xFFFFFFFF,
                        (x86_rva - 3) & 0xFFFFFFFF,
                        (x86_rva + 3) & 0xFFFFFFFF):
                raw = rva_map.get(key)
                if raw is None:
                    continue
                for off in _hint_offs(int(raw)):
                    if off not in hints:
                        hints.append(off)
            if not hints:
                for d in range(1, 0x40):
                    for key in ((x86_rva - d) & 0xFFFFFFFF,
                                (x86_rva + d) & 0xFFFFFFFF):
                        raw = rva_map.get(key)
                        if raw is None:
                            continue
                        for off in _hint_offs(int(raw)):
                            if off not in hints:
                                hints.append(off)
                    if hints:
                        break
            # Also search PE64 for ``inc r64; int3; jmp`` near any hint —
            # the store gap often sits a few dozen bytes past a snapped map.
            for hint in list(hints):
                lo = max(0, hint - 0x10)
                hi = min(len(out) - 6, hint + 0xC0)
                for i in range(lo, hi):
                    if (out[i] == 0xCC and out[i + 1] == 0xE9
                            and _is_gap_pad(i)):
                        if i not in hints:
                            hints.append(i)
                        break
            for hint in hints:
                if _search_and_fix(hint, reg, disp):
                    fixed += 1
                    break

        # ── Pass 2: PE64 forward scan (catches gaps map pass missed) ─────
        rev = {pe64: x86 for x86, pe64 in rva_map.items()}
        # Normalise rev keys to blob offsets.
        rev_off: Dict[int, int] = {}
        for pe64, x86 in rev.items():
            off = _map_to_off(int(pe64))
            if off is not None:
                rev_off[off] = x86
        sorted_offs = sorted(rev_off.keys())

        def _near_x86(off: int) -> Optional[int]:
            import bisect
            idx = bisect.bisect_right(sorted_offs, off) - 1
            if idx < 0:
                return None
            nearest = sorted_offs[idx]
            if off - nearest > 0x80:
                return None
            return rev_off[nearest]

        def _x86_ebp_store(x86_rva: int) -> Optional[Tuple[int, int]]:
            fo = x86_rva - text_rva
            if fo < 0:
                return None
            window = text_data[max(0, fo - 0x10):min(len(text_data), fo + 0x18)]
            for disp in (0x08, 0x0C, 0x10, 0x14):
                for reg, modrm in (
                        (0, 0x45), (3, 0x5D), (6, 0x75), (7, 0x7D)):
                    pat = bytes([0x89, modrm, disp])
                    if pat in window:
                        return reg, disp
            return None

        i = 0
        while i < len(out) - 8:
            if not _is_gap_pad(i):
                i += 1
                continue
            x86_rva = _near_x86(i)
            if x86_rva is None:
                i += 1
                continue
            store_info = _x86_ebp_store(x86_rva)
            if store_info is None:
                i += 1
                continue
            reg, ebp_disp = store_info
            if _apply_gap(i, reg, ebp_disp):
                fixed += 1
            i += 1
        return fixed

    def _pure_nop_orphan_int3(
            self, out: bytearray,
            rva_map: Optional[Dict[int, int]] = None) -> int:
        """NOP INT3 left where a dead ``mov [ebp+N],reg`` reload was dropped.

        Universal PE64 shape (no map required)::

            movabs r64, imm64
            int3                 ; omitted dead store
            mov    r64, imm32
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i + 15 < len(out):
            if (out[i] in (0x48, 0x49) and 0xB8 <= out[i + 1] <= 0xBF
                    and out[i + 10] == 0xCC
                    and out[i + 11] == 0x48 and out[i + 12] == 0xC7
                    and 0xC0 <= out[i + 13] <= 0xC7):
                out[i + 10] = 0x90
                fixed += 1
                i += 15
                continue
            i += 1
        return fixed

    def _pure_fix_missing_fifth_stack_home(self, out: bytearray) -> int:
        """Zero ``[rsp+0x20]`` before 5-arg IAT calls that only reserved shadow space.

        x86 ``push 0; push …; call [WriteFile]`` becomes
        ``sub rsp,0x20; and rsp; movabs; call rax`` with no 5th-home store —
        ``lpOverlapped`` then reads stack garbage and KERNELBASE AVs.
        Only rewrite wrappers whose absolute IAT cell is a known 5+-arg API.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, 'new_base', 0) or 0)
        name_map = getattr(self, '_iat_name_to_new_rva', None) or {}
        # APIs whose stdcall form pushes a 5th (often NULL) arg.
        # Exclude MultiByteToWideChar / WideCharToMultiByte (6 args): their
        # 5th/6th slots must hold real buffer/count pointers.  Zeroing only
        # the 5th home after a mis-emitted stdcall push sequence left the
        # wide buffer unset (cmd path helper → AV on garbage RSI).
        need_fifth = {
            'writefile', 'readfile', 'deviceiocontrol', 'waitformultipleobjects',
            'createfilew', 'createfilea', 'readfileex', 'writefileex',
            'getoverlappedresult', 'lockfileex', 'unlockfileex',
        }
        fifth_vas: Set[int] = set()
        for (dll, fn), rva in name_map.items():
            if fn.lower() in need_fifth:
                fifth_vas.add(nb + int(rva))
        if not fifth_vas:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 28:
            if out[i:i + 8] != bytes.fromhex('4883ec204883e4f0'):
                i += 1
                continue
            j = i + 8
            if j + 15 >= len(out):
                i += 1
                continue
            if out[j] not in (0x48, 0x49) or not (0xB8 <= out[j + 1] <= 0xBF):
                i += 1
                continue
            imm = struct.unpack_from('<Q', out, j + 2)[0]
            if imm not in fifth_vas:
                i += 1
                continue
            if out[j + 10:j + 15] not in (
                    bytes.fromhex('488b00ffd0'),
                    bytes.fromhex('498b00ffd0')):
                i += 1
                continue
            stub_at = len(out)
            stub = bytearray(bytes.fromhex('4883ec30'))
            stub += bytes.fromhex('4883e4f0')
            stub += bytes.fromhex('48c744242000000000')
            stub += out[j:j + 15]
            resume = j + 15
            stub += b'\xe9' + struct.pack(
                '<i', resume - (stub_at + len(stub) + 5))
            out.extend(stub)
            while len(out) % 16:
                out.append(0x90)
            out[i:i + 8] = (
                b'\xe9' + struct.pack('<i', stub_at - (i + 5))
                + b'\x90\x90\x90')
            for k in range(j, resume):
                out[k] = 0x90
            fixed += 1
            i = resume
        return fixed

    def _validate_all_call_targets(self, out: bytearray,
                                    rva_map: Dict[int, int],
                                    text_data: bytes,
                                    text_rva: int) -> int:
        """Final safety net: fix x64 CALLs whose target is clearly wrong.

        Only acts when the current target is a swallowed slot, a
        corrupt x86 hybrid, or a mid-instruction offset — cases where
        earlier repair passes definitively left a bad target.  Does
        NOT blindly redirect calls that already target a valid entry.
        """
        if not text_data or not rva_map:
            return 0
        rev = {}
        for x86_rva, x64_off in rva_map.items():
            rev[x64_off] = x86_rva
        sorted_offs = sorted(rev.keys())

        def _x86_for_x64(off: int) -> Optional[int]:
            import bisect
            idx = bisect.bisect_right(sorted_offs, off) - 1
            if idx < 0:
                return None
            nearest = sorted_offs[idx]
            if off - nearest > 32:
                return None
            return rev[nearest]

        fixed = 0
        i = 0
        while i < len(out) - 5:
            if out[i] != 0xE8:
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            cur_tgt = i + 5 + rel
            if cur_tgt < 0 or cur_tgt >= len(out):
                i += 1
                continue
            # Find x86 source and expected target
            x86_src = _x86_for_x64(i)
            if x86_src is None:
                i += 1
                continue
            x86_off = x86_src - text_rva
            if x86_off < 0 or x86_off + 5 > len(text_data):
                i += 1
                continue
            if text_data[x86_off] != 0xE8:
                i += 1
                continue
            x86_rel = struct.unpack_from('<i', text_data, x86_off + 1)[0]
            x86_tgt = (x86_src + 5 + x86_rel) & 0xFFFFFFFF
            expected = rva_map.get(x86_tgt)
            if expected is None:
                i += 1
                continue
            if not self._x64_entry_prologue_ok(out, expected):
                i += 1
                continue
            # Fix if current target doesn't match x86 source
            if cur_tgt == expected:
                i += 1
                continue
            # Only redirect if current target is clearly bad OR is a
            # thunk (short wrapper that just calls another function).
            # Redirecting a thunk to the materialized real function is
            # always safe — thunks have no side effects.
            bad = (self._pure_mapping_is_swallowed_slot(out, cur_tgt)
                   or self._pure_is_corrupt_x86_hybrid(out, cur_tgt)
                   or not self._x64_entry_prologue_ok(out, cur_tgt))
            is_thunk = False
            if not bad and cur_tgt + 24 <= len(out):
                # Thunk pattern: push r13; mov r13,rsp; sub rsp,0x20;
                # and rsp,-16; call X; mov rsp,r13; pop r13; ret
                # Only match standalone thunks (ending with ret),
                # not inline wrappers that continue to more code.
                if (out[cur_tgt:cur_tgt+2] == b'\x41\x55'          # push r13
                        and out[cur_tgt+2:cur_tgt+5] == b'\x49\x89\xe5'  # mov r13,rsp
                        and out[cur_tgt+5:cur_tgt+13] == b'\x48\x83\xec\x20\x48\x83\xe4\xf0'):
                    # Scan forward for the epilogue + ret
                    for scan in range(cur_tgt+18, min(cur_tgt+80, len(out)-3)):
                        if (out[scan:scan+3] == b'\x4c\x89\xec'      # mov rsp,r13
                                and out[scan+3:scan+5] == b'\x41\x5d'  # pop r13
                                and out[scan+5] == 0xC3):               # ret
                            is_thunk = True
                            break
            if not bad and not is_thunk:
                i += 1
                continue
            struct.pack_into('<i', out, i + 1, expected - (i + 5))
            fixed += 1
            i += 5
        return fixed

    def _materialize_missing_functions(self, out: bytearray,
                                        rva_map: Dict[int, int],
                                        text_data: bytes,
                                        text_rva: int) -> int:
        """Translate small x86 helper functions that were never emitted.

        Some init/helper functions are not reached by the main translation
        pass and calls to them are wrongly snapped to unrelated code.
        This function finds the gap between .text and the next section,
        translates missing x86 functions into it, and updates the RVA map
        so CALL-validation can fix the targets.  Bounded by a total byte
        budget so abs-load helpers (many ``movabs`` expansions) still fit.
        """
        if not text_data or len(out) < 0x1000:
            return 0
        MAX_FNS = 48
        MAX_CHUNK = 4096
        MAX_TOTAL = 0x18000  # 96 KiB append budget
        missing: Dict[int, int] = {}
        total_added = 0

        # Prefer call targets whose recorded slot is clearly wrong (abs-load
        # helpers collapsed onto align stubs, etc.) over first-seen E8 order.
        candidates: List[int] = []
        seen_tgt: Set[int] = set()
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_src = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            x86_tgt = (x86_src + 5 + rel) & 0xFFFFFFFF
            if x86_tgt in seen_tgt:
                continue
            seen_tgt.add(x86_tgt)
            candidates.append(x86_tgt)

        def _need_materialize(x86_tgt: int) -> bool:
            existing = rva_map.get(x86_tgt)
            if existing is None or not (0 <= existing < len(out)):
                return True
            # Entry/interior consistency: a nearby mapped byte of the SAME
            # function must map near the entry.  A large gap means the entry
            # tip landed in a stale copy / another function (cmd parser
            # 0x13A9C → 0x57E98 while body 0x13A9D → 0x26189 remat copy;
            # print fn 0x158EE → 0x5B38C while 0x15901 → 0x2A7DE) — force
            # a fresh chunk.
            for _d in range(1, 0x40):
                nxt = rva_map.get((x86_tgt + _d) & 0xFFFFFFFF)
                if nxt is None:
                    continue
                if (0 <= nxt < len(out) and 0 <= existing < len(out)
                        and abs(nxt - existing) > 0x200):
                    if os.environ.get('DBG_MMF') \
                            and x86_tgt in (0x12E14, 0x12E30, 0x13A9C,
                                            0x158EE):
                        print(f"[MMF-DBG] entry/interior split "
                              f"x86=0x{x86_tgt:X} entry=0x{existing:X} "
                              f"next(+{_d:#x})=0x{nxt:X}")
                    return True
                break
            sane = self._pure_mapped_entry_sane(
                out, existing, x86_tgt, text_data, text_rva)
            if os.environ.get('DBG_MMF') and x86_tgt in (0x12E14, 0x12E30):
                print(f"[MMF-DBG] _need_materialize x86=0x{x86_tgt:X} "
                      f"existing=0x{existing:X} sane={sane}")
            if sane:
                return False
            return True

        # Try cheap re-snap before spending budget on re-translation.
        for x86_tgt in list(candidates):
            if not _need_materialize(x86_tgt):
                continue
            sane = self._pure_find_sane_entry_for_x86(
                out, x86_tgt, rva_map, text_data, text_rva)
            if os.environ.get('DBG_MMF') and x86_tgt in (0x12E14, 0x12E30):
                print(f"[MMF-DBG] x86_tgt=0x{x86_tgt:X} need_mat=1 "
                      f"recorded=0x{rva_map.get(x86_tgt, 0):X} "
                      f"re-snap=0x{sane or 0:X}")
            if sane is not None:
                rva_map[x86_tgt] = sane

        # Unsound mappings first so the budget is spent on real holes.
        ranked = sorted(
            candidates,
            key=lambda t: (0 if _need_materialize(t) else 1, t))

        for x86_tgt in ranked:
            if len(missing) >= MAX_FNS or total_added >= MAX_TOTAL:
                break
            if not _need_materialize(x86_tgt):
                continue
            if self._is_alloca_probe_rva(x86_tgt):
                continue
            tgt_off = x86_tgt - text_rva
            if tgt_off < 0 or tgt_off + 4 > len(text_data):
                continue
            end_off = min(tgt_off + 128, len(text_data))
            ret_at = None
            for s in range(tgt_off, end_off):
                if text_data[s] in (0xC3, 0xC2):
                    ret_at = s
                    break
            if ret_at is None:
                # No early RET: the 128-byte window would cut the function
                # mid-body and the truncated chunk falls through into the
                # NEXT translated function with garbage args (cmd 0x53C9
                # chunk → fallthrough into 0x5630 → read @ -1 crash).
                # Extend to the next real boundary or skip entirely.
                for s in range(tgt_off + 128,
                               min(tgt_off + 0x300, len(text_data))):
                    if text_data[s] in (0xC3, 0xC2):
                        ret_at = s
                        break
                if ret_at is None:
                    continue
            end_off = ret_at + (3 if text_data[ret_at] == 0xC2 else 1)
            # Dual-exit predicates: keep ``mov al,1; ret`` after the first RET
            # so forward Jccs resolve (cmd e846).
            end_off = self._extend_end_for_dual_exit(
                text_data[tgt_off:], end_off - tgt_off) + tgt_off
            end_off = min(end_off, tgt_off + 0x300, len(text_data))
            func_bytes = text_data[tgt_off:end_off]
            if len(func_bytes) < 4:
                continue
            try:
                local_deferred: List[Tuple[int, int, str]] = []
                chunk, chunk_map = self._translate_function(
                    x86_tgt, func_bytes, False, 0,
                    chunk_base=0, section_rva=text_rva,
                    global_rva_map=rva_map, deferred_branches=local_deferred)
            except Exception:
                continue
            if not chunk or len(chunk) > MAX_CHUNK:
                continue
            if total_added + len(chunk) > MAX_TOTAL:
                break
            base = len(out)
            out += chunk
            out += b'\x90' * ((4 - len(out) % 4) % 4)
            self._note_code_span(base, len(chunk))
            rva_map[x86_tgt] = base
            # Prefer the real body start when a prefix epilogue was emitted.
            func_entry_va = self.old_base + x86_tgt
            body_off = chunk_map.get(func_entry_va, 0) if chunk_map else 0
            if body_off and (b'\xc3' in chunk[:body_off] or b'\xc2' in chunk[:body_off]):
                rva_map[x86_tgt] = base + body_off
            for old_va, rel in (chunk_map or {}).items():
                old_r = (old_va - self.old_base) & 0xFFFFFFFF
                if old_r not in rva_map:
                    rva_map[old_r] = base + rel
                elif self._pure_off_in_zero_hole(out, rva_map[old_r]):
                    rva_map[old_r] = base + rel
            # Resolve placeholders emitted inside this chunk (chunk_base was 0).
            if local_deferred:
                adj = [(base + po, trva, ft) for (po, trva, ft) in local_deferred]
                self._resolve_deferred_branches(out, rva_map, adj)
            missing[x86_tgt] = rva_map[x86_tgt]
            total_added += len(chunk)
        return len(missing)

    def _pure_retarget_calls_from_stale_map(
            self, out: bytearray, rva_map: Dict[int, int],
            old_map: Dict[int, int], text_data: bytes, text_rva: int) -> int:
        """Re-point x64 calls whose x86 target was just re-materialized.

        After a late ``_materialize_missing_functions`` re-run, entries whose
        old slots were overwritten by later chunks point to fresh code.
        Existing E8 calls still target the stale slot (cmd OOM reporter:
        14 callers → 0x36DE5 inside another chunk).  For every x86 call site
        whose target changed, retarget the x64 E8 near the mapped source
        position when it still points at the old slot.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        changed = {k: rva_map[k] for k, v in old_map.items()
                   if rva_map.get(k) is not None and rva_map[k] != v}
        if not changed:
            return 0
        n = len(out)

        def _to_off(v: int) -> int:
            return v if 0 <= v < n else v - text_rva

        src_by_tgt: Dict[int, List[int]] = {}
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x_src = (text_rva + off) & 0xFFFFFFFF
            x_tgt = (x_src + 5
                     + struct.unpack_from('<i', text_data, off + 1)[0]) & 0xFFFFFFFF
            if x_tgt in changed:
                src_by_tgt.setdefault(x_tgt, []).append(x_src)
        fixed = 0
        for x_tgt, new_v in changed.items():
            old_v = old_map.get(x_tgt)
            if old_v is None:
                continue
            old_off = _to_off(old_v)
            new_off = _to_off(new_v)
            if not (0 <= new_off < n) or not (0 <= old_off < n):
                continue
            per_key = 0
            for x_src in src_by_tgt.get(x_tgt, ()):
                pos = rva_map.get(x_src)
                if pos is None:
                    continue
                lo = max(0, _to_off(pos) - 0x20)
                hi = min(n - 5, _to_off(pos) + 0x20)
                for p in range(lo, hi + 1):
                    if out[p] != 0xE8:
                        continue
                    cur = p + 5 + struct.unpack_from('<i', out, p + 1)[0]
                    if cur == old_off:
                        struct.pack_into('<i', out, p + 1, new_off - (p + 5))
                        fixed += 1
                        per_key += 1
                        break
            # Anchored retarget found nothing (collapsed source positions):
            # sweep the whole blob for calls still targeting the old slot.
            # cmd print fn: 142 callers → 0x5B38C whose x86 anchors collapsed.
            if per_key == 0:
                for p in range(n - 5):
                    if out[p] != 0xE8:
                        continue
                    cur = p + 5 + struct.unpack_from('<i', out, p + 1)[0]
                    if cur == old_off:
                        struct.pack_into('<i', out, p + 1,
                                         new_off - (p + 5))
                        fixed += 1
        return fixed

    def _pure_fix_calls_into_implausible_entries(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Re-derive E8 calls whose current target is not a function entry.

        Map updates can leave existing calls pointing at stale slots (cmd
        OOM reporter: 14 callers → 0x36DE5, a byte inside another chunk,
        while rva_map already points 0x12E14 at its fresh chunk).  For each
        x64 E8 whose target fails the entry-plausibility gate, find the x86
        source via the nearest rva_map value, recompute the x86 target from
        the original rel32, and retarget when the mapped value is plausible.
        """
        if not self._cmd_no_hacks or not rva_map or not text_data:
            return 0
        if not HAS_CAPSTONE:
            return 0
        n = len(out)

        def _to_off(v: int) -> int:
            return v if 0 <= v < n else v - text_rva

        # x64 offset → x86 rva (nearest-by-value reverse map, offset form).
        rev: Dict[int, int] = {}
        for x_rva, v in rva_map.items():
            o = _to_off(v)
            if 0 <= o < n and o not in rev:
                rev[o] = x_rva
        rev_keys = sorted(rev)
        if not rev_keys:
            return 0
        import bisect
        fixed = 0
        mapped_offsets = {_to_off(v) for v in rva_map.values()}
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = True
        starts = set()
        for ins in md.disasm(bytes(out), 0):
            starts.add(ins.address)
        for p in sorted(starts):
            if p + 5 > n or out[p] != 0xE8:
                continue
            cur = p + 5 + struct.unpack_from('<i', out, p + 1)[0]
            if not (0 <= cur < n):
                continue
            # Nearest mapped source position within ±0x20.
            idx = bisect.bisect_left(rev_keys, p)
            x_src = None
            for cand_idx in (idx - 1, idx, idx + 1):
                if 0 <= cand_idx < len(rev_keys):
                    o = rev_keys[cand_idx]
                    if abs(o - p) <= 0x20:
                        x_src = rev[o]
                        break
            if x_src is None:
                continue
            xo = x_src - text_rva
            if xo < 0 or xo + 5 > len(text_data) or text_data[xo] != 0xE8:
                continue
            x_tgt = (x_src + 5
                     + struct.unpack_from('<i', text_data, xo + 1)[0]) & 0xFFFFFFFF
            new_v = rva_map.get(x_tgt)
            if new_v is None:
                continue
            new_off = _to_off(new_v)
            if not (0 <= new_off < n) or new_off == cur:
                continue
            # Repair when the current target does NOT match the x86 entry
            # shape of x_tgt (mid-chunk bytes, epilogue tails, …) OR when it
            # does match but is a STALE COPY: an unmapped duplicate of the
            # function (cmd parser: calls kept entering the old 0x5791C copy
            # while rva_map authoritatively places the body at the remat
            # chunk).  Unmapped-but-entry-shaped targets are never heal-built
            # stubs (those never match the x86 head), so snapping them to the
            # authoritative mapped entry is safe.
            cur_sane = self._pure_mapped_entry_sane(
                out, cur, x_tgt, text_data, text_rva)
            if cur_sane and cur in mapped_offsets:
                continue
            # Destination must be a plausible entry; x86 heads that open with
            # CALL translate with an align-stub lead, so also accept a CALL
            # instruction within the first 0x40 bytes of the destination.
            if not self._pure_call_target_plausible(out, new_off):
                continue
            win = out[new_off:new_off + 0x40]
            has_call = (b'\xe8' in win or b'\xff\xd0' in win
                        or b'\xff\xd1' in win or b'\xff\xd2' in win
                        or b'\xff\xd3' in win or b'\xff\xd4' in win
                        or b'\xff\xd5' in win or b'\xff\xd6' in win
                        or b'\xff\xd7' in win)
            if not has_call and not self._pure_mapped_entry_sane(
                    out, new_off, x_tgt, text_data, text_rva):
                continue
            struct.pack_into('<i', out, p + 1, new_off - (p + 5))
            fixed += 1
        return fixed

    def _pure_fix_single_e8_stale_copy_calls(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Re-derive E8 calls inside stale first-pass copies of functions.

        cmd parser: the authoritative remat chunk is a zero hole and the
        live copy (0x5791C) is the first-pass translation whose internal
        ``call wcschr`` was mis-patched to the malloc wrapper (0x19F54
        instead of rva_map[0x195D2]=0x320B4) because the enclosing-fn
        pairing for stub restore found the neighbouring wrapper, not the
        parser (its entry is not in the map).

        Universal: for every x64 E8 whose nearest mapped anchor belongs to
        an x86 function with EXACTLY ONE x86 E8, retarget the call to the
        mapped value of that one x86 target.  Multi-E8 functions are
        skipped (ordering ambiguity).
        """
        if not self._cmd_no_hacks or not rva_map or not text_data:
            return 0
        if not HAS_CAPSTONE:
            return 0
        n = len(out)

        def _to_off(v: int) -> int:
            return v if 0 <= v < n else v - text_rva

        fn_entries = sorted(getattr(self, '_fn_entry_rvas', set()) or set())
        if not fn_entries:
            return 0
        rev: Dict[int, int] = {}
        for xr, v in rva_map.items():
            o = _to_off(v)
            if 0 <= o < n and o not in rev:
                rev[o] = xr
        rev_keys = sorted(rev)
        if not rev_keys:
            return 0
        import bisect
        fixed = 0
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.skipdata = True
        starts = set()
        for ins in md.disasm(bytes(out), 0):
            starts.add(ins.address)
        for p in sorted(starts):
            if p + 5 > n or out[p] != 0xE8:
                continue
            idx = bisect.bisect_left(rev_keys, p) - 1
            if idx < 0:
                continue
            o = rev_keys[idx]
            if p - o > 0x400:
                continue
            x_anchor = rev[o]
            e = bisect.bisect_right(fn_entries, x_anchor) - 1
            if e < 0:
                continue
            entry = fn_entries[e]
            nxt_entry = (fn_entries[e + 1]
                         if e + 1 < len(fn_entries) else 0x20000)
            if x_anchor - entry > 0x3000:
                continue
            lo_off = entry - text_rva
            hi_off = min(nxt_entry - text_rva, len(text_data) - 5)
            if lo_off < 0 or hi_off <= lo_off:
                continue
            x_tgt = None
            cnt = 0
            for off in range(lo_off, hi_off):
                if text_data[off] != 0xE8:
                    continue
                cnt += 1
                if cnt > 1:
                    break
                x_tgt = (entry + (off - lo_off) + 5
                         + struct.unpack_from('<i', text_data, off + 1)[0]) & 0xFFFFFFFF
            if cnt != 1 or x_tgt is None:
                continue
            want = rva_map.get(x_tgt)
            if want is None:
                continue
            wo = _to_off(want)
            if not (0 <= wo < n):
                continue
            cur = p + 5 + struct.unpack_from('<i', out, p + 1)[0]
            if cur == wo or not (0 <= cur < n):
                continue
            if not self._pure_call_target_plausible(out, wo):
                continue
            struct.pack_into('<i', out, p + 1, wo - (p + 5))
            fixed += 1
        return fixed

    def _fix_thunk_arg_preservation(self, out: bytearray) -> int:
        """Fix align-wrapper thunks that clobber RCX/RDX across calls.

        Pattern::
            push r13 / mov r13,rsp / sub rsp,0x20 / and rsp,-16
            call <target>
            mov rsp,r13 / pop r13 / ret

        The ``sub rsp,0x20`` (4 bytes) is removed and replaced with
        ``push rcx; push rdx`` (2 bytes) at the top and
        ``pop rdx; pop rcx`` (2 bytes) at the bottom, keeping the
        thunk the same total size while preserving the first two
        integer argument registers.
        """
        AW_PUSH_R13 = b'\x41\x55'               # push r13
        AW_MOV_R13  = b'\x49\x89\xe5'           # mov r13, rsp
        AW_SUB      = b'\x48\x83\xec\x20'       # sub rsp, 0x20
        AW_AND      = b'\x48\x83\xe4\xf0'       # and rsp, -16
        AW_EPI_MOV  = b'\x4c\x89\xec'           # mov rsp, r13
        AW_EPI_POP  = b'\x41\x5d'               # pop r13

        fixed = 0
        i = 0
        while i < len(out) - 30:
            # Match align-wrapper prologue + sub rsp + and rsp
            if out[i:i+2] != AW_PUSH_R13:
                i += 1
                continue
            if out[i+2:i+5] != AW_MOV_R13:
                i += 1
                continue
            if out[i+5:i+9] != AW_SUB:
                i += 1
                continue
            if out[i+9:i+13] != AW_AND:
                i += 1
                continue
            # After and rsp,-16, expect a CALL (E8)
            call_pos = i + 13
            if call_pos + 5 > len(out) or out[call_pos] != 0xE8:
                i += 1
                continue
            # Find the matching epilogue
            rel = struct.unpack_from('<i', out, call_pos + 1)[0]
            after_call = call_pos + 5
            # Scan for mov rsp,r13; pop r13; ret after the call
            epi_pos = after_call
            max_scan = min(64, len(out) - after_call)
            found_epi = -1
            for j in range(max_scan - 5):
                if (out[after_call + j:after_call + j + 3] == AW_EPI_MOV
                        and out[after_call + j + 3:after_call + j + 5] == AW_EPI_POP
                        and after_call + j + 5 < len(out)
                        and out[after_call + j + 5] == 0xC3):   # ret
                    found_epi = after_call + j
                    break
            if found_epi < 0:
                i += 1
                continue
            # Found a complete thunk: push r13..ret
            # Remove sub rsp,0x20 (4 bytes at i+5) and replace with:
            #   push rcx (0x51) + push rdx (0x52) at top
            #   pop rdx (0x5A) + pop rcx (0x59) at bottom (before ret)
            out[i+5:i+9] = b'\x51\x52\x90\x90'   # push rcx; push rdx; nop; nop
            # Insert pop rdx; pop rcx before ret
            ret_pos = found_epi + 5               # ret is 2 bytes after mov rsp,r13; pop r13
            out[ret_pos - 2:ret_pos] = b'\x5a\x59'  # pop rdx; pop rcx
            fixed += 1
            i = ret_pos + 1
        return fixed

    def _fix_mistranslated_data_spans(self, out: bytearray,
                                       rva_map: Dict[int, int],
                                       text_data: bytes,
                                       text_rva: int) -> int:
        """Universal: for every rva_map entry whose x86 source is inside the
        text section, compare the x86 bytes with the x64 bytes at the mapped
        offset.  When the x86 bytes do NOT look like valid x86 instructions
        (i.e. they are data — strings, jump tables, padding interleaved with
        code), copy the original x86 bytes verbatim into the x64 blob.

        This catches data that was incorrectly fed through the instruction
        translator, which emitted different x64 bytes for what should have
        been a verbatim data copy.

        IMPORTANT: This only overwrites existing translated bytes — it does
        NOT append new data or change blob layout.  That makes it safe as a
        post-processing pass.  A more complete solution would skip translation
        of data spans entirely during Stage 2/3, but that requires deeper
        pipeline integration."""
        if text_data is None or not rva_map:
            return 0
        fixed = 0
        # Collect spans of rva_map entries sorted by x64 offset
        entries = [(x64_off, x86_rva) for x86_rva, x64_off in rva_map.items()
                   if text_rva <= x86_rva < text_rva + len(text_data)
                   and 0 <= x64_off < len(out)]
        if not entries:
            return 0
        entries.sort()
        # Process contiguous spans
        i = 0
        while i < len(entries):
            x64_off, x86_rva = entries[i]
            x86_off = x86_rva - text_rva
            # Find contiguous span in both x86 and x64
            j = i + 1
            while j < len(entries):
                next_x64, next_x86 = entries[j]
                if (next_x64 == entries[j-1][0] + 1 and
                        next_x86 == entries[j-1][1] + 1):
                    j += 1
                else:
                    break
            span_len = j - i
            if span_len < 4:  # too small to be meaningful data
                i = j
                continue
            # Check if the x86 bytes look like code or data
            x86_bytes = text_data[x86_off:x86_off + span_len]
            x64_bytes = out[x64_off:x64_off + span_len]
            if x86_bytes == x64_bytes:
                i = j
                continue  # already matches, no fix needed
            # Heuristic: if more than 25% of the bytes are zero or high-entropy,
            # treat as data.  Code has specific patterns (opcodes 0x50-0x5F,
            # 0x68, 0x6A, 0x74-0x7F, 0x80-0x8F, 0xE8-0xE9, 0xEB, etc.)
            # Note: 0xFF is omitted — EH3 sentinels / UTF-16 high bytes must
            # not inflate the "code" score and skip verbatim copy.
            code_bytes = sum(1 for b in x86_bytes
                           if b in (0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
                                    0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,
                                    0x68,0x6A,0x70,0x71,0x72,0x73,0x74,0x75,
                                    0x76,0x77,0x78,0x79,0x7A,0x7B,0x7C,0x7D,
                                    0x7E,0x7F,0x80,0x81,0x83,0x85,0x89,0x8B,
                                    0x8D,0x8F,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,
                                    0xBE,0xBF,0xC3,0xC7,0xE8,0xE9,0xEB,0xF3,
                                    0xF6,0xF7))
            zero_bytes = sum(1 for b in x86_bytes if b == 0)
            if code_bytes < span_len * 0.4 or zero_bytes > span_len * 0.15:
                # Looks like data — copy original bytes verbatim
                out[x64_off:x64_off + span_len] = x86_bytes
                fixed += span_len
            i = j
        return fixed

    def _fix_mistranslated_scope_tables(self, out: bytearray,
                                           rva_map: Dict[int, int],
                                           text_data: bytes,
                                           text_rva: int) -> int:
        """Overwrite mapped EH3 scope tables that no longer match x86 bytes.

        Only touches slots that already look like a scope sentinel (or a
        truncated one). Never blast raw EH3 bytes into UTF-16 identity maps —
        those are rematerialized by ``_force_rematerialize_scope_tables``.
        """
        if text_data is None or self.pe is None:
            return 0
        fixed = 0
        for start_rva, size in _scope_table_spans(text_data, text_rva, self.pe):
            mapped = rva_map.get(start_rva)
            if mapped is None or mapped + size > len(out):
                continue
            off = start_rva - text_rva
            raw = text_data[off:off + size]
            if raw[:4] != b'\xff\xff\xff\xff':
                continue
            cur = bytes(out[mapped:mapped + min(4, size)])
            # Skip UTF-16 / unrelated identity maps
            if cur != b'\xff\xff\xff\xff' and cur[:2] != b'\xff\xff':
                continue
            if bytes(out[mapped:mapped + size]) == raw:
                self._scope_table_old_rva[mapped] = start_rva
                if not any(s == mapped for s, _ in self._scope_table_out_ranges):
                    self._scope_table_out_ranges.append((mapped, size))
                continue
            out[mapped:mapped + size] = raw
            self._scope_table_old_rva[mapped] = start_rva
            if not any(s == mapped for s, _ in self._scope_table_out_ranges):
                self._scope_table_out_ranges.append((mapped, size))
            fn_off = self._seh_scope_reg_fn.get(start_rva)
            self._patch_scope_table_entries(out, mapped, size, start_rva, fn_off)
            fixed += size
        return fixed

    def _cf_repair_epilogue_branch_targets(self, out: bytearray,
                                           rva_map: Dict[int, int]) -> int:
        """Patch branches that aim at stale offsets for x86 epilogue labels."""
        cf = self._x86_cf
        if not cf or not cf.epilogue_labels:
            return 0
        fixed = 0
        for ep_rva in cf.epilogue_labels:
            stale_off = rva_map.get(ep_rva)
            slot = self._materialize_epilogue_label(out, rva_map, ep_rva)
            if slot is None:
                continue
            # Only repair stale rva_map slots — not sibling pops in the same tail.
            if stale_off is None or stale_off == slot:
                continue
            bad = {stale_off}
            for i in range(len(out) - 5):
                if out[i] == 0xE8:
                    rel = struct.unpack_from('<i', out, i + 1)[0]
                    tgt = i + 5 + rel
                    if tgt in bad:
                        struct.pack_into('<i', out, i + 1, slot - (i + 5))
                        fixed += 1
                elif out[i] == 0xE9:
                    rel = struct.unpack_from('<i', out, i + 1)[0]
                    tgt = i + 5 + rel
                    if tgt in bad:
                        struct.pack_into('<i', out, i + 1, slot - (i + 5))
                        fixed += 1
                elif (out[i] == 0x0F and i + 6 < len(out)
                      and 0x80 <= out[i + 1] <= 0x8F):
                    rel = struct.unpack_from('<i', out, i + 2)[0]
                    tgt = i + 6 + rel
                    if tgt in bad:
                        struct.pack_into('<i', out, i + 2, slot - (i + 6))
                        fixed += 1
        return fixed

    def _pure_fixup_swallowed_epilogue_pop(self, out: bytearray,
                                           rva_map: Dict[int, int],
                                           text_data: bytes,
                                           text_rva: int) -> int:
        """Patch inline ``nop; ret`` tails that swallowed ``pop callee-save``.

        Mega-chunk layout can place the *next* function's prologue on the
        epilogue POP slot while a healed copy at a branch target keeps the
        real ``pop r64; ret`` (cmd 0x1089F).  Fall-through paths then execute
        ``mov reg,1; nop; ret`` with an unbalanced entry ``push rsi``.  Scan
        x86 code bytes for ``pop ebx/esi/edi/ebp; ret/retn`` (linear disasm
        of the whole .text misses many sites when data is interleaved).
        """
        if not self._cmd_no_hacks:
            return 0
        # x86 single-byte POP r32 opcodes
        pop_map = {
            0x5B: 'rbx', 0x5D: 'rbp', 0x5E: 'rsi', 0x5F: 'rdi',
        }
        fixed = 0
        n = len(text_data)
        off = 0
        while off < n - 1:
            reg = pop_map.get(text_data[off])
            if reg is None:
                off += 1
                continue
            nxt = text_data[off + 1]
            if nxt == 0xC3:
                ret_size = 1
            elif nxt == 0xC2 and off + 3 < n:
                ret_size = 3
            else:
                off += 1
                continue
            x86_pop = text_rva + off
            x86_ret = text_rva + off + 1
            pop_op = self._CALLEE_POP_OPCODE[reg]
            anchor = rva_map.get(x86_ret)
            if anchor is not None:
                lo = max(0, anchor - 24)
                hi = min(len(out), anchor + 24)
                for ret_pos in range(lo, hi):
                    if out[ret_pos] == 0xC3:
                        slot = ret_pos - 1
                    elif (ret_pos + 2 < len(out) and out[ret_pos] == 0xC2
                          and out[ret_pos + 2] == 0x00):
                        slot = ret_pos - 1
                    else:
                        continue
                    if slot < 0 or out[slot] != 0x90:
                        continue
                    # Only patch the known swallowed-tail shape:
                    # ``push 1; pop eax`` → ``mov rax,1`` then swallowed ``pop esi``.
                    if not (slot >= 7
                            and out[slot - 7:slot] == b'\x48\xc7\xc0\x01\x00\x00\x00'):
                        continue
                    out[slot] = pop_op
                    rva_map[x86_pop] = slot
                    fixed += 1
                    break
            off += 1 + ret_size
        return fixed

    def _pure_final_layout_heal(self, out: bytearray, text_data: bytes,
                                text_rva: int) -> int:
        """Run swallowed-entry heal and call repair after all late post-patches."""
        if not self._cmd_no_hacks or not self._fn_entry_rvas:
            return 0
        self._pure_heal_text = text_data
        self._pure_heal_text_rva = text_rva
        heal_entries = self._pure_heal_entry_rvas(
            out, self.rva_map, text_data, text_rva)
        healed = self._pure_heal_swallowed_entries(
            out, self.rva_map, text_data, text_rva, heal_entries)
        if not healed:
            # Still repair calls / sanity even when no new blobs were appended.
            pass
        elif healed:
            print(f"        Pure final swallowed-entry heal: {healed}")
        reconciled = self._pure_reconcile_swallowed_rva_map(
            out, self.rva_map, text_data, text_rva)
        if reconciled:
            print(f"        Pure swallowed rva_map reconciles: {reconciled}")
        epi_pop = self._pure_fixup_swallowed_epilogue_pop(
            out, self.rva_map, text_data, text_rva)
        if epi_pop:
            print(f"        Pure swallowed epilogue POP fixes: {epi_pop}")
        # ── Materialize missing x86 helper functions ──
        # Some small init helpers were never reached by the main
        # translation pass.  Calls to them are wrongly snapped to
        # unrelated code.  Translate them now and append to the blob
        # (section overlap guard in _build_pe64_from_layout handles growth).
        materialized = self._materialize_missing_functions(
            out, self.rva_map, text_data, text_rva)
        if materialized:
            print(f"        Pure materialized missing functions: {materialized}")
        # Materialize epilogue labels *before* Jcc patch / CF repair so
        # scrambled remnants (cmd 0x24DF) get trampolines first.
        if self._x86_cf and self._x86_cf.epilogue_labels:
            mat_epi = self._pure_materialize_call_epilogues(out, self.rva_map)
            if mat_epi:
                print(f"        Pure materialized call epilogues: {mat_epi}")
            for ep_rva in self._x86_cf.epilogue_labels:
                if ep_rva not in self._x86_cf.branch_targets:
                    continue
                self._materialize_epilogue_label(out, self.rva_map, ep_rva)
        jcc_ph = self._pure_patch_jcc_placeholders(
            out, self.rva_map, text_data, text_rva)
        if jcc_ph:
            print(f"        Pure unresolved Jcc placeholder patches: {jcc_ph}")
        xor_jcc = self._pure_retarget_xor_jmp_epilogue_jccs(
            out, self.rva_map, text_data, text_rva)
        if xor_jcc:
            print(f"        Pure xor-jmp epilogue Jcc retargets: {xor_jcc}")
        chk_fixed = self._pure_fix_chkstk_prologue_entries(
            out, self.rva_map, text_data, text_rva)
        if chk_fixed:
            print(f"        Pure chkstk-prologue entry fixes: {chk_fixed}")
        if not os.environ.get('DISABLE_CHKSTK'):
            chk_call_fixed = self._pure_fix_broken_chkstk_calls(out)
            if chk_call_fixed:
                print(f"        Pure broken chkstk-call repairs: {chk_call_fixed}")
        cf_epi = self._cf_repair_epilogue_branch_targets(out, self.rva_map)
        if cf_epi:
            print(f"        Pure CF epilogue branch repairs: {cf_epi}")
        if self._x86_cf and self._x86_cf.epilogue_labels:
            self._epilogue_snap_map = self._build_epilogue_head_snap_map(self.rva_map, out)
            epi_snapped = self._snap_branch_targets_to_epilogue_heads(
                out, self._epilogue_snap_map)
            if epi_snapped:
                print(f"        Pure epilogue-head branch snaps: {epi_snapped}")
            # Universal: redirect branches that land inside materialized
            # ``pop...; add rsp; ret`` epilogues to the function body past ret.
            past_snapped = self._snap_branches_past_epilogues(out)
            if past_snapped:
                print(f"        Pure epilogue-past branch snaps: {past_snapped}")
            # Universal: detect and fix mistranslated data-in-code spans
            # (strings, jump tables, FP constants embedded in .text that
            # were incorrectly run through the instruction translator).
            data_fixed = self._fix_mistranslated_data_spans(
                out, self.rva_map, text_data, text_rva)
            if data_fixed:
                print(f"        Pure mistranslated data spans fixed: {data_fixed} bytes")
            scope_bytes = self._fix_mistranslated_scope_tables(
                out, self.rva_map, text_data, text_rva)
            if scope_bytes:
                print(f"        Pure mistranslated EH3 scope tables: {scope_bytes} bytes")
        self._resolve_deferred_branches(out, self.rva_map, [])
        pure_calls = self._pure_repair_call_targets(
            out, self.rva_map, text_data, text_rva)
        if pure_calls:
            print(f"        Pure post-heal CALL re-resolve: {pure_calls}")
        pure_x86_calls = self._pure_repair_calls_from_x86_source(
            out, self.rva_map, text_data, text_rva)
        if pure_x86_calls:
            print(f"        Pure x86-anchored CALL repairs: {pure_x86_calls}")
        pure_corr = self._pure_correlate_call_targets(
            out, self.rva_map, text_data, text_rva)
        if pure_corr:
            print(f"        Pure ordered CALL correlations: {pure_corr}")
        restored_calls = self._pure_restore_nopped_align_calls(
            out, self.rva_map, text_data, text_rva)
        if restored_calls:
            print(f"        Pure post-heal restored align calls: {restored_calls}")
        self._repair_unfixed_calls(out, self.rva_map, text_data, text_rva)
        fn_calls = self._snap_calls_to_function_entries(out, self.rva_map)
        if fn_calls:
            print(f"        Pure post-heal CALL entry snaps: {fn_calls}")
        epi_calls = self._pure_snap_calls_to_epilogue_targets(
            out, self.rva_map, text_data, text_rva)
        if epi_calls:
            print(f"        Pure post-heal epilogue CALL snaps: {epi_calls}")
        align_calls = self._pure_repair_all_align_stub_calls(
            out, self.rva_map, text_data, text_rva)
        if align_calls:
            print(f"        Pure post-heal align-stub CALL repairs: {align_calls}")
        self_calls = self._pure_repatch_align_stub_self_calls(
            out, self.rva_map, text_data, text_rva)
        if self_calls:
            print(f"        Pure post-heal align self-CALL fixes: {self_calls}")
        self._repair_unfixed_calls(out, self.rva_map, text_data, text_rva)
        self._reconcile_rva_map_prologues(out, self.rva_map)
        # ── Final safety-net: force-correct mov ebp,esp → mov rbp,rsp ──
        force_fixed = self._force_fix_mov_ebp_entries(out, self.rva_map,
                                                       text_data, text_rva)
        if force_fixed:
            print(f"        Pure force-fixed mov-ebp→mov-rbp entries: "
                  f"{force_fixed}")
        # ── Final safety-net: fix missing pop r13 after align stub ──
        pop13_fixed = self._fix_missing_pop_r13_after_align(out)
        if pop13_fixed:
            print(f"        Pure fixed missing pop-r13 in align stubs: "
                  f"{pop13_fixed}")
        if getattr(self, '_pure_heal_text', None):
            epi = self._pure_fix_jmp_over_epilogue(
                out, self._pure_heal_text, self._pure_heal_text_rva)
            if epi:
                print(f"        Pure post-heal jmp→epilogue fixes: {epi}")
        return max(healed, pure_calls)

    def _reconcile_seh_scope_pushes(self, out: bytearray, rva_map: Dict[int, int],
                                    text_rva: int) -> int:
        """Point SEH ``push scope`` at the materialized ``ff ff ff ff`` blob, not a nearby alias."""
        self._call_target_offs = None
        scope_off: Dict[int, int] = {}
        for base, old_rva in self._scope_table_old_rva.items():
            if 0 <= base < len(out) and self._valid_scope_sentinel(out, base):
                scope_off[old_rva] = base
        for old_rva, off in rva_map.items():
            if old_rva in scope_off:
                continue
            if 0 <= off < len(out) and self._valid_scope_sentinel(out, off):
                scope_off[old_rva] = off
        for start, size in self._scope_table_out_ranges:
            if (start < len(out) and self._valid_scope_sentinel(out, start)
                    and start not in scope_off.values()):
                old = self._scope_table_old_rva.get(start)
                if old is not None:
                    scope_off[old] = start
                    continue
                for old_rva, off in rva_map.items():
                    if off == start:
                        scope_off[old_rva] = start
                        break

        def _match_x86_scope(blob_off: int, want_old: Optional[int]) -> bool:
            if want_old is None:
                return False
            return self._scope_sentinel_matches_x86(out, blob_off, want_old)

        fixed = 0
        i = 0
        img_end = self.old_base + self.pe.image_size
        while i < len(out) - 24:
            if not (out[i] == 0x6A and out[i + 1] == 0xFF
                    and out[i + 2] == 0x48 and out[i + 3] == 0xB8):
                i += 1
                continue
            imm = struct.unpack_from('<Q', out, i + 4)[0]
            correct = None
            old_rva = None
            if self.old_base <= imm < img_end:
                old_rva = imm - self.old_base
            elif self.new_base <= imm < self.new_base + 0x01000000:
                blob_off = imm - self.new_base - text_rva
                for cand_rva, cand_off in rva_map.items():
                    if cand_off == blob_off:
                        old_rva = cand_rva
                        break
                if old_rva is None:
                    old_rva = self._scope_old_rva_for_blob_off(blob_off)
            if old_rva is not None and old_rva in scope_off:
                correct = scope_off[old_rva]
            if correct is None and old_rva is not None and old_rva in rva_map:
                base = rva_map[old_rva]
                if 0 <= base < len(out) and self._valid_scope_sentinel(out, base):
                    correct = base
                else:
                    # Prefer exact x86 begin/end match over largest nearby span
                    # (large false-positive tables sit next to UTF-16 literals).
                    for delta in range(0, min(128, len(out) - max(base, 0) - 3)):
                        off = base + delta
                        if off < 0 or not self._valid_scope_sentinel(out, off):
                            continue
                        if _match_x86_scope(off, old_rva):
                            correct = off
                            break
                    if correct is None:
                        best_off = None
                        best_span = 0
                        for delta in range(0, min(128, len(out) - max(base, 0) - 3)):
                            off = base + delta
                            if off < 0 or not self._valid_scope_sentinel(out, off):
                                continue
                            begin, end_va = struct.unpack_from('<II', out, off + 4)
                            span = end_va - begin
                            if span > best_span:
                                best_span = span
                                best_off = off
                        if best_off is not None:
                            correct = best_off
                if correct is not None:
                    scope_off[old_rva] = correct
            if correct is None and self.new_base <= imm < self.new_base + 0x01000000:
                blob_off = imm - self.new_base - text_rva
                if 0 <= blob_off < len(out):
                    # Exact match first when we know the x86 scope RVA
                    if old_rva is not None:
                        for delta in range(-64, min(128, len(out) - blob_off - 3)):
                            off = blob_off + delta
                            if off < 0 or not self._valid_scope_sentinel(out, off):
                                continue
                            if _match_x86_scope(off, old_rva):
                                correct = off
                                break
                    if correct is None:
                        best_off = None
                        best_span = 0
                        for delta in range(-64, min(128, len(out) - blob_off - 3)):
                            off = blob_off + delta
                            if off < 0 or not self._valid_scope_sentinel(out, off):
                                continue
                            begin, end_va = struct.unpack_from('<II', out, off + 4)
                            span = end_va - begin
                            if span > best_span:
                                best_span = span
                                best_off = off
                        correct = best_off
            if correct is not None:
                new_imm = self.new_base + text_rva + correct
                if imm != new_imm:
                    struct.pack_into('<Q', out, i + 4, new_imm)
                    fixed += 1
                scope_old = None
                for orva, off in scope_off.items():
                    if off == correct:
                        scope_old = orva
                        break
                if scope_old is None:
                    scope_old = self._scope_old_rva_for_blob_off(correct)
                if (scope_old is not None
                        and not self._scope_sentinel_matches_x86(out, correct,
                                                                 scope_old)):
                    # Still register if begin/end already relocated to PE64
                    if not self._valid_scope_sentinel(out, correct):
                        scope_old = None
                if scope_old is not None:
                    self._record_seh_scope_reg_fn(out, scope_old, i)
                    self._scope_table_old_rva[correct] = scope_old
                    size = 64
                    for s, sz in self._scope_table_out_ranges:
                        if s == correct:
                            size = sz
                            break
                    if not any(s <= correct < s + sz
                               for s, sz in self._scope_table_out_ranges):
                        self._scope_table_out_ranges.append((correct, size))
                    fn_off = self._seh_scope_reg_fn[scope_old]
                    self._patch_scope_table_entries(out, correct, size, scope_old,
                                                    fn_off)
            i += 14
        return fixed

    def _bridge_ret_to_entry_gaps(self, out: bytearray,
                                  rva_map: Dict[int, int]) -> int:
        """Turn orphan bytes + INT3 after RET into a JMP to the real entry."""
        entry_offs = set(rva_map.values())
        _PROLOGUES = (
            b'\x48\x83\xec', b'\x48\x81\xec', b'\x55', b'\x53',
            b'\x41\x54', b'\x48\x89', b'\x40\x53', b'\x48\x8b',
            b'\x56', b'\x57', b'\x41\x55', b'\x41\x56',
        )
        bridged = 0
        i = 0
        while i < len(out) - 6:
            if out[i] != 0xC3:
                i += 1
                continue
            bridged_here = False
            for j in range(i + 1, min(i + 24, len(out) - 4)):
                if out[j] != 0xCC:
                    continue
                entry = j + 1
                head = out[entry:entry + 3]
                if not any(head.startswith(p) for p in _PROLOGUES):
                    continue
                gap_start = i + 1
                if gap_start not in entry_offs:
                    break
                gap_len = entry - gap_start
                if gap_len < 5:
                    break
                rel = entry - (gap_start + 5)
                out[gap_start:gap_start + 5] = b'\xE9' + struct.pack('<i', rel)
                for k in range(gap_start + 5, entry):
                    out[k] = 0x90
                for rva, off in list(rva_map.items()):
                    if gap_start <= off < entry:
                        rva_map[rva] = gap_start
                bridged += 1
                bridged_here = True
                i = entry
                break
            if not bridged_here:
                i += 1
        return bridged

    def _fix_alloca_probe_epilogues(self, out: bytearray) -> int:
        """MSVC _alloca_probe / __chkstk on x64.

        After ``push rcx`` at entry, the return address lives at ``[rsp+8]``.
        The naive ``mov rax, rsp; push qword ptr [rax]; ret`` pushes the
        saved rcx register instead of the caller return address.
        """
        _BAD = (
            b'\x48\x89\xe0'              # mov rax, rsp
            b'\x85\x01'                  # test dword ptr [rcx], eax
            b'\x48\x89\xcc'              # mov rsp, rcx
            b'\xff\x30'                  # push qword ptr [rax]
            b'\xc3'                      # ret
        )
        _DUP = (
            b'\x48\x89\xe0'              # mov rax, rsp
            b'\x85\x01'
            b'\x48\x89\xcc'
            b'\x48\x8b\x44\x24\x08'      # mov rax, [rsp+8]  (partial prior fix)
            b'\x85\x01'
            b'\x48\x89\xcc'
            b'\x50'
            b'\xc3'
        )
        _GOOD = (
            b'\x48\x8b\x44\x24\x08'      # mov rax, [rsp+8]   — return address
            b'\x8d\x49\xf8'              # lea ecx, [ecx-8]   — allocate EXACT size
            b'\x89\xcc'                  # mov esp, ecx       — set RSP (32-bit)
            b'\x50'                      # push rax           — place return addr
            b'\xc3'                      # ret
        )
        # Previous fix revision aligned the allocation with ``and ecx,-16``.
        # That makes the allocated frame depend on the *caller's* RSP mod 16,
        # while the translation stack model assumes chkstk allocates exactly
        # ``eax`` bytes (x86 semantics) — deep [esp+disp] reads land 4/8 bytes
        # off and epilogues misrelease.  Convert any old tail to the exact form.
        _GOOD_OLD = (
            b'\x48\x8b\x44\x24\x08'      # mov rax, [rsp+8]
            b'\x83\xe1\xf0'              # and ecx, -16
            b'\x89\xcc'                  # mov esp, ecx
            b'\x50'                      # push rax
            b'\xc3'                      # ret
        )
        _POPRCX_BAD = (
            b'\x48\x89\xe0'              # mov rax, rsp
            b'\x85\x01'                  # test dword ptr [rcx], eax
            b'\x48\x89\xcc'              # mov rsp, rcx
            b'\x59'                      # pop rcx  (x86 _chkstk uses pop ecx; ret)
            b'\xc3'                      # ret
        )
        # Hybrid: translator emits old 8 bytes + _GOOD side-by-side (19 bytes).
        # The old `mov rax,rsp; test; mov rsp,rcx` sets RSP before _GOOD's
        # `mov rax,[rsp+8]` loads the return address — corrupting the load.
        # NOP-out the first 8 bytes to leave only the correct _GOOD code.
        _HYBRID_BAD = (
            b'\x48\x89\xe0'              # mov rax, rsp
            b'\x85\x01'                  # test dword ptr [rcx], eax
            b'\x48\x89\xcc'              # mov rsp, rcx
        ) + _GOOD
        _HYBRID_FIX = b'\x90' * 8 + _GOOD  # 8 NOPs + correct _GOOD
        _LEGACY_BAD = b'\x8b\x08\x8b\x40\x04\x50\xc3'
        _CHK = (b'\x3d\x00\x10\x00\x00', b'\x48\x3d\x00\x10\x00\x00')

        def _in_chkstk(head: bytes) -> bool:
            return any(p in head for p in _CHK)

        fixed = 0
        # Fix hybrid first (19 bytes → 19 bytes, cleanest fix)
        start = 0
        while start < len(out):
            i = out.find(_HYBRID_BAD, start)
            if i < 0:
                break
            head = out[max(0, i - 512):i]
            if _in_chkstk(head):
                out[i:i + len(_HYBRID_FIX)] = _HYBRID_FIX
                fixed += 1
            start = i + 1
        for bad, good_pad in ((_BAD, 0), (_DUP, 0), (_POPRCX_BAD, 1),
                              (_LEGACY_BAD, 0)):
            start = 0
            while start < len(out):
                i = out.find(bad, start)
                if i < 0:
                    break
                head = out[max(0, i - 512):i]
                if _in_chkstk(head):
                    if good_pad and len(_GOOD) > len(bad):
                        out[i:i + len(_GOOD)] = _GOOD
                    else:
                        out[i:i + len(bad)] = _GOOD + b'\x90' * (len(bad) - len(_GOOD))
                    fixed += 1
                start = i + 1
        # Frame-base LEA: x86 ``lea ecx,[esp+8]`` (4-byte retaddr + 4-byte saved
        # ecx) becomes ``lea rcx,[rsp+0x10]`` on x64 — both slots are now 8 bytes.
        # The instruction-level port kept the x86 ``+8`` displacement, so the
        # probe sets RSP 8 bytes too low and EVERY large-frame function's
        # ``add rsp,N; ret`` epilogue then reads a garbage return address
        # (the cmd 0xA4E7 epilogue crash).  Universal: keyed on the unique
        # ``cmp eax,0x1000`` probe fingerprint immediately preceding the LEA.
        _LEA_BAD = b'\x48\x8d\x4c\x24\x08'   # lea rcx, [rsp+8]
        _LEA_GOOD = b'\x48\x8d\x4c\x24\x10'  # lea rcx, [rsp+0x10]
        start = 0
        while start < len(out):
            i = out.find(_LEA_BAD, start)
            if i < 0:
                break
            start = i + 1
            head = out[max(0, i - 12):i]
            if b'\x3d\x00\x10\x00\x00' not in head:
                continue
            out[i:i + len(_LEA_BAD)] = _LEA_GOOD
            fixed += 1
        # Exact-allocation upgrade: convert any previously-fixed tail that
        # still uses ``and ecx,-16`` (alignment-dependent allocation) to the
        # exact-size form.  Both are 10 bytes, so no size changes.
        start = 0
        while start < len(out):
            i = out.find(_GOOD_OLD, start)
            if i < 0:
                break
            out[i:i + len(_GOOD_OLD)] = _GOOD
            fixed += 1
            start = i + len(_GOOD)
        return fixed

    def _fix_chkstk_epilogue_adds(self, out: bytearray) -> int:
        """For every ``call __chkstk`` site, find the matching epilogue
        ``add rsp, N`` and set N to the exact x86 frame size.

        The translated __chkstk now allocates EXACTLY ``rax`` bytes below the
        caller's pre-call RSP (``sub ecx,8`` tail — no alignment), matching
        x86 semantics that the translation stack model already assumes.
        The epilogue therefore releases exactly the original x86 frame size:
        ``pop…; add rsp, N; ret`` with N == the ``mov rax,N`` value.
        ``_adjust_epilogue_add_rsp`` rounds N up to 8 for plain ``sub rsp``
        frames, which is wrong for __chkstk frames — this pass runs after it
        and overwrites N with the exact size.
        """
        _CK_SIGS = (b'\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x10',
                    b'\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x08',
                    b'\x51\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x10',
                    b'\x51\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x08',
                    b'\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x10\x51',
                    b'\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x08\x51')
        ck_off = None
        for sig in _CK_SIGS:
            ck_off = out.find(sig)
            if ck_off >= 0:
                break
        if ck_off is None:
            return 0

        pop_set = {0x5E, 0x5F, 0x5B, 0x5D, 0x56, 0x57, 0x53,
                   0x58, 0x59, 0x5A, 0x5C}
        fixed = 0
        call_pos = 0
        while True:
            call_pos = out.find(b'\xe8', call_pos)
            if call_pos < 0:
                break
            if call_pos + 5 > len(out):
                call_pos += 1
                continue
            rel = int.from_bytes(out[call_pos+1:call_pos+5], 'little', signed=True)
            target = (call_pos + 5 + rel) & 0xFFFFFFFF
            if target != ck_off:
                call_pos += 1
                continue
            # Find the mov rax/eax, N before this call (original x86 frame size)
            x86_size = None
            for scan in range(call_pos - 7, max(0, call_pos - 48), -1):
                if scan + 7 <= call_pos:
                    if (out[scan] == 0x48 and out[scan + 1] == 0xC7
                            and (out[scan + 2] & 0xF8) == 0xC0):
                        x86_size = int.from_bytes(out[scan+3:scan+7], 'little')
                        break
                if scan + 5 <= call_pos:
                    b = out[scan]
                    if (0xB8 <= b <= 0xBF and (b & 7) == 0
                            and (scan == 0 or out[scan - 1] != 0x48)):
                        x86_size = int.from_bytes(out[scan+1:scan+5], 'little')
                        break
            if x86_size is None or x86_size < 0x100:
                call_pos += 1
                continue
            # Find matching epilogue ADD up to 65536 bytes forward
            for scan in range(call_pos + 5, min(len(out), call_pos + 65536)):
                if out[scan] not in pop_set:
                    continue
                pop_count = 0
                pos = scan
                while pos < len(out) and out[pos] in pop_set:
                    pop_count += 1
                    pos += 1
                if pop_count < 3:
                    continue
                if (pos + 7 <= len(out)
                        and out[pos:pos+3] == b'\x48\x81\xc4'):
                    old_imm = int.from_bytes(out[pos+3:pos+7], 'little')
                    if old_imm < 0x100:
                        continue
                    # Exact release: the translated __chkstk allocates exactly
                    # ``rax`` bytes below the caller's entry RSP, so the
                    # epilogue ADD must equal the original x86 frame size.
                    # (Previously (size & ~0xF) - 8 for the aligned helper —
                    # that left RSP 0xC high on cmd 0xA4E7 (size 0x2464) and
                    # ``ret`` popped a stack address → execute @ stack crash.)
                    new_imm = x86_size
                    if new_imm < 0x100:
                        call_pos += 1
                        break
                    if new_imm != old_imm:
                        out[pos+3:pos+7] = new_imm.to_bytes(4, 'little')
                        fixed += 1
                    break
            call_pos += 1
        return fixed

    def _fix_chkstk_frame_alignment(self, out: bytearray) -> int:
        """DISABLED (was: round ``mov rax,N`` probe sizes up to 16).

        Rounding the probe size up breaks the exact-allocation invariant: the
        translated __chkstk now allocates EXACTLY ``rax`` bytes and the
        translation stack model (deep [esp+disp] displacements, epilogue
        ``add rsp,N``) is built around the original x86 size.  Rounding here
        made deep arg reads land 4 bytes off and epilogues misrelease (cmd
        0xA4E7 switch-parser crash).  Call sites align locally via the
        ``push r13; …; and rsp,-16`` pattern, so no global alignment is
        needed.
        """
        return 0

    def _pure_chkstk_entry_off(self, out: bytearray) -> Optional[int]:
        """Locate the clean translated __chkstk/_alloca_probe entry.

        The probe is a universal MSVC CRT routine, but its rva_map entry
        frequently collapses onto the *previous* function's ``ret``/thunk tail
        (every interior instruction maps to one stale slot), so callers snap to
        garbage.  The translated body itself is intact and unmistakable —
        ``cmp eax,0x1000`` with ``lea rcx,[rsp+8/10]`` / ``push rcx`` in either
        order (emit order varies), plus page-probe ``sub eax,0x1000`` close
        behind.  Find it by signature and hand every probe call straight to it.
        """
        cached = getattr(self, '_chkstk_entry_cache', None)
        loop = b'\x2d\x00\x10\x00\x00'                        # sub eax, 0x1000
        if (cached is not None and 0 <= cached < len(out)
                and out[cached:cached + 5] == b'\x3d\x00\x10\x00\x00'):
            # Verify full signature: sub eax,0x1000 within 0x40 bytes
            if out.find(loop, cached, cached + 0x40) != -1:
                return cached
        # MSVC x86 is ``push ecx; cmp; lea``.  The translator may emit
        # ``cmp; push; lea``, ``push; cmp; lea``, or ``cmp; lea; push``
        # (lea-before-push after the entry push is folded / reordered).
        sigs = (
            b'\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x08',  # cmp;push;lea [rsp+8]
            b'\x51\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x08',  # push;cmp;lea [rsp+8]
            b'\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x10',  # cmp;push;lea [rsp+10]
            b'\x51\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x10',  # push;cmp;lea [rsp+10]
            b'\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x10\x51',  # cmp;lea [rsp+10];push
            b'\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x08\x51',  # cmp;lea [rsp+8];push
        )
        found: Optional[int] = None
        for sig in sigs:
            start = 0
            while True:
                i = out.find(sig, start)
                if i < 0:
                    break
                if out.find(loop, i, i + 0x40) != -1:
                    found = i
                    break
                start = i + 1
            if found is not None:
                break
        # Neutralize a stale ``jmp qword [rip+…]`` thunk immediately before the
        # probe body (rva_map often lands on that slot → wild RIP).  Fall through
        # into ``cmp eax,0x1000``.
        if found is not None and found >= 8:
            pre = found - 8
            if out[pre] == 0xFF and out[pre + 1] == 0x25:
                out[pre:found] = b'\x90' * (found - pre)
            elif out[pre + 2] == 0xFF and out[pre + 3] == 0x25:
                # optional 2-byte prefix / nops before ff25
                out[pre + 2:found] = b'\x90' * (found - (pre + 2))
        self._chkstk_entry_cache = found
        return found

    def _nop_fill_zero_gaps(self, out: bytearray) -> int:
        """NOP-fill tiny zero runs (1–8 bytes) at function-boundary gaps.

        Only touches zero bytes that are:
        1. Immediately preceded by a terminal insn (RET / JMP rel8 /
           JMP rel32 / CALL rel32).
        2. Immediately followed by a byte in ``self.rva_map`` (mapped code).
        3. Run length ≤ 8 bytes.

        These are alignment / inter-function gaps — never data sections.
        Universal for any Win2000 pure-mode binary: ``00 00`` decodes as
        ``add [rax], al`` (null-write crash when RAX == 0), while ``90 90``
        (NOP) lets stray branches slide into the next valid instruction.
        """
        if not self.rva_map:
            return 0
        mapped = set(self.rva_map)  # pure offsets (keys)
        fixed = 0
        for i in range(len(out) - 1):
            if out[i] != 0x00:
                continue
            # Must be immediately after a terminal instruction
            if i < 1:
                continue
            is_terminal = False
            # RET / RETN / JMP rel8  (1-2 byte insns)
            if out[i - 1] in (0xC3, 0xC2):
                is_terminal = True
            if i >= 2 and out[i - 2] == 0xEB:   # JMP rel8 (2 bytes)
                is_terminal = True
            # JMP/CALL rel32 (5 bytes)
            if i >= 5 and out[i - 5] in (0xE9, 0xE8):
                is_terminal = True
            if not is_terminal:
                continue
            # Measure zero run
            run_end = i
            while run_end < len(out) and out[run_end] == 0x00:
                run_end += 1
            run_len = run_end - i
            if run_len > 8:
                i = run_end - 1
                continue
            # Next non-zero byte must be mapped code
            if run_end in mapped:
                for pos in range(i, run_end):
                    out[pos] = 0x90
                    fixed += 1
                i = run_end
        return fixed

    def _pad_prologue_for_alignment(self, out: bytearray) -> int:
        """Add 8 bytes of shadow-space padding to translator prologues.

        The x86→x64 calling convention sometimes leaves RSP 4-mod-8 at
        function entry (x86 ``call`` pushes 4 bytes vs x64's 8).  Adding
        8 bytes to every ``sub rsp, N`` in the translator prologue lets
        the trailing ``and rsp, -16`` absorb the padding, ensuring every
        function's frame is 8-byte-safe without changing any offsets.

        Universal for all Win2000 pure binaries — the padding is always
        harmless because it just increases the shadow-space region.
        """
        fixed = 0
        i = 0
        while i + 16 <= len(out):
            if not self._is_translator_prologue(out, i):
                i += 1
                continue
            # Found: push r13; mov r13, rsp; sub rsp, N; and rsp, -16
            sub_off = i + 5  # start of sub rsp instruction
            if out[sub_off] != 0x48:
                i += 1
                continue
            if out[sub_off + 1] == 0x81 and sub_off + 7 <= len(out):
                # sub rsp, imm32 (48 81 EC xx xx xx xx)
                old_n = struct.unpack_from('<I', out, sub_off + 3)[0]
                struct.pack_into('<I', out, sub_off + 3, old_n + 8)
                fixed += 1
            elif out[sub_off + 1] == 0x83 and sub_off + 4 <= len(out):
                # sub rsp, imm8 (48 83 EC xx)
                old_n = out[sub_off + 3]
                new_n = old_n + 8
                if new_n <= 127:
                    out[sub_off + 3] = new_n & 0xFF
                    fixed += 1
                # else: can't fit in imm8 — leave it (rare for shadow space)
            i = sub_off + 7
        return fixed

    def _adjust_epilogue_add_rsp(self, out: bytearray,
                                  chkstk_off: Optional[int] = None) -> int:
        """Fix ``add rsp, imm32`` in pop…ret epilogues for x64 alignment.

        Universal: rounds the ADD immediate up to an 8-byte boundary.
        The matching ``sub rsp`` in the prologue is also rounded to 8 bytes,
        so the frame stays balanced.  No pop-size adjustment is needed —
        the x64 callee-save pushes already account for the 4→8 byte
        difference per register.

        _chkstk functions are handled separately by
        _fix_chkstk_epilogue_adds (which runs after this function).
        """
        fixed = 0
        i = 0
        pop_set = {0x5E, 0x5F, 0x5B, 0x5D, 0x56, 0x57, 0x53,
                   0x58, 0x59, 0x5A, 0x5C}
        while i + 10 <= len(out):
            if out[i] not in pop_set:
                i += 1
                continue
            pop_count = 0
            pos = i
            while pos < len(out) and out[pos] in pop_set:
                pop_count += 1
                pos += 1
            if pop_count == 0 or pos + 6 > len(out):
                i += 1
                continue
            # ADD RSP, imm32: 48 81 C4 xx xx xx xx
            if (out[pos:pos + 3] == b'\x48\x81\xc4' and pos + 7 <= len(out)):
                old_imm = struct.unpack_from('<I', out, pos + 3)[0]
                # Universal: round up to 8-byte boundary to match SUB rounding
                new_imm = (old_imm + 7) & ~7
                if new_imm != old_imm:
                    struct.pack_into('<I', out, pos + 3, new_imm)
                    fixed += 1
                i = pos + 7
            # Check for ADD RSP, imm8: 48 83 C4 xx
            elif (out[pos:pos + 3] == b'\x48\x83\xc4' and pos + 4 <= len(out)):
                old_imm = out[pos + 3]
                new_imm = (old_imm + 7) & ~7
                if new_imm != old_imm and new_imm <= 255:
                    out[pos + 3] = new_imm & 0xFF
                    fixed += 1
                i = pos + 4
            else:
                i += 1
        return fixed

    def _int3_sled_ff25_gaps(self, out: bytearray) -> int:
        """Fill bytes between orphan ``ff 25`` IAT thunks with INT3 so fall-through cannot execute garbage."""
        fixed = 0
        mapped_offs = set(self.rva_map.values()) if self.rva_map else set()
        i = 0
        while i + 6 <= len(out):
            if out[i:i + 2] != b'\xff\x25' or self._orphan_byte_protected(i):
                i += 1
                continue
            j = i + 6
            limit = min(len(out), i + 48)
            while j < limit:
                if self._orphan_byte_protected(j):
                    break
                if j in mapped_offs:
                    break
                if (j + 4 <= len(out)
                        and out[j:j + 4] == b'\x55\x48\x89\xe5'):
                    break
                if j + 2 <= len(out) and out[j:j + 2] == b'\xff\x25':
                    break
                if out[j] not in (0xCC, 0x90, 0xC3, 0x00):
                    out[j] = 0xCC
                    fixed += 1
                j += 1
            i = j if j > i + 6 else i + 6
        return fixed

    def _pure_fix_rbp_leave_before_ret(self, out: bytearray) -> int:
        """Insert ``mov rsp,rbp; pop rbp`` before ``ret`` when an RBP frame was not closed.

        Merged function blobs in pure mode can reach ``ret`` via branch repair while
        the x86 ``leave`` at the epilogue label was linearized into dead NOPs.
        """
        del out  # disabled — broad matching corrupts interior rets; use jmp fix.
        return 0

    def _pure_off_starts_real_jmp(self, out: bytearray, pos: int) -> bool:
        """True when *pos* is an instruction boundary starting a real ``jmp``.

        Blind ``out[pos] == 0xE9`` slot scans in epilogue materialization
        grabbed the 0xE9 *imm8* inside ``sub ecx,8`` (83 E9 08) in the
        translated __chkstk tail and overwrote it with ``c3 90 90 …`` —
        corrupting the probe (build 374).  Only accept a true jmp start.
        """
        if pos < 0 or pos >= len(out) or out[pos] != 0xE9:
            return False
        if not HAS_CAPSTONE:
            return True
        try:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            lo = max(0, pos - 16)
            for ins in md.disasm(bytes(out[lo:pos + 5]), lo):
                if ins.address == pos:
                    return ins.mnemonic == 'jmp'
        except CsError:
            pass
        return False

    def _pure_fix_jmp_over_epilogue(self, out: bytearray,
                                    text_data: bytes,
                                    text_rva: int) -> int:
        """Replace forward ``jmp`` at x86 ``pop/leave/ret`` labels with inline epilogue."""
        if not self._cmd_no_hacks or not self.rva_map:
            return 0
        fixed = 0
        seen_slots: Set[int] = set()
        for old_rva, off in list(self.rva_map.items()):
            xoff = old_rva - text_rva
            if xoff < 0 or xoff >= len(text_data) or text_data[xoff] != 0x5E:
                continue
            if xoff + 2 < len(text_data) and text_data[xoff + 1] == 0xC9:
                if text_data[xoff + 2] == 0xC3:
                    epilog = b'\x5E\xc9\xc3'
                elif (text_data[xoff + 2] == 0xC2 and xoff + 5 <= len(text_data)):
                    epilog = b'\x5E\xc9\xc2' + text_data[xoff + 3:xoff + 5]
                else:
                    epilog = b'\x5E\xc9\xc3'
            else:
                epilog = b'\x5E\xc9\xc3'
            if len(epilog) > 5:
                continue
            slot: Optional[int] = None
            for delta in range(0, 16):
                pos = off + delta
                if pos + 5 > len(out):
                    break
                if out[pos] == 0xE9 and self._pure_off_starts_real_jmp(out, pos):
                    slot = pos
                    break
                if out[pos] == 0x5E and pos + 2 <= len(out) and out[pos + 1] == 0xC9:
                    break
            if slot is None or slot in seen_slots:
                continue
            out[slot:slot + len(epilog)] = epilog
            for k in range(slot + len(epilog), slot + 5):
                if k < len(out):
                    out[k] = 0x90
            seen_slots.add(slot)
            fixed += 1
        return fixed

    def _int3_sled_orphan_data(self, out: bytearray) -> int:
        """Trap SEH/orphan *data* blobs (not IAT thunks) so stray RIP cannot run them as code."""
        if self._cmd_no_hacks:
            return 0
        fixed = 0
        for start, size in self._orphan_blob_out_ranges:
            end = min(len(out), start + size)
            if end - start >= 4 and out[start:start + 4] == b'\xff\xff\xff\xff':
                continue
            for pos in range(start, end):
                if self._orphan_byte_protected(pos):
                    continue
                if out[pos:pos + 2] == b'\xff\x25':
                    pos += 5
                    continue
                if out[pos:pos + 4] == b'\xff\xff\xff\xff':
                    continue
                if out[pos] not in (0xCC, 0x00):
                    out[pos] = 0xCC
                    fixed += 1
        return fixed

    def _fix_misaligned_direct_calls(self, out: bytearray,
                                     rva_map: Dict[int, int]) -> int:
        """
        Snap E8 rel32 targets that land inside an orphan FF25 stub (mid ``ff 25``).
        Do not snap to arbitrary rva_map values — that mis-anchors calls onto
        epilogue bytes inside translated functions.
        """
        del rva_map  # kept for call-site stability; not used for snapping
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < 0 or tgt >= len(out):
                continue
            if out[tgt:tgt + 2] == b'\xff\x25':
                continue
            snapped: Optional[int] = None
            for delta in range(1, 12):
                pos = tgt - delta
                if pos >= 0 and out[pos:pos + 2] == b'\xff\x25':
                    snapped = pos
                    break
            if snapped is not None:
                struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                fixed += 1
        return fixed

    def _fix_calls_to_wrapper_bodies(self, out: bytearray) -> int:
        """
        Call fixups sometimes land on ``mov eax,esi; pop edi; pop esi; ret`` tails.
        Prefer the next real function entry after that epilogue; only fall back to
        the import-wrapper prologue when no forward entry exists.
        """
        fixed = 0
        pro, epi = self._WRAPPER_PROLOG, self._WRAPPER_EPILOG
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < 2 or tgt >= len(out):
                continue
            if out[tgt - 2:tgt + len(epi) - 2] != epi:
                continue
            snapped: Optional[int] = None
            epi_end = tgt - 2 + len(epi)
            for pos in range(epi_end, min(epi_end + 16, len(out) - 3)):
                if out[pos:pos + 4] == b'\x48\x83\xec\x58':   # sub rsp, 0x58
                    snapped = pos
                    break
                if out[pos:pos + 4] == b'\x48\x83\xec\x20':   # sub rsp, 0x20
                    snapped = pos
                    break
                if out[pos:pos + 1] == b'\x40' and out[pos + 1:pos + 3] == b'\x55':
                    snapped = pos + 1   # push rbp (REX prefix)
                    break
            if snapped is None:
                for back in range(0, 0x80):
                    pos = tgt - back
                    if pos >= 0 and out[pos:pos + len(pro)] == pro:
                        snapped = pos
                        break
            if snapped is not None and snapped != tgt:
                struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                fixed += 1
        return fixed

    def _snap_calls_to_insn_boundaries(self, out: bytearray) -> int:
        """Snap E8 targets that land mid-instruction back to the enclosing start."""
        if not HAS_CAPSTONE:
            return 0
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt <= 0 or tgt >= len(out):
                continue
            prologue_hit = False
            for delta in range(0, 4):
                pos = tgt + delta
                if pos + 3 > len(out):
                    break
                if out[pos:pos + 3] == b'\x55\x48\x89':
                    struct.pack_into('<i', out, i + 1, pos - (i + 5))
                    fixed += 1
                    prologue_hit = True
                    break
                if out[pos:pos + 3] == b'\x48\x83\xec':
                    struct.pack_into('<i', out, i + 1, pos - (i + 5))
                    fixed += 1
                    prologue_hit = True
                    break
            if not prologue_hit and self._call_lands_in_epilogue_tail(out, tgt):
                for delta in range(0, 24):
                    pos = tgt + delta
                    if pos + 1 > len(out):
                        break
                    if out[pos] == 0x53 or out[pos] == 0x56:       # push rbx/rsi
                        struct.pack_into('<i', out, i + 1, pos - (i + 5))
                        fixed += 1
                        prologue_hit = True
                        break
                    if pos + 3 <= len(out) and out[pos:pos + 3] == b'\x48\x83\xec':
                        struct.pack_into('<i', out, i + 1, pos - (i + 5))
                        fixed += 1
                        prologue_hit = True
                        break
                    if pos + 2 <= len(out) and out[pos:pos + 2] == b'\x48\xb8':
                        struct.pack_into('<i', out, i + 1, pos - (i + 5))
                        fixed += 1
                        prologue_hit = True
                        break
                    if out[pos:pos + 3] == b'\x55\x48\x89':
                        struct.pack_into('<i', out, i + 1, pos - (i + 5))
                        fixed += 1
                        prologue_hit = True
                        break
            if prologue_hit:
                continue
            # Never rip a call off a mapped / plausible entry just because
            # Capstone can decode a shadow insn from earlier bytes that
            # *covers* this address (cmd 0x1A9A0 ``mov rcx,imm`` sat inside
            # a phantom ``call [rax+disp]`` decoded from the preceding FF25
            # gap → CRT ``_controlfp`` wrapper callers landed mid-gap → AV).
            if (self._offset_is_mapped_entry(out, tgt)
                    or self._pure_call_target_plausible(out, tgt)):
                pass  # keep tgt; still allow the forward sub-rsp snap below
            else:
                snapped: Optional[int] = None
                scan_lo = max(0, tgt - 14)
                for start in range(scan_lo, tgt + 1):
                    insns = list(md.disasm(out[start:start + 20], start, count=8))
                    for ins in insns:
                        if ins.address > tgt:
                            break
                        end = ins.address + ins.size
                        if ins.address <= tgt < end and ins.address != tgt:
                            snapped = ins.address
                            break
                    if snapped is not None:
                        break
                if snapped is not None:
                    struct.pack_into('<i', out, i + 1, snapped - (i + 5))
                    fixed += 1
                    tgt = snapped
            # Do not forward-snap to ``sub rsp`` inside call-align prologues:
            # callers must land on outer push rbx/rbp before the align wrapper.
            if (tgt + 16 <= len(out)
                    and not self._offset_is_mapped_entry(out, tgt)):
                for delta in range(0, 16):
                    pos = tgt + delta
                    if out[pos:pos + 3] != b'\x48\x83\xec':
                        continue
                    if self._outer_entry_before_align(out, pos) is not None:
                        break
                    if pos != i + 5 + rel:
                        struct.pack_into('<i', out, i + 1, pos - (i + 5))
                        fixed += 1
                    break
        return fixed

    def _snap_calls_to_function_entries(self, out: bytearray,
                                        rva_map: Optional[Dict[int, int]] = None) -> int:
        """Snap E8 rel32 targets that land mid-function back to a real entry."""
        if rva_map is None:
            rva_map = self.rva_map or None
        return self._snap_calls_to_enclosing_entries(out, rva_map)

    def _reconcile_rva_map_prologues(self, out: bytearray,
                                     rva_map: Dict[int, int]) -> int:
        """Move rva_map entries off mid-function bytes onto real prologues."""
        fixed = 0
        force_fixed = 0
        text_data = getattr(self, '_pure_heal_text', None) if self._cmd_no_hacks else None
        text_rva = getattr(self, '_pure_heal_text_rva', 0)
        for old_rva in list(rva_map.keys()):
            off = rva_map.get(old_rva)
            if off is None or off < 0 or off >= len(out):
                continue
            if self._cmd_no_hacks and text_data is not None:
                if self._pure_mapped_entry_sane(out, off, old_rva, text_data, text_rva):
                    continue
                # Search BOTH directions for a sane prologue — not just
                # backwards.  A collapsed entry may land on the previous
                # function's epilogue (leave;ret) while the real prologue
                # sits a few bytes *forward* (push rbp; mov rbp,rsp).
                best_pos = None
                for delta in range(1, 160):
                    for pos in (off - delta, off + delta):
                        if pos < 0 or pos >= len(out):
                            continue
                        if self._pure_mapped_entry_sane(out, pos, old_rva, text_data, text_rva):
                            best_pos = pos
                            break
                    if best_pos is not None:
                        break
                if best_pos is not None and rva_map[old_rva] != best_pos:
                    rva_map[old_rva] = best_pos
                    fixed += 1
                # ── Force-fix: mov ebp,esp → mov rbp,rsp ──
                # Runs UNCONDITIONALLY for 8B EC entries regardless of
                # whether the bidirectional search found a candidate.
                # The search may snap to ``push rbp; mov rbp,rsp``
                # (55 48 89 E5) which is one byte before the true
                # ``mov rbp,rsp`` (48 89 E5), and even that fix can be
                # reverted by later passes.  This force-fix is the last
                # line of defence: it walks forward from the *updated*
                # offset and ensures the final mapping points at the
                # exact ``mov rbp,rsp`` bytes.
                func_off = old_rva - text_rva
                if 0 <= func_off < len(text_data) - 1:
                    x86_head = text_data[func_off:func_off + 2]
                    if x86_head == b'\x8b\xec':
                        cur = rva_map.get(old_rva, off)
                        # x86 is mov ebp,esp — x64 MUST be mov rbp,rsp (48 89 E5)
                        if (cur + 3 > len(out)
                                or out[cur:cur + 3] != b'\x48\x89\xe5'):
                            # Search forward up to 32 bytes for mov rbp,rsp
                            for fwd in range(1, 33):
                                fpos = cur + fwd
                                if (fpos + 3 <= len(out)
                                        and out[fpos:fpos + 3] == b'\x48\x89\xe5'):
                                    rva_map[old_rva] = fpos
                                    force_fixed += 1
                                    break
                continue
            if self._x64_entry_prologue_ok(out, off):
                continue
            best_pos = None
            for delta in range(1, 160):
                for pos in (off - delta, off + delta):
                    if pos < 0 or pos >= len(out):
                        continue
                    if self._x64_entry_prologue_ok(out, pos):
                        best_pos = pos
                        break
                if best_pos is not None:
                    break
            if best_pos is not None and rva_map[old_rva] != best_pos:
                rva_map[old_rva] = best_pos
                fixed += 1
        if force_fixed:
            print(f"        Pure force-fixed mov-ebp→mov-rbp rva_map entries: "
                  f"{force_fixed}")
        return fixed + force_fixed

    def _force_fix_mov_ebp_entries(self, out: bytearray,
                                   rva_map: Dict[int, int],
                                   text_data: bytes,
                                   text_rva: int) -> int:
        """Force-correct rva_map entries where x86 ``mov ebp,esp`` maps to
        non-``mov rbp,rsp`` x64 bytes.  This is the final safety net that
        runs after all other reconciliation passes."""
        if not self._cmd_no_hacks or text_data is None:
            return 0
        fixed = 0
        for old_rva in list(rva_map.keys()):
            func_off = old_rva - text_rva
            if old_rva == 0x15142:
                print(f"        [DEBUG force-fix] old_rva=0x{old_rva:X} "
                      f"text_rva=0x{text_rva:X} func_off=0x{func_off:X} "
                      f"len(text_data)=0x{len(text_data):X} "
                      f"in_rva_map={old_rva in rva_map} "
                      f"cur={rva_map.get(old_rva)}")
                if 0 <= func_off < len(text_data) - 1:
                    xhead = text_data[func_off:func_off + 4]
                    print(f"        [DEBUG force-fix] x86 head: {xhead.hex()} "
                          f"match_8bec={xhead[:2]==b'\\x8b\\xec'}")
            if not (0 <= func_off < len(text_data) - 1):
                if old_rva == 0x15142:
                    print(f"        [DEBUG force-fix] SKIP: func_off out of range")
                continue
            if text_data[func_off:func_off + 2] != b'\x8b\xec':
                if old_rva == 0x15142:
                    xhead = text_data[func_off:func_off + 2]
                    print(f"        [DEBUG force-fix] SKIP: x86 head is "
                          f"{xhead.hex()} not 8bec")
                continue
            cur = rva_map[old_rva]
            if cur < 0 or cur + 3 > len(out):
                if old_rva == 0x15142:
                    print(f"        [DEBUG force-fix] SKIP: cur={cur} out of range")
                continue
            if out[cur:cur + 3] == b'\x48\x89\xe5':
                if old_rva == 0x15142:
                    print(f"        [DEBUG force-fix] SKIP: already correct at {cur:X}")
                continue  # already correct
            # Search forward for the nearest mov rbp,rsp
            for fwd in range(1, 64):
                fpos = cur + fwd
                if fpos + 3 <= len(out) and out[fpos:fpos + 3] == b'\x48\x89\xe5':
                    if old_rva == 0x15142:
                        print(f"        [DEBUG force-fix] 0x{old_rva:X}: "
                              f"0x{cur:X}->0x{fpos:X} "
                              f"(x64[cur]={out[cur:cur+4].hex()}, "
                              f"x64[fpos]={out[fpos:fpos+4].hex()})")
                    rva_map[old_rva] = fpos
                    fixed += 1
                    break
            else:
                if old_rva == 0x15142:
                    print(f"        [DEBUG force-fix] 0x{old_rva:X}: "
                          f"0x{cur:X} NO mov rbp,rsp found within 64 bytes! "
                          f"x64[cur]={out[cur:cur+4].hex()}")
        return fixed

    def _neutralize_degenerate_calls(self, out: bytearray) -> int:
        """
        NOP CALL rel32 inside align prologue stubs whose target is the byte
        before ``mov rsp, r13`` (failed fixup rel32 often equals -1).
        """
        if self._cmd_no_hacks:
            return 0
        align_and = b'\x48\x83\xe4\xf0'
        epilogue = b'\x4c\x89\xec'   # mov rsp, r13
        fixed = 0
        for i in range(len(out) - 8):
            if out[i] != 0xE8:
                continue
            after = i + 5
            if out[after:after + 3] != epilogue:
                continue
            if align_and not in out[max(0, i - 12):i]:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = after + rel
            if not (after - 4 <= tgt <= after + 1):
                continue
            out[i:i + 5] = b'\x90' * 5
            fixed += 1
        return fixed

    def _fix_missing_pop_r13_after_align(self, out: bytearray) -> int:
        """Fix missing ``pop r13`` (+ missing x86 pops) after ``mov rsp,r13``.

        Uses IN-PLACE replacement (no byte shifting!) to avoid corrupting
        downstream offsets.  Only fixes the pattern where both ``pop r13``
        AND a register pop (like ``pop rsi``) are missing from the align stub
        epilogue.  The callee already restored RSP to R13 (via its own align
        stub), so ``mov rsp,r13`` in the caller is a no-op and can be safely
        replaced."""
        fixed = 0
        i = 0
        while i + 5 <= len(out):
            # Look for: mov rsp, r13; mov r32, r32  (5 bytes: 4C 89 EC 89 xx)
            # where xx is a ModRM byte indicating a reg-reg MOV.
            # Replace with: pop r13; pop rsi; mov r32, r32  (5 bytes: 41 5D 5E 89 xx)
            if (out[i:i + 5] == b'\x4c\x89\xec\x89\xd8'  # mov eax,ebx
                    or out[i:i + 5] == b'\x4c\x89\xec\x89\xf0'  # mov eax,esi
                    or out[i:i + 5] == b'\x4c\x89\xec\x89\xc8'):  # mov eax,ecx
                # Verify that pop rsi (5E) is NOT present in the next 6 bytes
                # (if it is, only pop r13 is missing — skip, as that requires shifting)
                found_pop = False
                for j in range(i + 5, min(len(out), i + 12)):
                    if out[j] == 0x5E:  # pop rsi
                        found_pop = True
                        break
                if not found_pop:
                    # Save the mov bytes and replace
                    mov_bytes = out[i + 3:i + 5]
                    out[i:i + 5] = b'\x41\x5d\x5e' + mov_bytes
                    fixed += 1
                    i += 5
                    continue
            i += 1

        return fixed
        """
        NOP CALL rel32 inside align prologue stubs whose target is the byte
        before ``mov rsp, r13`` (failed fixup rel32 often equals -1).
        """
        if self._cmd_no_hacks:
            return 0
        align_and = b'\x48\x83\xe4\xf0'
        epilogue = b'\x4c\x89\xec'   # mov rsp, r13
        fixed = 0
        for i in range(len(out) - 8):
            if out[i] != 0xE8:
                continue
            after = i + 5
            if out[after:after + 3] != epilogue:
                continue
            if align_and not in out[max(0, i - 12):i]:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = after + rel
            if not (after - 4 <= tgt <= after + 1):
                continue
            out[i:i + 5] = b'\x90' * 5
            fixed += 1
        return fixed

    def _fix_mangled_imm_ret_stubs(self, out: bytearray) -> int:
        """NOP a stray ``pop reg`` between ``mov rax, imm32`` and ``ret`` in tiny stubs."""
        fixed = 0
        i = 0
        pops = {0x5E, 0x5F, 0x5B, 0x5D, 0x58, 0x59, 0x5A, 0x5C}
        while i + 9 <= len(out):
            if out[i:i + 3] == b'\x48\xc7\xc0' and out[i + 7] in pops and out[i + 8] == 0xC3:
                out[i + 7] = 0x90
                fixed += 1
                i += 9
                continue
            i += 1
        return fixed

    def _fix_corrupted_align_prologues(self, out: bytearray) -> int:
        """Restore ``and rsp,-16`` when stray x86 bytes replace it after align ``sub rsp,0x20``."""
        align_sub = b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20'
        and16 = b'\x48\x83\xe4\xf0'
        fixed = 0
        start = 0
        while start < len(out) - len(align_sub) - 4:
            i = out.find(align_sub, start)
            if i < 0:
                break
            off = i + len(align_sub)
            if out[off:off + 4] != and16:
                out[off:off + 4] = and16
                fixed += 1
            start = i + 1
        return fixed

    def _nop_empty_align_stubs(self, out: bytearray) -> int:
        """Drop orphan ``push r13`` align wrappers that realign the stack but emit no call."""
        if self._cmd_no_hacks:
            return 0
        pro = b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'
        epi = b'\x4c\x89\xec\x41\x5d'
        fixed = 0
        start = 0
        while start < len(out) - len(pro) - len(epi):
            i = out.find(pro, start)
            if i < 0:
                break
            j = i + len(pro)
            end = None
            for k in range(j, min(j + 8, len(out) - len(epi) + 1)):
                gap = out[j:k]
                if 0xE8 in gap or 0xFF in gap:
                    break
                if out[k:k + len(epi)] == epi:
                    end = k + len(epi)
                    break
            if end is not None:
                out[i:end] = b'\x90' * (end - i)
                fixed += 1
            start = i + 1
        return fixed

    def _pure_align_stub_pro_epilogue(self) -> Tuple[bytes, bytes]:
        pro = bytearray()
        self._emit_call_align_prologue(pro, 0)
        epi = bytearray()
        self._emit_call_align_epilogue(epi, 0)
        return bytes(pro), bytes(epi)

    def _pure_call_target_plausible(self, out: bytearray, tgt: int) -> bool:
        """Reject IAT thunks / epilogue tails as direct E8 call destinations."""
        if tgt < 0 or tgt + 2 > len(out):
            return False
        if out[tgt:tgt + 2] == b'\xff\x25':
            return False
        # Epilogue tails — Capstone happily decodes ``pop rbp`` as a real insn
        # when a call lands mid-``pop r13`` (``41 5d``), so a mnemonic-only gate
        # is not enough.  Translated Win2000 helpers never *enter* on a pop /
        # leave / xor-rax-before-ret; those are always the previous function's
        # teardown (cmd ``call 0x151c9`` → ``pop rbp; xor rax; ret`` AV).
        if 0x58 <= out[tgt] <= 0x5f:  # pop rax..rdi
            return False
        if out[tgt] == 0x41 and 0x58 <= out[tgt + 1] <= 0x5f:  # pop r8..r15
            return False
        if out[tgt] == 0xc9:  # leave
            return False
        if out[tgt:tgt + 3] in (b'\x48\x31\xc0', b'\x4c\x89\xec', b'\x48\x89\xec'):
            return False  # xor rax,rax / mov rsp,r13 / mov rsp,rbp
        if out[tgt:tgt + 2] in (b'\x41\x5d', b'\x4c\x89'):
            return False
        if self._pure_is_corrupt_x86_hybrid(out, tgt):
            return False
        if tgt + 3 <= len(out) and out[tgt:tgt + 3] in (
                b'\x89\x44\x24', b'\x89\x04\x24', b'\x89\x54\x24'):
            return False
        # Mid-instruction landings (e.g. into ``jne`` imm) are never valid.
        if HAS_CAPSTONE and tgt + 8 <= len(out):
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                ins = list(md.disasm(bytes(out[tgt:tgt + 16]), tgt, count=1))
                if not ins or ins[0].address != tgt:
                    return False
                if ins[0].mnemonic in ('db', '.byte', 'invalid'):
                    return False
            except CsError:
                return False
        return True

    def _pure_ff35_entry_rank(self, out: bytearray, off: int) -> int:
        """Lower is better: prefer canonical ``movabs r11, imm`` global helpers."""
        if off + 3 <= len(out) and out[off:off + 3] == b'\x49\xbb':
            return 0
        if off + 2 <= len(out) and out[off:off + 2] == b'\xff\x35':
            return 2
        return 1

    def _pure_entry_after_prev_ret(self, out: bytearray, tgt_x86: int,
                                   rva_map: Dict[int, int]) -> Optional[int]:
        """Snap a collapsed entry forward past the previous function's ``ret``.

        rva_map[entry] very often lands a few bytes early — inside the *previous*
        function's epilogue tail (a run of pop / mov rsp,* / leave ending in
        ``ret``) — so a caller jumps into register restores or a bare ``ret`` and
        unwinds to garbage.  When the recorded slot is a *clean* epilogue, the
        real entry is the instruction right after that ``ret`` (skipping
        nop/int3/zero padding).  The snap is validated with the function's own
        forward interior maps, which cluster on the true body, so it is
        prologue-shape agnostic and therefore universal across every Win2000
        binary (it fixes mov-eax-imm, push-imm, cmp-[esp+4], … entries alike
        without a bespoke rule for each).
        """
        base = rva_map.get(tgt_x86)
        if base is None or not (0 <= base < len(out) - 1):
            return None
        i = base
        end = min(len(out) - 1, base + 28)
        ret_end: Optional[int] = None
        # ── Allow up to 24 bytes of non-epilogue bytes before the epilogue ──
        # Some entries map a few bytes before the shared epilogue (padding
        # zeros, a short ``mov rax, imm`` success-return, etc.).  Scan forward
        # byte-by-byte looking for the canonical pop/ret epilogue start.
        non_epi_run = 0
        while i < end:
            b = out[i]
            if 0x58 <= b <= 0x5f:                              # pop r32/r64 (low)
                non_epi_run = 0
                i += 1
                continue
            if b == 0x41 and 0x58 <= out[i + 1] <= 0x5f:       # pop r8..r15
                non_epi_run = 0
                i += 2
                continue
            # ``mov eax, e*; pop…`` — epilogue head, not a non-epi run.
            if (b == 0x89 and i + 2 < len(out)
                    and out[i + 1] in (0xD8, 0xF0, 0xF8, 0xC8, 0xD0)
                    and out[i + 2] in (0x58, 0x59, 0x5A, 0x5B,
                                       0x5C, 0x5D, 0x5E, 0x5F)):
                non_epi_run = 0
                i += 2
                continue
            if bytes(out[i:i + 3]) in (b'\x48\x89\xec', b'\x4c\x89\xec'):
                non_epi_run = 0
                i += 3                                          # mov rsp,rbp / r13
                continue
            if out[i] == 0x48 and out[i + 1] == 0x83 and out[i + 2] == 0xc4:
                non_epi_run = 0
                i += 4                                          # add rsp, imm8
                continue
            if b == 0xc9:                                       # leave
                non_epi_run = 0
                i += 1
                continue
            if b == 0xc3:                                       # ret
                ret_end = i + 1
                break
            if b == 0xc2:                                       # ret imm16
                ret_end = i + 3
                break
            # ── Universal: tolerate a short run of non-epilogue bytes ──
            # e.g. padding NUL (00), NOP (90), INT3 (CC), or a ``mov rax,imm``
            # success-return that falls through to the shared epilogue.
            non_epi_run += 1
            if non_epi_run > 24:
                return None                                    # too far — bail
            i += 1
            continue
        if ret_end is None:
            return None
        j = ret_end
        while j < len(out) and out[j] in (0x90, 0xcc, 0x00):
            j += 1
        cand = j
        if not (0 <= cand < len(out)):
            return None
        if not self._pure_call_target_plausible(out, cand):
            return None
        # Tiny CRT callbacks (cmp [esp+4] / ret 4) often have no interior
        # rva_map density.  Accept when the byte after ``ret`` is a real
        # prologue — especially for discovered fn-entry RVAs.
        if self._x64_entry_prologue_ok(out, cand):
            fwd = 0
            for dr in range(1, 28):
                v = rva_map.get((tgt_x86 + dr) & 0xFFFFFFFF)
                if v is not None and cand <= v <= cand + 0x80:
                    fwd += 1
            if fwd >= 2:
                return cand
            if tgt_x86 in (self._fn_entry_rvas or ()):
                return cand
            # Still accept when the recorded slot itself was clearly an
            # epilogue (pop / xor-eax / mov-eax+pop / ret) — snap is the
            # only recovery.
            b0 = out[base]
            if (b0 in (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0xC3)
                    or out[base:base + 2] in (b'\x31\xc0', b'\x33\xc0')
                    or out[base:base + 3] == b'\x48\x31\xc0'
                    or (b0 == 0x89
                        and out[base + 1] in (0xD8, 0xF0, 0xF8, 0xC8, 0xD0)
                        and base + 2 < len(out)
                        and out[base + 2] in (0x58, 0x59, 0x5A, 0x5B,
                                              0x5C, 0x5D, 0x5E, 0x5F))):
                return cand
        return None

    def _pure_fix_chkstk_prologue_entries(self, out: bytearray,
                                          rva_map: Dict[int, int],
                                          text_data: bytes,
                                          text_rva: int) -> int:
        """Force every ``mov eax,imm; call __chkstk`` entry onto its real body.

        These large-frame prologues are the ones whose rva_map slot most often
        collapses into a neighbouring epilogue (the 0xA4E7 switch-parser bug).
        Running this authoritatively *before* the call-repair passes means every
        downstream CALL/align-stub repair resolves against the correct entry, so
        a single fix here propagates universally to all callers.
        """
        if not self._cmd_no_hacks:
            return 0
        # ENABLED BY DEFAULT (opt out with DISABLE_CHKSTK=1).
        #
        # This pass snaps a chkstk-prologue function's rva_map slot onto its
        # ``mov rax,imm; …; call __chkstk`` entry so calls to large-frame
        # functions resolve onto the real body.  Earlier this regressed (the
        # 0xA4E7 wcschr crash at ~68k) because of three now-fixed bugs:
        #   1. the spurious post-__chkstk callee-save entry (0xA4F1) — rejected
        #      by ``_is_post_chkstk_callee_save``;
        #   2. the CALL re-pointer hijacking an adjacent unrelated call — fixed
        #      in ``_pure_repair_chkstk_prologue_calls`` (only junk/duplicate
        #      sites are repointed now);
        #   3. the translated __chkstk leaving RSP 8 bytes low (``lea rcx,
        #      [rsp+8]`` not doubled) — fixed in ``_fix_alloca_probe_epilogues``.
        # With all three fixed, cmd's ``/c`` parser (0xA4E7) now executes and
        # returns correctly and the trace runs PAST the old 202,344 baseline.
        # Disable only for debugging regressions.
        if os.environ.get('DISABLE_CHKSTK'):
            return 0
        need: Set[int] = set(self._fn_entry_rvas or ())
        if self._x86_cf:
            need |= self._x86_cf.call_targets
        fixed = 0
        for func in need:
            fo = func - text_rva
            if not (0 <= fo and fo + 10 <= len(text_data)):
                continue
            if text_data[fo] != 0xB8 or text_data[fo + 5] != 0xE8:
                continue
            snap = self._pure_chkstk_prologue_entry_for_x86(
                out, func, text_data, text_rva, rva_map)
            if snap is not None and rva_map.get(func) != snap:
                if func == self._dbg_rva:
                    print(f"        [DBG chkfix {func:#x}] "
                          f"{rva_map.get(func)!r} -> {snap:#x}")
                rva_map[func] = snap
                fixed += 1
        return fixed

    def _pure_fix_broken_chkstk_calls(self, out: bytearray) -> int:
        """Repoint every large-frame ``call __chkstk`` that lost its target.

        A chkstk-prologue is ``mov rax,imm`` + the RCX/RDX/R8/R9 shadow spill +
        ``call __chkstk``. When a function is re-emitted by the swallowed-entry
        heal pass, that interior probe ``call`` is frequently left as its rel=0
        placeholder (``call $+5``) — the heal blob's deferred branches are not
        reconciled against the alloca probe — so the 0x2464-byte frame is never
        allocated and the body scribbles over the return address / spilled args
        (cmd 0xA4E7 heal copy). Find each opener whose ``call`` does NOT land on
        the single translated __chkstk body and snap it there. Universal: keyed
        on the prologue shape + the unique chkstk fingerprint, not any binary.
        """
        ck = self._pure_chkstk_entry_off(out)
        if ck is None:
            return 0

        def _is_chkstk_body(t: int) -> bool:
            return (0 <= t < len(out) - 6
                    and (out[t:t + 5] == b'\x3d\x00\x10\x00\x00'
                         or out[t:t + 6] == b'\x51\x3d\x00\x10\x00\x00'))

        fixed = 0
        openers = (b'\x48\xc7\xc0', b'\xb8')  # mov rax,imm32 / mov eax,imm32
        for opener in openers:
            olen = len(opener) + 4  # opcode bytes + imm32
            start = 0
            while True:
                p = out.find(opener, start)
                if p < 0:
                    break
                start = p + 1
                c = p + olen
                # Prefer the canonical arg-spill between opener and call.  Some
                # large-frame prologues emit ``mov rax,imm; call`` directly
                # (homes already written via ``mov [rbp+…],r*``); allow that
                # only when the call currently lands on a non-prologue /
                # epilogue slot — never retarget a sane ordinary callee.
                had_spill = out[c:c + len(_CHKSTK_ARG_SPILL)] == _CHKSTK_ARG_SPILL
                if had_spill:
                    c += len(_CHKSTK_ARG_SPILL)
                if c + 5 > len(out) or out[c] != 0xE8:
                    continue
                crel = int.from_bytes(out[c + 1:c + 5], 'little', signed=True)
                tgt = (c + 5 + crel) & 0xFFFFFFFFFFFFFFFF
                # Leave correctly-resolved probes alone; only repair the ones
                # whose call missed the body (``call $+5`` heal placeholder).
                if _is_chkstk_body(tgt):
                    continue
                # Accept the thin jmp/thunk immediately before the probe body
                # (rva_map often lands on that slot).
                if abs(int(tgt) - int(ck)) <= 16:
                    continue
                if not had_spill:
                    # ``mov rax,imm; call X`` is common for ordinary helpers.
                    # MSVC large-frame probes are uniquely imm >= 4KiB in
                    # EAX/RAX immediately before the call.  Do NOT skip just
                    # because X looks like a prologue — call-sync frequently
                    # aims these at heap helpers (cmd locale init 0xA12C →
                    # HeapAlloc-shaped body), the frame is never allocated,
                    # and [rbp-locals] clobber the return address.
                    imm = struct.unpack_from('<I', out, p + len(opener))[0]
                    if imm < 0x1000:
                        continue
                struct.pack_into('<i', out, c + 1, ck - (c + 5))
                fixed += 1
        return fixed

    def _pure_unhijack_nonprobe_chkstk_calls(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget ordinary calls that were wrongly aimed at __chkstk.

        Near-prologue snap / sync can pull a normal ``call`` onto the
        ``cmp eax,0x1000`` chkstk opener (now ``prologue_ok``).  The switch
        parser at x86 ``0xA4E7`` then does ``call 0x195d2`` → ``call __chkstk``
        and treats the probe return as a string pointer (wcscpy into .text).
        Real probes are only ``mov rax/eax,imm`` (+ optional home spill) then
        ``call``; anything else targeting chkstk is reclaimed.

        Matching prefers *function-local direct-call ordinals*: within each
        mapped entry, the N-th real ``E8`` in x64 lines up with the N-th
        direct ``E8`` in x86 (FF15→``call reg`` drops out of both sides).
        That survives collapsed interior rva_map slots and rip-rel VAs that
        no longer equal ``_relocate_imm`` of the x86 abs32 load.
        """
        if not self._cmd_no_hacks:
            return 0
        ck = self._pure_chkstk_entry_off(out)
        if ck is None:
            return 0

        def _is_real_probe(call_off: int) -> bool:
            # mov rax, imm32 ; [spill] ; call
            if call_off >= 7 and out[call_off - 7:call_off - 4] == b'\x48\xc7\xc0':
                if call_off >= 7 + len(_CHKSTK_ARG_SPILL):
                    pre = call_off - len(_CHKSTK_ARG_SPILL)
                    if out[pre - 7:pre - 4] == b'\x48\xc7\xc0' and out[
                            pre:call_off] == _CHKSTK_ARG_SPILL:
                        return True
                imm = struct.unpack_from('<I', out, call_off - 4)[0]
                return imm >= 0x1000
            # mov eax, imm32 ; [spill] ; call
            if call_off >= 5 and out[call_off - 5] == 0xB8:
                if call_off >= 5 + len(_CHKSTK_ARG_SPILL):
                    pre = call_off - len(_CHKSTK_ARG_SPILL)
                    if out[pre - 5] == 0xB8 and out[pre:call_off] == _CHKSTK_ARG_SPILL:
                        return True
                imm = struct.unpack_from('<I', out, call_off - 4)[0]
                return imm >= 0x1000
            return False

        def _map_to_off(v: int) -> int:
            """Live rva_map stores blob offsets; DUMP_RVA_MAP stores final RVAs."""
            if 0 <= v < len(out):
                return v
            tr = int(getattr(self, '_pure_heal_text_rva', None) or text_rva or 0)
            if tr and v >= tr and (v - tr) < len(out):
                return v - tr
            return v

        def _retarget(call_off: int, tgt_x86: int) -> bool:
            if self._is_alloca_probe_rva(tgt_x86):
                return False
            cand = self._pure_find_sane_entry_for_x86(
                out, tgt_x86, rva_map, text_data, text_rva)
            if cand is None or cand == ck:
                return False
            if not self._x64_entry_prologue_ok(out, cand):
                return False
            if not self._pure_call_target_plausible(out, cand):
                return False
            struct.pack_into('<i', out, call_off + 1, cand - (call_off + 5))
            return True

        fixed = 0
        claimed: Set[int] = set()
        fn_rvas = sorted(r for r in (self._fn_entry_rvas or ()) if r in rva_map)
        use_cs = bool(HAS_CAPSTONE)
        md32 = Cs(CS_ARCH_X86, CS_MODE_32) if use_cs else None
        md64 = Cs(CS_ARCH_X86, CS_MODE_64) if use_cs else None
        if md32 is not None:
            md32.detail = True
        if md64 is not None:
            md64.detail = True

        for idx, entry in enumerate(fn_rvas):
            base = _map_to_off(int(rva_map[entry]))
            if base is None or not (0 <= base < len(out)):
                continue
            # Next x86 fn; x64 end must be a *later* mapped slot (collapsed
            # maps often place the next entry earlier in the blob).
            if idx + 1 < len(fn_rvas):
                x86_end = int(fn_rvas[idx + 1])
            else:
                x86_end = entry + 0x1000
            end = min(base + max(0x200, (x86_end - entry) * 8), len(out))
            for k in range(idx + 1, len(fn_rvas)):
                e2 = _map_to_off(int(rva_map[fn_rvas[k]]))
                if e2 is not None and e2 > base:
                    end = min(e2, end)
                    break
            # Direct near calls only — Capstone avoids E8 immediates in
            # switch tables; FF15/call-reg drop out on both sides.
            x86_tgts: List[int] = []
            o0 = entry - text_rva
            o1 = min(x86_end - text_rva, len(text_data))
            if o0 < 0 or o1 <= o0:
                continue
            if md32 is not None:
                for insn in md32.disasm(bytes(text_data[o0:o1]),
                                        self.old_base + entry):
                    if insn.mnemonic != 'call' or not insn.operands:
                        continue
                    op = insn.operands[0]
                    if op.type != X86_OP_IMM:
                        continue
                    x86_tgts.append((op.imm - self.old_base) & 0xFFFFFFFF)
            else:
                for off in range(o0, max(0, o1 - 5)):
                    if text_data[off] != 0xE8:
                        continue
                    xrel = struct.unpack_from('<i', text_data, off + 1)[0]
                    x86_tgts.append((text_rva + off + 5 + xrel) & 0xFFFFFFFF)
            x64_offs: List[int] = []
            if md64 is not None and end > base:
                for insn in md64.disasm(bytes(out[base:end]), 0):
                    if insn.mnemonic != 'call' or not insn.operands:
                        continue
                    op = insn.operands[0]
                    if op.type != X86_OP_IMM:
                        continue
                    # Capstone VA was 0-based on the slice → blob offset
                    x64_offs.append(base + int(insn.address))
            else:
                for i in range(base, max(base, end - 5)):
                    if out[i] != 0xE8:
                        continue
                    if not self._e8_byte_is_real_call(out, i):
                        continue
                    x64_offs.append(i)
            for j, i in enumerate(x64_offs):
                if j >= len(x86_tgts):
                    break
                if i + 5 > len(out) or out[i] != 0xE8:
                    continue
                rel = struct.unpack_from('<i', out, i + 1)[0]
                if i + 5 + rel != ck:
                    continue
                if _is_real_probe(i):
                    continue
                if _retarget(i, x86_tgts[j]):
                    claimed.add(i)
                    fixed += 1

        # Fallback: VA / near-entry distance for sites outside fn windows.
        for i in range(len(out) - 5):
            if i in claimed or out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            if i + 5 + rel != ck:
                continue
            if _is_real_probe(i):
                continue
            new_tgt: Optional[int] = None
            best_d = 999999
            pre_vas: Set[int] = set()
            nb = int(getattr(self, 'new_base', 0) or 0)
            tr_abs = int(getattr(self, '_pure_heal_text_rva', None) or text_rva)
            for p in range(max(0, i - 48), i - 6):
                if out[p:p + 3] == b'\x66\x8b\x05':
                    disp = struct.unpack_from('<i', out, p + 3)[0]
                    pre_vas.add((nb + tr_abs + p + 7 + disp) & 0xFFFFFFFFFFFFFFFF)
                elif out[p:p + 2] == b'\x8b\x05':
                    disp = struct.unpack_from('<i', out, p + 2)[0]
                    pre_vas.add((nb + tr_abs + p + 6 + disp) & 0xFFFFFFFFFFFFFFFF)
                elif out[p:p + 2] in (b'\x48\xb8', b'\x49\xbb') and p + 10 <= i:
                    pre_vas.add(struct.unpack_from('<Q', out, p + 2)[0])
            # Owning entry: nearest mapped fn entry at or before this call.
            owner_anchor: Optional[int] = None
            for entry in reversed(fn_rvas):
                a = _map_to_off(int(rva_map[entry]))
                if a <= i:
                    owner_anchor = a
                    break
            for off in range(len(text_data) - 5):
                if text_data[off] != 0xE8:
                    continue
                x86_rva = (text_rva + off) & 0xFFFFFFFF
                xrel = struct.unpack_from('<i', text_data, off + 1)[0]
                tgt_x86 = (x86_rva + 5 + xrel) & 0xFFFFFFFF
                if self._is_alloca_probe_rva(tgt_x86):
                    continue
                matched_va = False
                for back in range(1, 14):
                    po = off - back
                    if po < 0:
                        break
                    va = None
                    if text_data[po] == 0xA1 and po + 5 <= off:
                        va = struct.unpack_from('<I', text_data, po + 1)[0]
                    elif text_data[po:po + 2] == b'\x66\xa1' and po + 6 <= off:
                        va = struct.unpack_from('<I', text_data, po + 2)[0]
                    if va is None:
                        continue
                    exp = self._relocate_imm(va) & 0xFFFFFFFFFFFFFFFF
                    if exp in pre_vas:
                        matched_va = True
                        break
                anchor = rva_map.get(x86_rva)
                if anchor is not None:
                    anchor = _map_to_off(int(anchor))
                if anchor is None:
                    for d in range(1, 12):
                        a = rva_map.get((x86_rva - d) & 0xFFFFFFFF)
                        if a is not None:
                            anchor = _map_to_off(int(a))
                            break
                dist = abs(i - anchor) if anchor is not None else 999999
                if owner_anchor is not None and 0 <= i - owner_anchor < 0x800:
                    # Call site map collapsed; still accept x86 calls that
                    # belong to the same owning entry window.
                    if dist > 160:
                        dist = abs(i - owner_anchor) + 50
                if not matched_va and dist > 160:
                    continue
                score = 0 if matched_va else dist
                cand = self._pure_find_sane_entry_for_x86(
                    out, tgt_x86, rva_map, text_data, text_rva)
                if cand is None or cand == ck:
                    continue
                if not self._x64_entry_prologue_ok(out, cand):
                    continue
                if score < best_d:
                    best_d = score
                    new_tgt = cand
            if new_tgt is not None:
                struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
                fixed += 1
        return fixed

    def _pure_chkstk_prologue_targets(self, rva_map: Dict[int, int],
                                      text_data: bytes,
                                      text_rva: int) -> Dict[int, int]:
        """{x86 entry -> shim offset} for every ``mov eax,imm; call __chkstk`` fn."""
        out_map: Dict[int, int] = {}
        need: Set[int] = set(self._fn_entry_rvas or ())
        if self._x86_cf:
            need |= self._x86_cf.call_targets
        for func in need:
            fo = func - text_rva
            if not (0 <= fo and fo + 10 <= len(text_data)):
                continue
            if text_data[fo] != 0xB8 or text_data[fo + 5] != 0xE8:
                continue
            rel = int.from_bytes(text_data[fo + 6:fo + 10], 'little', signed=True)
            if not self._is_alloca_probe_rva((func + 10 + rel) & 0xFFFFFFFF):
                continue
            snap = rva_map.get(func)
            if snap is not None:
                out_map[func] = snap
        return out_map

    def _pure_repair_chkstk_prologue_calls(self, out: bytearray,
                                           rva_map: Dict[int, int],
                                           text_data: bytes,
                                           text_rva: int) -> int:
        """Final, targeted: re-point CALLs to ``mov eax,imm; call __chkstk`` fns.

        The dozens of generic call-repair passes occasionally re-snap a call to
        one of these large-frame entries onto a neighbour (the 0xA4E7 case maps
        ``call`` onto an unrelated 0x208-frame helper).  Running last and ONLY
        for chkstk-prologue targets — whose rva_map slots were just corrected —
        guarantees their callers land on the real body without disturbing any
        other call.  Universal: keyed purely on the prologue shape.
        """
        if not self._cmd_no_hacks:
            return 0
        # ENABLED BY DEFAULT (opt out with DISABLE_CHKSTK=1) — paired with
        # _pure_fix_chkstk_prologue_entries.  Only repoints calls whose current
        # target is a junk/swallowed slot or a stale duplicate copy (never a
        # sane unrelated entry), so the adjacent-call hijack that caused the
        # 0xA4E7 wcschr crash can no longer happen.
        if os.environ.get('DISABLE_CHKSTK'):
            return 0
        targets = self._pure_chkstk_prologue_targets(rva_map, text_data, text_rva)
        if not targets:
            return 0
        # Anchor at each x86 ``call rel32`` whose destination is a chkstk-prologue
        # function, then patch the matching translated E8 (plain or align-stub)
        # nearest that call's anchor — the same proven mechanism as the generic
        # x86-anchored repair, but scoped to these collision-prone entries.
        fixed = 0
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (text_rva + off + 5 + rel) & 0xFFFFFFFF
            if tgt_x86 not in targets:
                continue
            anchor = rva_map.get(x86_rva)
            if anchor is None or not (0 <= anchor < len(out)):
                continue
            want = targets[tgt_x86]
            if not (0 <= want < len(out)):
                continue
            sites = self._pure_call_e8_sites_near_anchor(out, anchor)
            if not sites:
                continue
            # Framesize of the target ``mov eax,imm32; call __chkstk`` prologue,
            # used to recognise an alternate (duplicate) translated copy.
            fo = tgt_x86 - text_rva
            framesize: Optional[int] = None
            if 0 <= fo and fo + 5 <= len(text_data) and text_data[fo] == 0xB8:
                framesize = int.from_bytes(text_data[fo + 1:fo + 5], 'little')

            def _repointable(site: int) -> bool:
                """Only redirect a call that is currently junk or a stale copy.

                Deferred-push argument flushing routinely emits an UNRELATED
                neighbouring call (e.g. cmd 0xAB1D) closer to this call's
                rva_map anchor than the real one.  The old ``nearest site``
                heuristic hijacked that neighbour and pointed it into the
                large-frame body, leaving the genuine call aimed at a junk
                duplicate (the 0xA4E7 wcschr crash).  Repoint a site ONLY when
                its current target is a swallowed epilogue/thunk slot or
                another copy of THIS same chkstk prologue — never when it
                already resolves to a sane, unrelated function entry.
                """
                cur = site + 5 + struct.unpack_from('<i', out, site + 1)[0]
                if cur == want:
                    return False
                if not (0 <= cur < len(out)):
                    return True
                if self._pure_mapping_is_swallowed_slot(out, cur):
                    return True
                if (framesize is not None
                        and self._pure_is_chkstk_opener_at(out, cur, framesize)):
                    return True
                return False

            cand = [s for s in sites if _repointable(s)]
            if not cand:
                continue
            best = min(cand, key=lambda s: abs(s - anchor))
            struct.pack_into('<i', out, best + 1, want - (best + 5))
            fixed += 1
        return fixed

    @staticmethod
    def _pure_is_chkstk_opener_at(out: bytearray, off: int,
                                  framesize: int) -> bool:
        """True when *off* begins a ``mov rax/eax,framesize`` chkstk copy."""
        if off < 0 or off + 5 > len(out):
            return False
        simm = framesize - 0x100000000 if framesize >= 0x80000000 else framesize
        if (out[off:off + 3] == b'\x48\xc7\xc0' and off + 7 <= len(out)
                and struct.unpack_from('<i', out, off + 3)[0] == simm):
            return True
        if (out[off] == 0xb8 and off + 5 <= len(out)
                and int.from_bytes(out[off + 1:off + 5], 'little') == framesize):
            return True
        return False

    @staticmethod
    def _pure_frameless_shadow_homes_len_at(out: bytearray, off: int) -> int:
        """Bytes of ``_FRAMELESS_SHADOW_HOMES`` starting at *off*, else 0."""
        n = len(_FRAMELESS_SHADOW_HOMES)
        if 0 <= off and off + n <= len(out) and out[off:off + n] == _FRAMELESS_SHADOW_HOMES:
            return n
        return 0

    @staticmethod
    def _pure_frameless_shadow_homes_len_before(out: bytearray, off: int) -> int:
        """Bytes of ``_FRAMELESS_SHADOW_HOMES`` immediately before *off*, else 0."""
        n = len(_FRAMELESS_SHADOW_HOMES)
        if off >= n and out[off - n:off] == _FRAMELESS_SHADOW_HOMES:
            return n
        return 0

    @staticmethod
    def _pure_snap_back_past_frameless_shadow_homes(out: bytearray, off: int) -> int:
        """If *off* sits right after Win64 shadow homes, return the homes start."""
        back = HealingMixin._pure_frameless_shadow_homes_len_before(out, off)
        return off - back if back else off

    def _snap_calls_back_past_frameless_shadow_homes(self, out: bytearray) -> int:
        """Retarget E8s that land on the first insn after injected shadow homes.

        Translator prepends ``mov [rsp+8],rcx…r9`` before frameless stdcall
        bodies; rva_map / VA fingerprints often pin the *movabs* that follows.
        Callers that skip the homes leave RCX/RDX unsaved → null IAT args
        (cmd SetEnvironmentVariableW name=NULL).

        Skip the ``mov rax/eax,imm; homes; lea r15; call __chkstk`` spill —
        those homes sit *after* the real entry opener.
        """
        if not self._cmd_no_hacks:
            return 0
        home_n = len(_FRAMELESS_SHADOW_HOMES)
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt < home_n or tgt >= len(out):
                continue
            if out[tgt - home_n:tgt] != _FRAMELESS_SHADOW_HOMES:
                continue
            home_at = tgt - home_n
            # chkstk spill: homes follow ``mov rax/eax, imm``
            if (home_at >= 7
                    and out[home_at - 7:home_at - 4] == b'\x48\xc7\xc0'):
                continue
            if home_at >= 5 and out[home_at - 5] == 0xB8:
                continue
            # chkstk spill continuation ``lea r15,[rsp+4]``
            if out[tgt:tgt + 5] == b'\x4c\x8d\x7c\x24\x04':
                continue
            struct.pack_into('<i', out, i + 1, home_at - (i + 5))
            fixed += 1
        return fixed

    @staticmethod
    def _pure_is_movabs_iat_call_body(out: bytearray, off: int) -> bool:
        """True when *off* is ``movabs r64,imm; mov r64,[r64]; call r64``."""
        if off < 0 or off + 15 > len(out):
            return False
        if out[off] not in (0x48, 0x49, 0x4C, 0x4D):
            return False
        if not (0xB8 <= out[off + 1] <= 0xBF):
            return False
        # mov rax,[rax] (48 8b 00) + call r/m (ff d0..) — or short call rax
        if out[off + 10:off + 13] == b'\x48\x8b\x00' and out[off + 13] == 0xFF:
            return True
        if out[off + 10:off + 12] == b'\xff\xd0':
            return True
        return False

    def _pure_snap_back_past_mid_align_iat_entry(self, out: bytearray,
                                                 off: int) -> int:
        """If *off* is an IAT body sitting after the callee's align pro, snap back.

        Frameless helpers often look like::

            homes; push r13; …; and rsp,-16; movabs rax,iat; call rax; epi

        ``rva_map`` pins the ``movabs``, so callers land mid-wrapper.  The
        orphaned ``mov rsp,r13; pop r13`` then tears down the *caller's*
        align frame → ``ret`` to NULL (cmd InitCmd → GetVersion helper).
        """
        if off < 0 or off >= len(out):
            return off
        pro, _epi = self._pure_align_stub_pro_epilogue()
        pl = len(pro)
        if off < pl or out[off - pl:off] != pro:
            return off
        if not self._pure_is_movabs_iat_call_body(out, off):
            return off
        new = off - pl
        home_n = len(_FRAMELESS_SHADOW_HOMES)
        if (new >= home_n
                and out[new - home_n:new] == _FRAMELESS_SHADOW_HOMES):
            new -= home_n
        return new

    def _snap_calls_back_past_mid_align_iat_entry(self, out: bytearray) -> int:
        """Retarget E8s that land on align-wrapped IAT bodies (see snap helper)."""
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            new_tgt = self._pure_snap_back_past_mid_align_iat_entry(out, tgt)
            if new_tgt == tgt:
                continue
            if not self._x64_entry_prologue_ok(out, new_tgt):
                continue
            struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
            fixed += 1
        return fixed

    def _pure_fix_ebp_local_ptr_dword_store(self, out: bytearray) -> int:
        """Widen ``lea rax,[rbp+N]; mov dword [rbp-4],eax`` pointer locals to qword.

        MSVC ``push ecx; lea eax,[ebp+10]; mov [ebp-4],eax; lea eax,[ebp-4]``
        (cmd PutMsg ``0x13a62``) becomes a 4-byte local under a frame.  On
        x64 the stored pointer must be 8 bytes — a dword store leaves the
        high half as the *saved RBP*.  When the caller used ``mov rbp,imm``
        as a size scratch (InitCmd ``0x20c``), FormatMessage then walks
        ``0x0000020C00xxxxxx`` and AVs in ntdll.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 19:
            # sub rsp, 4
            if out[i:i + 4] != b'\x48\x83\xec\x04':
                i += 1
                continue
            # lea rax, [rbp+disp8]
            if out[i + 4:i + 7] != b'\x48\x8d\x45':
                i += 1
                continue
            disp = out[i + 7]
            # mov dword ptr [rbp-4], eax
            if out[i + 8:i + 11] != b'\x89\x45\xfc':
                i += 1
                continue
            # lea rax, [rbp-4]
            if out[i + 11:i + 15] != b'\x48\x8d\x45\xfc':
                i += 1
                continue
            # Steal the REX from the following ``mov rcx, [rbp+0x10]`` so the
            # replacement stays size-matched (19 bytes).
            if out[i + 15:i + 19] != b'\x48\x8b\x4d\x10':
                i += 1
                continue
            repl = bytearray()
            repl += b'\x48\x83\xec\x08'            # sub rsp, 8
            repl += b'\x48\x8d\x45' + bytes([disp])  # lea rax, [rbp+disp]
            repl += b'\x48\x89\x45\xf8'            # mov qword [rbp-8], rax
            repl += b'\x48\x8d\x45\xf8'            # lea rax, [rbp-8]
            repl += b'\x8b\x4d\x10'                # mov ecx, [rbp+0x10]
            assert len(repl) == 19
            out[i:i + 19] = repl
            # The Arguments register load still uses ``lea r9,[rbp-4]`` a few
            # insns later — retarget it onto the widened slot.
            j = i + 19
            end = min(len(out) - 4, i + 19 + 24)
            while j < end:
                if out[j:j + 4] == b'\x4c\x8d\x4d\xfc':  # lea r9, [rbp-4]
                    out[j:j + 4] = b'\x4c\x8d\x4d\xf8'  # lea r9, [rbp-8]
                    break
                if out[j:j + 4] == b'\x48\x8d\x4d\xfc':  # lea rcx, [rbp-4]
                    out[j:j + 4] = b'\x48\x8d\x4d\xf8'
                    break
                j += 1
            fixed += 1
            i += 19
        return fixed

    def _pure_fix_call_ebp_minus4_as_neg4_abs(self, out: bytearray) -> int:
        """Fix ``call [ebp-4]`` rematerialized as ``movabs rax, 0xfffffffc``.

        x86 keeps a local function pointer at ``[ebp-4]`` (cmd path builder
        ``0xce7d`` / ``0xcf90``).  Translation turns the call into::

            movabs rax, 0xfffffffc
            mov rax, [rax]
            call rax

        Park the pointer in callee-saved R12 (length-neutral store) and
        ``call r12`` at the site; wrap the frame with ``push/pop r12``.
        """
        if not self._cmd_no_hacks:
            return 0
        bad = bytes.fromhex('48b8fcffffff00000000488b00ffd0')
        assert len(bad) == 15
        fixed = 0
        i = 0
        while True:
            at = out.find(bad, i)
            if at < 0:
                break
            i = at + 1
            store = out.rfind(b'\x89\x45\xfc', max(0, at - 0x500), at)
            if store < 0:
                continue
            # Locate frame sub rsp,0x210 and matching pop rdi..leave;ret
            sub = -1
            for s in range(store, max(0, store - 0x300), -1):
                if out[s:s + 7] == bytes.fromhex('4881ec10020000'):
                    sub = s
                    break
            if sub < 0:
                continue
            epi = out.find(b'\x5f\x5e\x5b\xc9\xc3', store, min(len(out), at + 0x80))
            if epi < 0:
                epi = out.find(b'\x5f\x5e\x5b\xc9\xc3', at, min(len(out), at + 0x40))
            if epi < 0:
                continue
            # push r12 after sub rsp (detour the 7-byte sub)
            cave_pro = self._pure_find_padding_cave(out, 7 + 2 + 5)
            if cave_pro < 0:
                continue
            body = bytearray(bytes.fromhex('4881ec10020000'))  # sub rsp, 0x210
            body += b'\x41\x54'  # push r12
            body += b'\xe9' + struct.pack(
                '<i', (sub + 7) - (cave_pro + len(body) + 5))
            out[cave_pro:cave_pro + len(body)] = body
            out[sub:sub + 7] = (
                b'\xe9' + struct.pack('<i', cave_pro - (sub + 5))
                + b'\x90\x90')
            # pop r12 before leave;ret
            cave_epi = self._pure_find_padding_cave(out, 8)
            if cave_epi < 0:
                continue
            eb = bytes.fromhex('5f5e5b415cc9c3')  # pops; pop r12; leave; ret
            out[cave_epi:cave_epi + len(eb)] = eb
            out[epi:epi + 5] = b'\xe9' + struct.pack(
                '<i', cave_epi - (epi + 5))
            # store: mov [rbp-4], eax → mov r12, rax
            out[store:store + 3] = b'\x49\x89\xc4'
            # call site → call r12; nops
            out[at:at + 15] = b'\x41\xff\xd4' + b'\x90' * 12
            fixed += 1
            i = at + 15
        return fixed

    def _pure_fix_formatmessage_call_rbx(self, out: bytearray) -> int:
        """Reload FormatMessage into RBX before ``call rbx`` when RBX was clobbered.

        CmdPutMsg keeps ``FormatMessageW`` in RBX, but the fallback trampoline
        ``jmp``s into the shared ``push r13; …; call rbx`` tail from Echo while
        Echo still holds ``rbx=0x100`` (grow sentinel).  Reload from the IAT
        slot used by the PutMsg prologue (``movabs rbx, iat; mov rbx,[rbx]``).
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, 'new_base', 0) or 0)
        iat = 0
        # Prefer the real FormatMessageW IAT cell.  Blindly taking the first
        # ``movabs rbx,imm; mov rbx,[rbx]`` after ``push rbx`` mis-binds the
        # reload stub to an earlier import (cmd: RegEnumKeyW @ 0x85140) and
        # the fallback ``call rbx`` AVs in ADVAPI32.
        name_map = getattr(self, '_iat_name_to_new_rva', None) or {}
        for (dll, fn), rva in name_map.items():
            if fn.lower() == 'formatmessagew':
                iat = nb + int(rva)
                break
        if not iat:
            # Belt-and-braces: resolve through the x86 IAT cell (name known
            # from parse_imports) → final .idata slot.  Never fall through
            # to the pattern search with a stale map.
            iat = self._resolve_import_iat_va('FormatMessageW') or 0
        if not iat:
            # PutMsg-shaped: cmp [rbp+0x10],0x13d ; push rbx ; movabs rbx,iat
            i = 0
            while i < len(out) - 20:
                if (out[i:i + 2] == b'\x48\xbb'
                        and out[i + 10:i + 13] == b'\x48\x8b\x1b'):
                    window = out[max(0, i - 32):i]
                    if (b'\x53' in window  # push rbx
                            and (b'\x81\x7d\x10\x3d\x01\x00\x00' in window
                                 or b'\x83\x7d\x10\x3d' in window)):
                        iat = struct.unpack_from('<Q', out, i + 2)[0]
                        break
                i += 1
        if not iat:
            return 0
        fixed = 0
        # Pattern: mov rax,0x1770; mov [rsp+0x28],rax; mov [rsp+0x30],rax/…; call rbx
        # Rewrite call rbx (ff d3) sites that follow 0x1770 nSize home into a
        # same-size trampoline jump to a reload+call+ret stub is heavy; instead
        # patch the fallback trampoline's final jmp to bounce through reload.
        # Trampoline tail: b9 00 30 00 00 31 d2 41 b8 3d 01 00 00 45 31 c9 e9
        pat = bytes.fromhex('b90030000031d241b83d0100004531c9e9')
        j = 0
        while True:
            at = out.find(pat, j)
            if at < 0:
                break
            jmp_at = at + len(pat) - 1  # e9
            old_rel = struct.unpack_from('<i', out, jmp_at + 1)[0]
            old_targ = jmp_at + 5 + old_rel
            # Build: movabs rbx,iat; mov rbx,[rbx]; jmp old_targ
            stub = bytearray()
            stub += b'\x48\xbb' + struct.pack('<Q', iat)
            stub += b'\x48\x8b\x1b'
            stub += b'\xe9' + struct.pack('<i', 0)  # filled below
            need = len(stub) + 4
            # Always append — scavenging end-of-text pad collides with the
            # EF42 empty-node stub and shreds both.
            pad_at = len(out)
            out.extend(b'\x00' * need)
            struct.pack_into('<i', stub, len(stub) - 4,
                             old_targ - (pad_at + len(stub)))
            out[pad_at:pad_at + len(stub)] = stub
            struct.pack_into('<i', out, jmp_at + 1,
                             pad_at - (jmp_at + 5))
            fixed += 1
            j = jmp_at + 5
        # Also rewrite remaining wrong Application/System movabs tips.
        # Prefer the UTF-16 literal in the PE64 text blob — searching the
        # original x86 .text yields nb+old_rva (same as the bad tip).
        nb = int(self.new_base or 0)
        pe_text_rva = int(getattr(self, 'text_rva', 0) or 0x1000)
        app_needle = b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00'
        sys_needle = b'S\x00y\x00s\x00t\x00e\x00m\x00\x00\x00'
        app_idx = bytes(out).find(app_needle)
        sys_idx = -1
        if app_idx > 0:
            # CmdPutMsg keeps System immediately before Application.
            near = bytes(out).rfind(sys_needle, max(0, app_idx - 0x40), app_idx)
            if near >= 0:
                sys_idx = near
        if sys_idx < 0:
            sys_idx = bytes(out).find(sys_needle)
        for idx, bad_offs in (
                (app_idx, (0x1B78,)),
                (sys_idx, (0x1B68, 0x1B58)),
        ):
            if idx < 0:
                continue
            good = nb + pe_text_rva + idx
            tip_g = struct.pack('<Q', good)
            for bad_off in bad_offs:
                bad = nb + bad_off
                if good == bad:
                    continue
                tip_b = struct.pack('<Q', bad)
                k = 0
                while True:
                    at = out.find(tip_b, k)
                    if at < 0:
                        break
                    if at >= 2 and out[at - 2:at] in (b'\x48\xb8', b'\x48\xbb'):
                        out[at:at + 8] = tip_g
                        fixed += 1
                    k = at + 1
        return fixed

    def _pure_fix_flag_clobber_before_jcc(self, out: bytearray) -> int:
        """Fix ``cmp/test; add rsp, imm; jcc`` where ADD destroys the branch flags.

        VC6 ``push arg; call; pop; cmp/test; jcc`` becomes Win64
        ``push; call; cmp/test; add rsp,8; jcc``.  The ``add rsp`` between the
        flag producer and the jcc rewrites ZF from RSP, so the wrong arm is
        taken (setjmp longjmp-path, or call-site failure → stack overflow).
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 12:
            # (cmp eax,ebx | test eax,eax) ; add rsp, imm8 ; jcc rel32
            cmpb = out[i:i + 2]
            if (cmpb in (b'\x39\xd8', b'\x85\xc0')
                    and out[i + 2:i + 5] == b'\x48\x83\xc4'
                    and out[i + 6] == 0x0f
                    and 0x80 <= out[i + 7] <= 0x8f):
                imm = out[i + 5:i + 6]
                jcc = out[i + 6:i + 8]
                rel = out[i + 8:i + 12]
                # add rsp, imm ; test eax, eax ; jcc rel32  (same 12 bytes)
                out[i:i + 12] = (
                    b'\x48\x83\xc4' + imm  # add rsp, imm
                    + b'\x85\xc0'          # test eax, eax
                    + jcc + rel           # same condition + target
                )
                fixed += 1
                i += 12
                continue
            i += 1
        return fixed

    def _pure_fix_ff15_ret_sled_entries(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Re-pin ``call/jmp [IAT]`` helpers whose tip collapsed onto a ret-sled.

        ``rva_map`` occasionally parks an ``ff15`` opener on padding ``ret``s
        before an unrelated neighbour (cmd GetVersion helper ``0xacab`` →
        ``0x446aa``).  The relocated IAT slot as a ``movabs`` immediate is a
        unique fingerprint of the real body; snap back past align/homes and
        retarget every E8 still aiming at the sled or mid-align body.
        """
        if not self._cmd_no_hacks:
            return 0
        need: Set[int] = set(self._fn_entry_rvas or ())
        if self._x86_cf:
            need |= self._x86_cf.call_targets
        fixed = 0
        for func in sorted(need):
            fo = func - text_rva
            if not (0 <= fo and fo + 6 <= len(text_data)):
                continue
            if text_data[fo:fo + 2] not in (b'\xff\x15', b'\xff\x25'):
                continue
            old_iat = struct.unpack_from('<I', text_data, fo + 2)[0]
            new_iat = None
            if hasattr(self, '_resolve_iat_slot_va'):
                try:
                    new_iat = self._resolve_iat_slot_va(old_iat)
                except Exception:
                    new_iat = None
            if not new_iat:
                new_iat = self._relocate_imm(old_iat) & 0xFFFFFFFFFFFFFFFF
            va_le = struct.pack('<Q', new_iat & 0xFFFFFFFFFFFFFFFF)
            body = None
            pos = 0
            while pos < len(out) - 15:
                j = out.find(b'\x48\xb8', pos)
                if j < 0:
                    break
                if out[j + 2:j + 10] == va_le and self._pure_is_movabs_iat_call_body(
                        out, j):
                    body = j
                    break
                pos = j + 1
            if body is None:
                continue
            ent = self._pure_snap_back_past_mid_align_iat_entry(out, body)
            if not self._x64_entry_prologue_ok(out, ent):
                continue
            old = rva_map.get(func)
            if old == ent:
                # Still retarget E8s stuck on the movabs body / old sled.
                pass
            else:
                # Only rewrite clearly-broken tips (ret / epilogue / wrong).
                broken = (old is None
                          or old < 0 or old >= len(out)
                          or out[old] == 0xC3
                          or out[old] == 0xC2
                          or not self._pure_mapped_entry_sane(
                              out, old, func, text_data, text_rva))
                if not broken and old == body:
                    broken = True  # mid-align body — prefer homes entry
                if not broken:
                    continue
                rva_map[func] = ent
                fixed += 1
            # Retarget E8s at old tip, ret-sled run, or movabs body.
            retarget_from: Set[int] = {body, ent}
            if old is not None:
                retarget_from.add(old)
                # Consume a short run of padding rets at *old*.
                k = old
                while k < len(out) and out[k] in (0xC3, 0x90, 0xCC, 0x00):
                    retarget_from.add(k)
                    k += 1
                    if k - old > 32:
                        break
            for i in range(len(out) - 5):
                if out[i] != 0xE8:
                    continue
                if not self._e8_byte_is_real_call(out, i):
                    continue
                rel = struct.unpack_from('<i', out, i + 1)[0]
                tgt = i + 5 + rel
                if tgt not in retarget_from or tgt == ent:
                    continue
                struct.pack_into('<i', out, i + 1, ent - (i + 5))
                fixed += 1
        return fixed

    @staticmethod
    def _pure_snap_chkstk_home_spill_entry(out: bytearray, off: int) -> int:
        """If *off* is the first arg-home after ``mov rax/eax,imm``, return the mov."""
        if off < 0 or off + 4 > len(out):
            return off
        if out[off:off + 4] != b'\x48\x89\x4c\x24':
            return off
        if off >= 7 and out[off - 7:off - 4] == b'\x48\xc7\xc0':
            return off - 7
        if off >= 5 and out[off - 5] == 0xB8:
            return off - 5
        return off

    def _pure_chkstk_prologue_entry_for_x86(
            self, out: bytearray, tgt_x86: int,
            text_data: bytes, text_rva: int,
            rva_map: Dict[int, int]) -> Optional[int]:
        """Snap an x86 ``mov eax,imm32; call __chkstk`` large-frame entry.

        A great many Win2000 functions open with the MSVC large-frame stack
        probe ``mov eax,<framesize>; call __chkstk``.  That two-instruction
        prologue routinely has its rva_map slot collapse into the *previous*
        function's aligned-call / epilogue tail, so a caller lands
        mid-instruction and the whole function is skipped — this is exactly
        what swallowed cmd's ``/c`` switch parser at 0xA4E7 (its slot pointed
        into the preceding ``srand`` wrapper, so ``call 0xA4E7`` just ran srand
        and returned).  The translated opener is an exact, collision-resistant
        fingerprint: ``mov rax/eax,<framesize>`` immediately followed by a
        direct ``call`` to the single translated __chkstk body.  Locate that
        pair and pick the occurrence nearest the recorded slot.  Purely
        prologue-driven, so it is universal across every Win2000 binary rather
        than specific to cmd.
        """
        fo = tgt_x86 - text_rva
        if not (0 <= fo and fo + 10 <= len(text_data)):
            return None
        if text_data[fo] != 0xB8 or text_data[fo + 5] != 0xE8:  # mov eax,imm; call rel32
            return None
        imm = int.from_bytes(text_data[fo + 1:fo + 5], 'little')
        rel = int.from_bytes(text_data[fo + 6:fo + 10], 'little', signed=True)
        call_tgt = (tgt_x86 + 10 + rel) & 0xFFFFFFFF
        if not self._is_alloca_probe_rva(call_tgt):
            return None
        simm = imm - 0x100000000 if imm >= 0x80000000 else imm
        openers = (
            b'\x48\xc7\xc0' + struct.pack('<i', simm),   # mov rax, imm32 (sign-extended)
            b'\xb8' + struct.pack('<I', imm),            # mov eax, imm32
        )

        def _is_chkstk_body(t: int) -> bool:
            # Bytes of the __chkstk probe: ``cmp eax,0x1000`` optionally behind a
            # ``push rcx``.  Used only as a *preference*, since at heal time the
            # prologue's chkstk ``call`` rel32 may still be a deferred (rel=0)
            # placeholder — so the opener+call shape alone must remain sufficient.
            return (0 <= t < len(out) - 6
                    and (out[t:t + 5] == b'\x3d\x00\x10\x00\x00'
                         or out[t:t + 6] == b'\x51\x3d\x00\x10\x00\x00'))

        hint = rva_map.get(tgt_x86)
        # candidates: (chkstk_resolved_pref, distance, offset); 0 sorts first.
        cands: List[Tuple[int, int, int]] = []
        for opener in openers:
            olen = len(opener)
            start = 0
            while True:
                p = out.find(opener, start)
                if p < 0:
                    break
                start = p + 1
                c = p + olen
                # Skip the canonical chkstk arg-spill prologue (RCX/RDX/R8/R9 ->
                # shadow space + ``lea r15,[rsp+4]``) emitted between the opener
                # and ``call __chkstk`` so the fingerprint still resolves.
                if out[c:c + len(_CHKSTK_ARG_SPILL)] == _CHKSTK_ARG_SPILL:
                    c += len(_CHKSTK_ARG_SPILL)
                if c + 5 > len(out) or out[c] != 0xE8:
                    continue
                if not self._pure_call_target_plausible(out, p):
                    continue
                crel = int.from_bytes(out[c + 1:c + 5], 'little', signed=True)
                pref = 0 if _is_chkstk_body((c + 5 + crel) & 0xFFFFFFFFFFFFFFFF) else 1
                d = abs(p - hint) if hint is not None else p
                cands.append((pref, d, p))
        if not cands:
            return None
        cands.sort()
        return cands[0][2]

    def _pure_find_sane_entry_for_x86(self, out: bytearray, tgt_x86: int,
                                      rva_map: Dict[int, int],
                                      text_data: bytes, text_rva: int) -> Optional[int]:
        """Locate a shim offset that actually matches the x86 entry at *tgt_x86*."""
        if self._is_alloca_probe_rva(tgt_x86):
            ck = self._pure_chkstk_entry_off(out)
            if ck is not None:
                return ck
        # Entry/interior consistency FIRST: when the recorded entry and a
        # nearby mapped x86 byte point far apart, the interior's chunk is
        # the authoritative body (entry tip landed in a stale copy / another
        # function — cmd parser 0x13A9C → mid-formatter while 0x13A9D →
        # remat copy; print fn 0x158EE → 0x5B38C while 0x15901 → 0x2A7DE).
        # Snap the entry onto the interior-implied prologue.
        direct0 = rva_map.get(tgt_x86)
        if direct0 is not None:
            for d in range(1, 0x40):
                nxt0 = rva_map.get((tgt_x86 + d) & 0xFFFFFFFF)
                if nxt0 is None or abs(nxt0 - direct0) <= 0x200:
                    continue
                for cand in (nxt0 - d, nxt0 - d + 1, nxt0 - d - 1):
                    ok = (0 <= cand < len(out)
                          and self._pure_call_target_plausible(out, cand)
                          and self._pure_mapped_entry_sane(
                              out, cand, tgt_x86, text_data, text_rva))
                    if os.environ.get('DBG_MMF') \
                            and tgt_x86 in (0x158EE, 0x13A9C):
                        print(f"[SNAP-DBG] tgt=0x{tgt_x86:X} d={d:#x} "
                              f"direct=0x{direct0:X} nxt=0x{nxt0:X} "
                              f"cand=0x{cand:X} ok={ok}")
                    if ok:
                        return cand
                break
        # Prefer absolute-VA fingerprints for ``push [global]`` / abs-load /
        # abs-store entries *before* epilogue-forward snaps.  A collapsed
        # rva_map slot on an unrelated epilogue would otherwise win and leave
        # callers targeting the wrong body (cmd 0xAC4F EnterCS helper).
        exp_va_early = self._pure_ff35_global_va_from_x86(
            text_data, text_rva, tgt_x86)
        if exp_va_early is None:
            func_off_e = tgt_x86 - text_rva
            if 0 <= func_off_e < len(text_data):
                head_e = text_data[func_off_e:func_off_e + 16]
                gva_e = self._pure_x86_global_store_va_from_head(head_e)
                if gva_e is None:
                    gva_e = self._pure_x86_abs_load_va_from_head(head_e)
                if gva_e is not None:
                    exp_va_early = self._relocate_imm(gva_e)
        if exp_va_early is not None:
            va_le = struct.pack('<Q', exp_va_early & 0xFFFFFFFFFFFFFFFF)
            ranked: List[Tuple[int, int]] = []
            for prefix in (b'\x49\xbb', b'\x48\xb8'):
                pos = 0
                while pos < len(out) - 10:
                    j = out.find(prefix, pos)
                    if j < 0:
                        break
                    if out[j + 2:j + 10] == va_le:
                        ent = self._pure_snap_back_past_frameless_shadow_homes(
                            out, j)
                        if (self._pure_call_target_plausible(out, ent)
                                and self._x64_entry_prologue_ok(out, ent)
                                and self._pure_mapped_entry_sane(
                                    out, ent, tgt_x86, text_data, text_rva)):
                            ranked.append(
                                (self._pure_ff35_entry_rank(out, ent), ent))
                    pos = j + 1
            if ranked:
                ranked.sort(key=lambda x: x[0])
                return ranked[0][1]

        frameless = self._pure_find_frameless_entry_for_x86(
            out, tgt_x86, text_data, text_rva, rva_map)
        if frameless is not None:
            return frameless
        # Large-frame functions opening with ``mov eax,imm; call __chkstk`` get
        # their slot collapsed into the previous function's tail; the translated
        # ``mov rax/eax,imm; call <chkstk>`` opener is a unique fingerprint.
        chk_pro = self._pure_chkstk_prologue_entry_for_x86(
            out, tgt_x86, text_data, text_rva, rva_map)
        if chk_pro is not None:
            return chk_pro
        # The function's OWN recorded slot (and a short forward window past it)
        # is the most authoritative source whenever it actually matches the x86
        # prologue.  rva_map frequently points a handful of bytes early — into
        # the preceding function's epilogue tail — so scan forward from the slot
        # to snap onto the true entry.  Prefer this over interior inference,
        # which can be badly skewed when a function's interior byte-maps landed
        # in an unrelated chunk.
        direct = rva_map.get(tgt_x86)
        if direct is not None and 0 <= direct < len(out):
            direct = self._pure_snap_chkstk_home_spill_entry(out, direct)
            bases = (direct, self._refine_shim_target_off(out, tgt_x86, direct))
            for base in bases:
                for d in range(0, 12):
                    cand = base + d
                    if (0 <= cand < len(out)
                            and self._pure_call_target_plausible(out, cand)
                            and self._pure_mapped_entry_sane(
                                out, cand, tgt_x86, text_data, text_rva)):
                        cand = self._pure_snap_chkstk_home_spill_entry(out, cand)
                        # Snap *after* sanity: mid-align IAT bodies are the
                        # fingerprint for ``ff15`` x86 heads, but callers must
                        # land on the preceding homes / align pro.
                        return self._pure_snap_back_past_mid_align_iat_entry(
                            out, cand)
        # Universal collapsed-epilogue recovery: when the recorded slot is a
        # clean epilogue tail, snap to the entry right after its ``ret`` (proven
        # by forward interior maps).  Catches entries whose prologue shape the
        # idiom checks above don't recognise (mov eax,imm; push imm; …).
        snapped = self._pure_entry_after_prev_ret(out, tgt_x86, rva_map)
        if snapped is not None:
            return snapped
        inferred = self._pure_infer_entry_from_interior_map(
            out, tgt_x86, rva_map, text_data, text_rva)
        if (inferred is not None
                and self._pure_accept_inferred_entry(
                    out, inferred, tgt_x86, text_data, text_rva)):
            return inferred
        exp_va = self._pure_ff35_global_va_from_x86(
            text_data, text_rva, tgt_x86)
        if exp_va is None:
            func_off = tgt_x86 - text_rva
            if 0 <= func_off < len(text_data):
                head = text_data[func_off:func_off + 16]
                gva = self._pure_x86_global_store_va_from_head(head)
                if gva is None:
                    gva = self._pure_x86_abs_load_va_from_head(head)
                if gva is not None:
                    exp_va = self._relocate_imm(gva)
        if exp_va is not None:
            va_le = struct.pack('<Q', exp_va & 0xFFFFFFFFFFFFFFFF)
            for prefix in (b'\x49\xbb', b'\x48\xb8'):
                pos = 0
                while pos < len(out) - 10:
                    j = out.find(prefix, pos)
                    if j < 0:
                        break
                    if out[j + 2:j + 10] == va_le:
                        ent = self._pure_snap_back_past_frameless_shadow_homes(
                            out, j)
                        if (self._pure_call_target_plausible(out, ent)
                                and self._x64_entry_prologue_ok(out, ent)
                                and self._pure_mapped_entry_sane(
                                    out, ent, tgt_x86, text_data, text_rva)):
                            return ent
                    pos = j + 1
        seen: Set[int] = set()
        candidates: List[Tuple[int, int, int]] = []
        for rva, mapped in sorted(rva_map.items(), key=lambda x: x[0]):
            if not (tgt_x86 <= rva <= tgt_x86 + 24):
                continue
            for base in (mapped, self._refine_shim_target_off(out, tgt_x86, mapped)):
                # Scan a small window behind the recorded base too: rva_map
                # sometimes points a few bytes early (into the prior epilogue)
                # *or* a few bytes late, so a forward-only scan can miss the
                # true entry that sits just before ``base``.
                for delta in range(-8, 32):
                    off = base + delta
                    if off in seen or off < 0 or off >= len(out):
                        continue
                    seen.add(off)
                    if (self._pure_call_target_plausible(out, off)
                            and self._pure_mapped_entry_sane(
                                out, off, tgt_x86, text_data, text_rva)):
                        candidates.append(
                            (self._pure_ff35_entry_rank(out, off), rva, off))
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]))
            return candidates[0][2]
        return None

    def _pure_reconcile_swallowed_rva_map(self, out: bytearray,
                                          rva_map: Dict[int, int],
                                          text_data: bytes, text_rva: int) -> int:
        """Point rva_map entries at sane translations instead of swallowed slots."""
        if not self._cmd_no_hacks:
            return 0
        need: Set[int] = set(self._fn_entry_rvas or ())
        if self._x86_cf:
            need |= self._x86_cf.call_targets
        fixed = 0
        for func in sorted(need):
            off = rva_map.get(func)
            if off is not None:
                # Mid-align IAT bodies are valid *fingerprints* for ``ff15``
                # heads, but callers must enter on the preceding homes.  Snap
                # only when the body itself is sane — never leave the map on
                # homes alone and then re-resolve (that loses the +0x21 body
                # and collapses onto a neighbouring ret-sled).
                mid = self._pure_snap_back_past_mid_align_iat_entry(out, off)
                if mid != off:
                    if (self._pure_mapped_entry_sane(
                            out, off, func, text_data, text_rva)
                            and self._x64_entry_prologue_ok(out, mid)):
                        rva_map[func] = mid
                        off = mid
                        fixed += 1
                        # Trusted homes entry — skip further re-resolve.
                        continue
                else:
                    snapped = self._pure_snap_back_past_frameless_shadow_homes(
                        out, off)
                    if snapped != off:
                        rva_map[func] = snapped
                        off = snapped
                        fixed += 1
            func_off = func - text_rva
            x86_head = (text_data[func_off:func_off + 2]
                        if 0 <= func_off < len(text_data) else b'')
            if off is not None and self._pure_mapped_entry_sane(
                    out, off, func, text_data, text_rva):
                func_off = func - text_rva
                x86_head = (text_data[func_off:func_off + 16]
                            if 0 <= func_off < len(text_data) else b'')
                need_repoint = False
                if (x86_head[:2] == b'\xff\x35'
                        and out[off:off + 3] == b'\x49\xbb'
                        and not self._pure_ff35_global_va_match(
                            out, off, func, text_data, text_rva)):
                    need_repoint = True
                elif self._pure_x86_global_store_va_from_head(x86_head) is not None:
                    gva = self._pure_x86_global_store_va_from_head(x86_head)
                    exp = self._relocate_imm(gva)
                    if not self._pure_x64_region_has_va(out, off, 48, exp):
                        need_repoint = True
                if need_repoint:
                    sane = self._pure_find_sane_entry_for_x86(
                        out, func, rva_map, text_data, text_rva)
                    if sane is not None and sane != off:
                        rva_map[func] = sane
                        fixed += 1
                continue
            if off is not None:
                sane = self._pure_find_sane_entry_for_x86(
                    out, func, rva_map, text_data, text_rva)
                if sane is not None and sane != off:
                    rva_map[func] = sane
                    fixed += 1
                    continue
            inferred = self._pure_infer_entry_from_interior_map(
                out, func, rva_map, text_data, text_rva)
            if (inferred is not None
                    and not self._pure_accept_inferred_entry(
                        out, inferred, func, text_data, text_rva)):
                inferred = None
            if inferred is not None:
                if off is None or off != inferred:
                    rva_map[func] = inferred
                    fixed += 1
                continue
            if off is None:
                continue
            if (self._pure_mapping_is_swallowed_slot(out, off)
                    or self._pure_is_corrupt_x86_hybrid(out, off)
                    or not self._pure_call_target_plausible(out, off)):
                sane = self._pure_find_sane_entry_for_x86(
                    out, func, rva_map, text_data, text_rva)
                if sane is not None and sane != off:
                    rva_map[func] = sane
                    fixed += 1
        return fixed

    def _pure_resolve_x86_call_target(self, out: bytearray, tgt_x86: int,
                                      rva_map: Dict[int, int],
                                      text_data: bytes, text_rva: int,
                                      reject: Optional[int] = None) -> Optional[int]:
        """Resolve an x86 CALL destination to a shim offset (pure mode)."""
        hint = rva_map.get(tgt_x86)
        if hint is not None and hint != reject:
            if hint < 0 or hint >= len(out):
                hint = None
            else:
                refined = self._refine_shim_target_off(out, tgt_x86, hint)
                if (self._pure_call_target_plausible(out, refined)
                        and self._pure_mapped_entry_sane(
                            out, refined, tgt_x86, text_data, text_rva)):
                    return refined
        # Interior-map inference BEFORE the fingerprint scan when no hint is
        # recorded: interiors pin the live copy, while the VA-fingerprint
        # scan can match a STALE duplicate island (cmd 0x1EF0 dead island).
        if hint is None:
            inferred = self._pure_infer_entry_from_interior_map(
                out, tgt_x86, rva_map, text_data, text_rva)
            if (inferred is not None and inferred != reject
                    and 0 <= inferred < len(out)
                    and self._pure_call_target_plausible(out, inferred)
                    and self._pure_accept_inferred_entry(
                        out, inferred, tgt_x86, text_data, text_rva)):
                rva_map[tgt_x86] = inferred
                return inferred
        sane = self._pure_find_sane_entry_for_x86(
            out, tgt_x86, rva_map, text_data, text_rva)
        if sane is not None and sane != reject and 0 <= sane < len(out):
            rva_map[tgt_x86] = sane
            return sane
        resolved = self._resolve_call_target_off(out, tgt_x86, rva_map)
        if (resolved is not None and resolved != reject
                and self._pure_call_target_plausible(out, resolved)):
            if (tgt_x86 in (getattr(self._x86_cf, 'epilogue_labels', {}) or {})
                    or self._pure_mapped_entry_sane(
                        out, resolved, tgt_x86, text_data, text_rva)):
                rva_map[tgt_x86] = resolved
                return resolved
        return None

    def _pure_repatch_align_stub_self_calls(self, out: bytearray,
                                            rva_map: Dict[int, int],
                                            text_data: bytes,
                                            text_rva: int) -> int:
        """Fix E8 inside align stubs that still call the stub prologue (infinite recursion)."""
        if not self._cmd_no_hacks:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pro_len = len(pro)
        fixed = 0
        seen: Set[int] = set()

        def _tgt_from_x86_call_at(cand: int) -> Optional[int]:
            off = cand - text_rva
            if not (0 <= off < len(text_data) - 5):
                return None
            if text_data[off] != 0xE8:
                return None
            # Reject E8 bytes inside immediates (cmd ``mov eax,[0x4ad1fae8]``
            # embeds ``E8`` and poisoned the forward scan from efd6).
            if HAS_CAPSTONE:
                # Disassemble a short window ending at *cand*; require an insn
                # that starts exactly on the E8.
                win_lo = max(0, off - 0x20)
                md = Cs(CS_ARCH_X86, CS_MODE_32)
                md.detail = True
                hit = False
                for ins in md.disasm(bytes(text_data[win_lo:off + 5]),
                                     self.old_base + text_rva + win_lo):
                    if (ins.address - self.old_base) == cand:
                        if (ins.mnemonic == 'call' and ins.operands
                                and ins.operands[0].type == X86_OP_IMM):
                            hit = True
                        break
                    if (ins.address - self.old_base) > cand:
                        break
                if not hit:
                    return None
            rel_x = struct.unpack_from('<i', text_data, off + 1)[0]
            return (cand + 5 + rel_x) & 0xFFFFFFFF

        def _tgt_from_push_imm_match(imm: int, search_rva: int) -> Optional[int]:
            """``mov rcx, imm`` before stub ↔ x86 ``push imm; call`` near *search_rva*."""
            lo = max(text_rva, search_rva - 0x20)
            hi = min(text_rva + len(text_data) - 5, search_rva + 0x100)
            for cand in range(lo, hi):
                off = cand - text_rva
                # push ib / push iz
                if imm <= 0x7F and text_data[off] == 0x6A and text_data[off + 1] == (imm & 0xFF):
                    t = _tgt_from_x86_call_at(cand + 2)
                    if t is not None:
                        return t
                if (text_data[off] == 0x68
                        and struct.unpack_from('<I', text_data, off + 1)[0] == (imm & 0xFFFFFFFF)):
                    t = _tgt_from_x86_call_at(cand + 5)
                    if t is not None:
                        return t
            return None

        for p in range(len(out) - pro_len - len(epi) - 5):
            if out[p:p + pro_len] != pro:
                continue
            j = p + len(pro)
            if j in seen or j + 5 > len(out) or out[j] != 0xE8:
                continue
            if out[j + 5:j + 5 + len(epi)] != epi:
                continue
            rel = struct.unpack_from('<i', out, j + 1)[0]
            if j + 5 + rel != p:
                continue
            tgt_x86 = None
            # Orphan islands (cmd efd6→bad copy) often have no rva_map byte
            # *inside* the stub — widen to the preceding function body.
            anchor_rvas = [rva for rva, mapped in rva_map.items()
                           if p - 0x100 <= mapped <= j + 5]
            for anchor in sorted(anchor_rvas, reverse=True):
                # Prefer an E8 at/after the anchor (call follows pushes).
                for delta in range(0, 0x80):
                    tgt_x86 = _tgt_from_x86_call_at(anchor + delta)
                    if tgt_x86 is not None:
                        break
                if tgt_x86 is None:
                    for delta in range(-16, 0):
                        tgt_x86 = _tgt_from_x86_call_at(anchor + delta)
                        if tgt_x86 is not None:
                            break
                if tgt_x86 is not None:
                    break
            if tgt_x86 is None and p >= 7:
                # ``mov rcx, imm32`` immediately before the align prologue
                # (cmd ``push 8; call ff31`` → ``mov rcx,8; call``).
                imm = None
                if (out[p - 7] == 0x48 and out[p - 6] == 0xC7
                        and out[p - 5] == 0xC1):
                    imm = struct.unpack_from('<I', out, p - 4)[0]
                if imm is not None:
                    hint = max(anchor_rvas) if anchor_rvas else (text_rva + 0x1000)
                    tgt_x86 = _tgt_from_push_imm_match(imm, hint)
            if tgt_x86 is None:
                if os.environ.get('DBG_SELFCALL'):
                    anch = ', '.join(
                        f'x86=0x{xa:X}@off+0x{rva_map[xa]:X}'
                        for xa in sorted(anchor_rvas,
                                         key=lambda x: abs(rva_map[x] - p))[:4])
                    with open(os.environ.get('DBG_SELFCALL_LOG',
                                             '_selfcall_dbg.txt'), 'a') as dbg_f:
                        dbg_f.write(f'REPATCH-NO-TGT stub=+0x{p:X} '
                                    f'call=+0x{j:X} anchors=[{anch}]\n')
                continue
            new_tgt = self._pure_resolve_x86_call_target(
                out, tgt_x86, rva_map, text_data, text_rva, reject=p)
            if new_tgt is None:
                if os.environ.get('DBG_SELFCALL'):
                    with open(os.environ.get('DBG_SELFCALL_LOG',
                                             '_selfcall_dbg.txt'), 'a') as dbg_f:
                        dbg_f.write(f'REPATCH-RESOLVE-FAIL stub=+0x{p:X} '
                                    f'call=+0x{j:X} tgt_x86=0x{tgt_x86:X}\n')
                continue
            struct.pack_into('<i', out, j + 1, new_tgt - (j + 5))
            seen.add(j)
            fixed += 1
        return fixed

    def _pure_repair_all_align_stub_calls(self, out: bytearray,
                                          rva_map: Dict[int, int],
                                          text_data: bytes,
                                          text_rva: int) -> int:
        """Re-resolve E8 inside call-align stubs, one x86 ``call`` per stub site."""
        if not self._cmd_no_hacks:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pro_len = len(pro)
        epi_len = len(epi)
        fixed = 0
        paired: Set[int] = set()
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            mapped = rva_map.get(x86_rva)
            if mapped is None:
                continue
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (x86_rva + 5 + rel) & 0xFFFFFFFF
            new_tgt = self._pure_resolve_x86_call_target(
                out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                continue
            best_j: Optional[int] = None
            best_dist = 999999
            j_lo = max(pro_len, mapped - 8)
            # Large-frame functions put the align stub far past the nearest
            # mapped byte (chkstk wipe).  Search the whole remaining body
            # rather than a fixed +64/+96 window.
            j_hi = min(len(out) - 5, mapped + 0x800)
            for j in range(j_lo, j_hi):
                if out[j] != 0xE8 or j in paired:
                    continue
                scan = j - pro_len
                if scan < 0 or out[scan:scan + pro_len] != pro:
                    continue
                if out[j + 5:j + 5 + epi_len] != epi:
                    continue
                dist = abs(j - mapped)
                if dist < best_dist:
                    best_dist = dist
                    best_j = j
            if best_j is None:
                continue
            paired.add(best_j)
            cur = best_j + 5 + struct.unpack_from('<i', out, best_j + 1)[0]
            if cur == new_tgt:
                continue
            struct.pack_into('<i', out, best_j + 1, new_tgt - (best_j + 5))
            fixed += 1
        return fixed

    def _pure_restore_nopped_align_calls(self, out: bytearray,
                                         rva_map: Dict[int, int],
                                         text_data: bytes,
                                         text_rva: int) -> int:
        """Restore E8 rel32 inside align stubs that legacy NOP-out passes erased."""
        if not self._cmd_no_hacks:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        fixed = 0
        seen: Set[int] = set()
        sec_end = text_rva + len(text_data)
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = text_rva + off
            if not (text_rva <= x86_rva < sec_end):
                continue
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (x86_rva + 5 + rel) & 0xFFFFFFFF
            new_tgt = self._pure_resolve_x86_call_target(
                out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                continue
            site = rva_map.get(x86_rva)
            if site is None:
                continue
            for p in range(max(0, site - 8),
                           min(site + 40, len(out) - len(pro) - len(epi))):
                if out[p:p + len(pro)] != pro:
                    continue
                key = p
                if key in seen:
                    break
                j = p + len(pro)
                if j + 5 <= len(out) and out[j] == 0xE8:
                    if out[j + 5:j + 5 + len(epi)] == epi:
                        cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
                        if cur != new_tgt:
                            struct.pack_into('<i', out, j + 1, new_tgt - (j + 5))
                            seen.add(key)
                            fixed += 1
                        break
                k = j
                while k < j + 12 and k < len(out) and out[k] == 0x90:
                    k += 1
                if k > j and k + len(epi) <= len(out) and out[k:k + len(epi)] == epi:
                    rel32 = new_tgt - (j + 5)
                    out[j:j + 5] = b'\xE8' + struct.pack('<i', rel32)
                    seen.add(key)
                    fixed += 1
                    break
        fixed += self._pure_repair_all_align_stub_calls(
            out, rva_map, text_data, text_rva)
        return fixed

    def _pure_find_frameless_entry_for_x86(
            self, out: bytearray, tgt_x86: int,
            text_data: bytes, text_rva: int,
            rva_map: Dict[int, int]) -> Optional[int]:
        """Locate frameless wchar-scan helpers (e.g. wcslen @ 0x6711).

        Many stdcall helpers open with ``mov ecx,[esp+4]`` (cmd list-pop
        ``0x480f`` among them).  Only the double-null / wchar-length shape
        ``test ecx; mov eax,ecx`` + ``cmp word [r32],0`` may use this scanner;
        a bare ``mov ecx,[esp+4]`` match remapped those callers onto wcslen
        and spun forever on a struct pointer (univ52).
        """
        func_off = tgt_x86 - text_rva
        if func_off < 0 or func_off + 12 > len(text_data):
            return None
        if text_data[func_off:func_off + 4] != b'\x8b\x4c\x24\x04':
            return None
        # x86 must itself be the wchar-scan idiom — not merely any esp+4 load.
        x86_head = text_data[func_off:func_off + 16]
        if not (x86_head[4:8] in (b'\x85\xc9\x8b\xc1', b'\x85\xc9\x89\xc8')
                and (b'\x66\x83\x39\x00' in x86_head
                     or b'\x66\x83\x38\x00' in x86_head
                     or b'\x66\x83\x3a\x00' in x86_head)):
            return None
        head_variants = (b'\x85\xc9\x8b\xc1', b'\x85\xc9\x89\xc8')  # test ecx; mov eax,ecx
        hint = rva_map.get(tgt_x86)
        # ``rva_map[tgt]`` alone is unreliable here: for these frameless helpers
        # it frequently lands in an unrelated epilogue, which then drags the
        # proximity search onto a *duplicate* wcslen-shaped helper elsewhere in
        # .text.  The function's own interior byte-maps are far more trustworthy,
        # so anchor the search on the median of the nearby interior mappings.
        anchor = self._pure_interior_anchor(rva_map, tgt_x86, len(out))
        ref = anchor if anchor is not None else hint
        scan_lo = 0
        scan_hi = len(out) - 24
        best: Optional[int] = None
        best_dist = 999999
        for j in range(scan_lo, scan_hi):
            if not any(out[j:j + 4] == h for h in head_variants):
                continue
            win = out[j:j + 24]
            if (b'\x66\x83\x39\x00' not in win
                    and b'\x66\x83\x38\x00' not in win):
                continue
            if not self._pure_call_target_plausible(out, j):
                continue
            dist = abs(j - ref) if ref is not None else j
            if dist < best_dist:
                best_dist = dist
                best = j
        return best

    @staticmethod
    def _pure_interior_anchor(rva_map: Dict[int, int], tgt_x86: int,
                              out_len: int) -> Optional[int]:
        """Robust body anchor from a function's nearby interior mappings.

        rva_map[entry] is often skewed (it lands in the previous function's
        epilogue tail), but the *interior* instruction maps cluster around the
        real translated body.  Take the median mapped offset over a small x86
        window around the entry — the median shrugs off the odd scrambled
        outlier, giving a reliable place to search for the true entry.
        """
        vals: List[int] = []
        for dr in range(-8, 48):
            mp = rva_map.get((tgt_x86 + dr) & 0xFFFFFFFF)
            if mp is not None and 0 <= mp < out_len:
                vals.append(mp)
        if not vals:
            return None
        vals.sort()
        return vals[len(vals) // 2]

    def _pure_authoritative_x86_call_sync(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """One x86 ``call rel32`` → one align-stub E8, in source order.

        Conservative proximity (+96, skip ``__chkstk``) — a whole-function zip
        when stub/call counts differ mis-pairs CRT and exits within ~200 steps.
        Clearly-bad stub targets (mid-movabs / non-prologue) are repaired by
        ``_pure_fix_bad_align_stub_targets`` with a wider window.
        Collapsed rva_map slots that leave the stub just past +96 are handled
        by ``_pure_fix_implausible_align_calls`` (bad targets only).
        """
        if not self._cmd_no_hacks:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        fixed = 0
        used: Set[int] = set()
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (x86_rva + 5 + rel) & 0xFFFFFFFF
            if self._is_alloca_probe_rva(tgt_x86):
                continue
            new_tgt = self._pure_find_sane_entry_for_x86(
                out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                new_tgt = self._pure_resolve_x86_call_target(
                    out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                hint = rva_map.get(tgt_x86)
                if (hint is not None and 0 <= hint < len(out)
                        and self._pure_call_target_plausible(out, hint)):
                    new_tgt = hint
            if new_tgt is None:
                continue
            anchor: Optional[int] = None
            for delta in range(0, 12):
                for key in ((x86_rva - delta) & 0xFFFFFFFF,
                            (x86_rva + delta) & 0xFFFFFFFF):
                    cand = rva_map.get(key)
                    if cand is not None:
                        anchor = cand
                        break
                if anchor is not None:
                    break
            if anchor is None or anchor < 0 or anchor >= len(out):
                continue
            # If pe64 emitted an indirect/IAT call closer to the anchor than
            # any align stub, this x86 E8 has no stub to retarget — leave
            # neighbour stubs alone (cmd 0xef69 setjmp → call rax stole
            # 0xef81's efd6 stub, shifting BA38/FF31 and stacking overflow).
            indir_at: Optional[int] = None
            for i in range(max(0, anchor - 4),
                           min(len(out) - 2, anchor + 48)):
                b0, b1 = out[i], out[i + 1]
                if b0 == 0xFF and b1 in (
                        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                    indir_at = i
                    break
                if b0 == 0xFF and b1 == 0x15:
                    indir_at = i
                    break
            best_j: Optional[int] = None
            best_dist = 999999
            j_lo = max(0, anchor - 8)
            j_hi = min(len(out) - pl - el - 5, anchor + 96)
            for scan in range(j_lo, j_hi):
                if out[scan:scan + pl] != pro:
                    continue
                j = scan + pl
                if j in used or out[j] != 0xE8:
                    continue
                if out[j + 5:j + 5 + el] != epi:
                    continue
                if j + 5 > anchor + 96:
                    continue
                dist = abs(j - anchor)
                if dist < best_dist:
                    best_dist = dist
                    best_j = j
            if best_j is None:
                for j in range(anchor, min(anchor + 96, len(out) - 5)):
                    if out[j] != 0xE8 or j in used:
                        continue
                    if not self._pure_branch_site_ok(out, j):
                        continue
                    dist = abs(j - anchor)
                    if dist < best_dist:
                        best_dist = dist
                        best_j = j
            if best_j is None:
                continue
            if (indir_at is not None
                    and abs(indir_at - anchor) <= best_dist):
                # Abstain only when THIS x86 call was lowered to the indirect
                # (target is ``jmp [iat]`` / import trampoline — cmd setjmp at
                # 0xEF69).  A neighbouring IAT ``call rax`` next to a collapsed
                # rva_map anchor must not block sync of a real align-stub call
                # (cmd 0x1A6A1 → 0x1A9A0 ``_controlfp`` wrapper skipped, then
                # mid-gap insn-snap → AV).
                tgt_off = (tgt_x86 - text_rva) & 0xFFFFFFFF
                is_iat_tramp = False
                if 0 <= tgt_off + 1 < len(text_data):
                    b0 = text_data[tgt_off]
                    b1 = text_data[tgt_off + 1]
                    if b0 == 0xFF and b1 in (0x25, 0x15):
                        is_iat_tramp = True
                if is_iat_tramp or self._is_iat_rva(tgt_x86 & 0xFFFFFFFF):
                    continue
            cur = best_j + 5 + struct.unpack_from('<i', out, best_j + 1)[0]
            if cur != new_tgt:
                struct.pack_into('<i', out, best_j + 1, new_tgt - (best_j + 5))
                fixed += 1
            used.add(best_j)
        return fixed

    def _pure_fix_implausible_align_calls(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget align-stub E8s on epilogue landings or single-push mispairs.

        Broader stub rewrites (univ48) die in CRT within ~1k steps.  Two rules:

        1. **Epilogue landing** — ``pop`` / ``leave`` / ``xor rax`` /
           ``mov rsp,*``.  Latest ±12 anchor, +160 window (cmd ``0x151c9``).

        2. **``push r32; call`` reclaim** — x86 one-register-arg calls whose
           align stub was stolen by sync (cmd ``push edi; call 0x14fe4`` →
           ``0x1ef0``).  Multi-push sites (``push imm; push eax; call``) are
           left alone so good SEH pairings stay intact.
        """
        if not self._cmd_no_hacks:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        win = 160

        owners: List[Tuple[int, int]] = []  # (max_anchor, new_tgt)
        pushreg_owners: List[Tuple[int, int]] = []  # exact/near anchor, new_tgt
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (x86_rva + 5 + rel) & 0xFFFFFFFF
            if self._is_alloca_probe_rva(tgt_x86):
                continue
            new_tgt = self._pure_find_sane_entry_for_x86(
                out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                continue
            if not (self._x64_entry_prologue_ok(out, new_tgt)
                    and self._pure_call_target_plausible(out, new_tgt)):
                continue
            anchors: List[int] = []
            for delta in range(0, 12):
                for key in ((x86_rva - delta) & 0xFFFFFFFF,
                            (x86_rva + delta) & 0xFFFFFFFF):
                    cand = rva_map.get(key)
                    if cand is not None and 0 <= cand < len(out):
                        anchors.append(cand)
            if anchors:
                owners.append((max(anchors), new_tgt))
            # ``push r32`` immediately before ``call`` (50-57), not push imm.
            if off >= 1 and 0x50 <= text_data[off - 1] <= 0x57:
                exact = rva_map.get(x86_rva)
                if exact is None and anchors:
                    exact = max(anchors)
                if exact is not None:
                    pushreg_owners.append((exact, new_tgt))

        def _is_epi(tgt: int) -> bool:
            if tgt < 0 or tgt >= len(out):
                return True
            b = out[tgt]
            if 0x58 <= b <= 0x5f:
                return True
            if b == 0x41 and 0x58 <= out[tgt + 1] <= 0x5f:
                return True
            if b == 0xc9:
                return True
            return out[tgt:tgt + 3] in (
                b'\x48\x31\xc0', b'\x4c\x89\xec', b'\x48\x89\xec')

        fixed = 0
        claimed: Set[int] = set()
        # Rule 1: epilogue landings (stub-centric).
        scan = 0
        while scan < len(out) - pl - el - 5:
            if out[scan:scan + pl] != pro:
                scan += 1
                continue
            j = scan + pl
            if out[j] != 0xE8 or out[j + 5:j + 5 + el] != epi:
                scan += 1
                continue
            cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
            if _is_epi(cur):
                cands = [(abs(j - a), t) for a, t in owners
                         if (a - 8) <= j <= (a + win)]
                if cands:
                    cands.sort()
                    if cands[0][1] != cur:
                        struct.pack_into('<i', out, j + 1,
                                         cands[0][1] - (j + 5))
                        fixed += 1
                        claimed.add(j)
            scan = j + 5
        # Rule 2: ``mov rcx, rDI/SI/BX`` + align stub — translation of
        # ``push edi/esi/ebx; call``.  Owner-centric 1:1 pairing with a
        # tight window: stub→nearest-owner within ±64 stole neighbours
        # (cmd ``push ebx; …; call efd6`` then later ``push ebx; call ff31``
        # both carry ``mov rcx,rbx``, and the first stub was retargeted to
        # ff31 — switch parse never ran efd6, add9 got flags=0 → More?).
        _MOV_RCX_REG = {
            b'\x48\x89\xf9',  # mov rcx, rdi
            b'\x48\x89\xf1',  # mov rcx, rsi
            b'\x48\x89\xd9',  # mov rcx, rbx
            b'\x48\x89\xc1',  # mov rcx, rax
        }
        pushreg_win = 24
        mov_rcx_stubs: List[int] = []
        scan = 0
        while scan < len(out) - pl - el - 5:
            if out[scan:scan + pl] != pro:
                scan += 1
                continue
            j = scan + pl
            if out[j] != 0xE8 or out[j + 5:j + 5 + el] != epi:
                scan += 1
                continue
            if j not in claimed:
                lead = bytes(out[scan - 3:scan]) if scan >= 3 else b''
                if lead in _MOV_RCX_REG:
                    mov_rcx_stubs.append(j)
            scan = j + 5
        claimed_stubs: Set[int] = set(claimed)
        for anchor, new_tgt in sorted(pushreg_owners, key=lambda x: x[0]):
            cands = [(abs(j - anchor), j) for j in mov_rcx_stubs
                     if j not in claimed_stubs
                     and abs(j - anchor) <= pushreg_win]
            if not cands:
                continue
            cands.sort()
            j = cands[0][1]
            cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
            if cur != new_tgt:
                struct.pack_into('<i', out, j + 1, new_tgt - (j + 5))
                fixed += 1
            claimed_stubs.add(j)
        return fixed

    def _pure_rematerialize_nullcheck_iat_wrappers(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Restore thin ``cmp arg0,0 / call [iat] / ret N`` wrappers.

        x86 helpers like cmd ``0x195d2`` (null-check then ``call [MSVCRT!wcschr]``)
        often keep a recognisable ``cmp rcx,0; jne work; xor eax,eax; jmp done``
        skeleton while the *work* path collapses to a bare ``ret`` sled.  Callers
        then return with a garbage RAX and the switch parser walks off into
        recursion / stack overflow.  Rewrite the work path as a standard
        ``sub rsp,0x28; call [iat]; add rsp,0x28; ret`` using the x86 IAT slot.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        if not getattr(self, '_iat_rva_map', None):
            return 0

        def _map_to_off_cands(v: int) -> List[int]:
            # Live rva_map stores blob offsets; dump/_final_rva stores RVAs.
            # Both can be numerically valid offsets into a ~300KB blob
            # (cmd 0x195d2 → dump RVA 0x3038c == also a plausible offset).
            # Prefer the candidate that already hosts a cmp-rcx skeleton.
            raw: List[int] = []
            seen: Set[int] = set()
            tr = int(getattr(self, '_pure_heal_text_rva', None) or text_rva or 0)
            if tr and v >= tr and (v - tr) < len(out):
                o = v - tr
                if o not in seen:
                    raw.append(o)
                    seen.add(o)
            if 0 <= v < len(out) and v not in seen:
                raw.append(v)
                seen.add(v)

            def _has_skel(off: int) -> bool:
                for d in range(0, 16):
                    if (off + d + 4 <= len(out)
                            and out[off + d:off + d + 4]
                            == b'\x48\x83\xf9\x00'):
                        return True
                return False

            ranked = sorted(raw, key=lambda o: (0 if _has_skel(o) else 1, o))
            return ranked

        def _iat_slot_for_va(iat_va: int) -> Optional[int]:
            try:
                slot = self._resolve_iat_slot_va(iat_va)
            except Exception as exc:
                print(f"        [nullchk] resolve fail iat={iat_va:#x}: {exc}",
                      flush=True)
                slot = None
            if slot is not None:
                slot_rva = (slot - self.new_base) & 0xFFFFFFFF
                if slot in iat_slots or slot_rva >= 0x20000:
                    return slot
            # Prefer direct old-base subtraction: x86 FF15 immediates are absolute
            # image VAs (old_base+iat_rva).  ``_imm_to_old_rva`` can miss when the
            # heal blob's preferred base differs from the PE32 parse base.
            candidates = [
                self._imm_to_old_rva(iat_va) & 0xFFFFFFFF,
                (iat_va - int(getattr(self, 'old_base', 0) or 0)) & 0xFFFFFFFF,
                iat_va & 0xFFFFFFFF,
            ]
            lo = iat_va & 0xFFFF
            if 0x1000 <= lo <= 0x3000:
                candidates.append(lo)
            for old_rva in candidates:
                mapped = (self._iat_rva_map or {}).get(old_rva)
                if mapped is not None:
                    return self.new_base + mapped
            # Name-based fallback when shim reorder drops the old IAT RVA key.
            name_map = getattr(self, '_iat_name_to_new_rva', None) or {}
            pe = getattr(self, 'pe', None)
            if pe is not None and name_map:
                try:
                    for imp in pe.parse_imports():
                        dll = imp['dll'].lower()
                        for fn in imp['functions']:
                            if not fn.get('name'):
                                continue
                            if (self.old_base + fn.get('iat_rva', 0)) & 0xFFFFFFFF == iat_va & 0xFFFFFFFF:
                                mapped = name_map.get((dll, fn['name']))
                                if mapped is not None:
                                    return self.new_base + mapped
                            if fn.get('iat_rva', -1) in candidates:
                                mapped = name_map.get((dll, fn['name']))
                                if mapped is not None:
                                    return self.new_base + mapped
                except Exception:
                    pass
            print(f"        [nullchk] bad slot iat={iat_va:#x} "
                  f"-> {slot:#x}" if slot is not None else
                  f"        [nullchk] bad slot iat={iat_va:#x}",
                  flush=True)
            return None

        def _x86_nullcheck_iat(fo: int) -> Optional[Tuple[int, Optional[str]]]:
            """Return (old IAT VA, optional import name) for nullcheck wrappers."""
            if fo < 0 or fo + 20 > len(text_data):
                return None
            # cmp dword ptr [esp+4], 0
            if text_data[fo:fo + 5] != b'\x83\x7c\x24\x04\x00':
                return None
            if text_data[fo + 5] == 0x75:
                work = fo + 5 + 2 + struct.unpack_from('<b', text_data, fo + 6)[0]
            elif text_data[fo + 5:fo + 7] == b'\x0f\x85':
                work = fo + 5 + 6 + struct.unpack_from('<i', text_data, fo + 7)[0]
            else:
                return None
            if work < 0 or work + 12 > len(text_data):
                return None
            iat_va = None
            for q in range(work, min(work + 24, len(text_data) - 6)):
                if text_data[q:q + 2] == b'\xff\x15':
                    iat_va = struct.unpack_from('<I', text_data, q + 2)[0]
                    break
            if iat_va is None:
                return None
            nm = None
            pe = getattr(self, 'pe', None)
            if pe is not None:
                try:
                    for imp in pe.parse_imports():
                        for fn in imp['functions']:
                            if fn.get('iat_rva') and (pe.image_base + fn['iat_rva']) & 0xFFFFFFFF == iat_va & 0xFFFFFFFF:
                                nm = fn.get('name')
                                break
                        if nm:
                            break
                except Exception:
                    pass
            return iat_va, nm

        def _slot_for_site(iat_va: int, nm: Optional[str]) -> Optional[int]:
            slot = _iat_slot_for_va(iat_va)
            if slot is not None:
                return slot
            name_map = getattr(self, '_iat_name_to_new_rva', None) or {}
            # Direct old-IAT RVA → new slot (most reliable for PE32 FF15 abs).
            old_base = int(getattr(self, 'old_base', 0) or 0)
            for old_rva in (
                    (iat_va - old_base) & 0xFFFFFFFF,
                    iat_va & 0xFFFF,
                    iat_va & 0xFFFFFFFF,
            ):
                mapped = (self._iat_rva_map or {}).get(old_rva)
                if mapped is not None:
                    return self.new_base + mapped
            if nm:
                nm_l = nm.lower()
                for (dll, fn), mapped in name_map.items():
                    if fn.lower() == nm_l:
                        return self.new_base + mapped
                for dll in ('msvcrt.dll', 'MSVCRT.dll', 'ntdll.dll',
                            'kernel32.dll', 'KERNEL32.dll'):
                    mapped = name_map.get((dll, nm))
                    if mapped is None:
                        mapped = name_map.get((dll.lower(), nm))
                    if mapped is None:
                        mapped = name_map.get((dll.lower(), nm_l))
                    if mapped is not None:
                        return self.new_base + mapped
            # Last resort: any MSVCRT slot whose old RVA matches the FF15 low word.
            lo = iat_va & 0xFFFF
            mapped = (self._iat_rva_map or {}).get(lo)
            if mapped is not None:
                return self.new_base + mapped
            print(f"        [nullchk] slot miss iat={iat_va:#x} name={nm!r} "
                  f"map={len(self._iat_rva_map or {})} names={len(name_map)}",
                  flush=True)
            return None

        def _work_is_bare_ret(entry: int) -> Tuple[bool, int, int]:
            """Return (broken, work_off, done_off) for cmp rcx,0 skeleton.

            Broken shapes:
            - work path is a bare ``ret``/nop sled (classic collapse)
            - work path is ``mov rcx,[rsp+8]; mov rdx,[rsp+10]; ret`` — args
              reloaded then return with no IAT call (cmd 0x195d2: RAX still
              holds the caller's wchar immediate → switch parser AV on
              ``[rsi+2]`` with RSI=0x2F)
            """
            if entry < 0 or entry + 16 > len(out):
                return False, 0, 0
            if out[entry:entry + 4] != b'\x48\x83\xf9\x00':
                return False, 0, 0
            # Accept both near (0F 85) and short (75) jne — MSVC emits either.
            if out[entry + 4:entry + 6] == b'\x0f\x85':
                work = entry + 10 + struct.unpack_from('<i', out, entry + 6)[0]
                p_after_jcc = entry + 10
            elif out[entry + 4] == 0x75:
                work = entry + 6 + struct.unpack_from('<b', out, entry + 5)[0]
                p_after_jcc = entry + 6
            else:
                return False, 0, 0
            if not (0 <= work < len(out)):
                return False, 0, 0
            # Identify first ret in the work path (bare or after home reloads).
            ret_at = None
            if out[work] == 0xC3:
                ret_at = work
            elif (work + 11 <= len(out)
                  and out[work:work + 11]
                  == b'\x48\x8b\x4c\x24\x08\x48\x8b\x54\x24\x10\xc3'):
                ret_at = work + 10
            elif (work + 6 <= len(out)
                  and out[work:work + 6] == b'\x48\x8b\x4c\x24\x08\xc3'):
                ret_at = work + 5
            if ret_at is None:
                return False, 0, 0
            for j in range(entry, work):
                if out[j] == 0xE8 or out[j:j + 2] == b'\xff\x15':
                    return False, 0, 0
            done = ret_at + 1
            p = p_after_jcc
            if out[p:p + 3] == b'\x48\x31\xc0' and out[p + 3] == 0xE9:
                done = p + 8 + struct.unpack_from('<i', out, p + 4)[0]
            elif out[p:p + 3] == b'\x48\x31\xc0' and out[p + 3] == 0xC3:
                done = p + 3
            # Cap at the next nullcheck skeleton — packed wrappers sit
            # back-to-back and an uncapped null-path ``jmp done`` can land
            # past the neighbour.
            scan = ret_at + 1
            limit = done if done > work else min(work + 0x80, len(out))
            while scan + 4 <= len(out) and scan < limit:
                if out[scan:scan + 4] == b'\x48\x83\xf9\x00':
                    done = scan
                    break
                scan += 1
            # Work path must be a bare ret/nop/int3 sled only (after optional
            # home reloads).  Never use a fixed +0x40 window — that overwrites
            # the next real function when the null path is a short ``xor; ret``
            # (done <= work).
            grow = ret_at
            while grow < len(out) and out[grow] in (0xC3, 0x90, 0xCC):
                grow += 1
                if grow + 4 <= len(out) and out[grow:grow + 4] == b'\x48\x83\xf9\x00':
                    break
            if done <= work or done > grow:
                done = grow
            if done - work < 19:
                # Sled too short for in-place body — still report broken so
                # the caller can emit a trampoline.
                return True, work, grow if grow > work else work
            return True, work, done

        def _emit_iat_call_body(work_off: int, iat_slot: int) -> bytes:
            rel = iat_slot - (self.new_base + tr + work_off + 4 + 6)
            return (
                b'\x48\x83\xec\x28'
                + b'\xff\x15' + struct.pack('<i', rel)
                + b'\x48\x83\xc4\x28'
                + b'\xc3'
            )

        def _patch_work(work: int, done: int, iat_slot: int,
                        entry_rva: int, off: int) -> bool:
            span = done - work
            if span >= 19:
                patch = _emit_iat_call_body(work, iat_slot)
                if len(patch) > span:
                    return False
                patch += b'\x90' * (span - len(patch))
                if out[work:done] == patch:
                    return True
                out[work:done] = patch
                rva_map[entry_rva] = off
                return True
            # Trampoline: need ≥5 bytes at work for near jmp.
            if span < 5:
                return False
            stub_at = len(out)
            stub = bytearray(_emit_iat_call_body(stub_at, iat_slot))
            # rip-rel inside stub must use stub_at as the call site
            stub = bytearray(
                b'\x48\x83\xec\x28'
                + b'\xff\x15' + struct.pack(
                    '<i', iat_slot - (self.new_base + tr + stub_at + 4 + 6))
                + b'\x48\x83\xc4\x28'
                + b'\xc3'
            )
            out.extend(stub)
            while len(out) % 16:
                out.append(0x90)
            site = (
                b'\xe9' + struct.pack('<i', stub_at - (work + 5))
            )
            site += b'\x90' * (span - 5)
            out[work:done] = site
            rva_map[entry_rva] = off
            return True

        fixed = 0
        seen_off: Set[int] = set()
        candidates: List[int] = []
        for r in (self._fn_entry_rvas or ()):
            if r in rva_map:
                candidates.append(r)
        for fo in range(len(text_data) - 5):
            if text_data[fo:fo + 5] == b'\x83\x7c\x24\x04\x00':
                r = text_rva + fo
                if r not in candidates:
                    candidates.append(r)

        tr = int(getattr(self, '_pure_heal_text_rva', None) or text_rva)
        iat_slots = {self.new_base + v for v in self._iat_rva_map.values()}
        for entry_rva in candidates:
            fo = entry_rva - text_rva
            site = _x86_nullcheck_iat(fo)
            if site is None:
                continue
            iat_va, iat_nm = site
            raw = rva_map.get(entry_rva)
            if raw is None:
                for d in range(1, 8):
                    raw = rva_map.get((entry_rva - d) & 0xFFFFFFFF)
                    if raw is not None:
                        break
            # Live map may have dropped the thin wrapper RVA after sync.
            # Fall back to scanning for the bare-ret cmp-rcx skeleton and
            # confirming via any nearby mapped neighbour (±0x40 x86).
            snap_cands: List[int] = []
            if raw is not None:
                snap_cands.extend(_map_to_off_cands(int(raw)))
            else:
                for d in range(0, 0x80, 4):
                    for key in ((entry_rva - d) & 0xFFFFFFFF,
                                (entry_rva + d) & 0xFFFFFFFF):
                        alt = rva_map.get(key)
                        if alt is None:
                            continue
                        for c in _map_to_off_cands(int(alt)):
                            if c not in snap_cands:
                                snap_cands.append(c)
                # Last resort: whole-blob scan for broken skeletons (rare).
                if not snap_cands:
                    for sc in range(0, len(out) - 16):
                        if out[sc:sc + 4] == b'\x48\x83\xf9\x00':
                            snap_cands.append(sc)
            if not snap_cands:
                continue
            patched_here = False
            for snap0 in snap_cands:
                if snap0 in seen_off:
                    continue
                off = snap0
                for d in range(0, 16):
                    if (snap0 + d + 4 <= len(out)
                            and out[snap0 + d:snap0 + d + 4]
                            == b'\x48\x83\xf9\x00'):
                        off = snap0 + d
                        break
                broken, work, done = _work_is_bare_ret(off)
                if not broken:
                    continue
                try:
                    iat_slot = _slot_for_site(iat_va, iat_nm)
                except Exception as exc:
                    print(f"        [nullchk] resolve fail {entry_rva:#x}: {exc}",
                          flush=True)
                    continue
                if iat_slot is None:
                    continue
                if _patch_work(work, done, iat_slot, entry_rva, off):
                    seen_off.add(off)
                    fixed += 1
                    patched_here = True
                    break
            if patched_here:
                continue
        # Always run a blob-wide pass for bare-ret nullcheck skeletons.
        # Call-sync / map-shape races leave the site unpatched even when the
        # candidate loop above returned early with fixed==0 and no diagnostics.
        x86_sites = []
        for fo in range(len(text_data) - 5):
            site = _x86_nullcheck_iat(fo)
            if site is not None:
                iat_va, iat_nm = site
                x86_sites.append((text_rva + fo, iat_va, iat_nm))
        if x86_sites and fixed == 0:
            print(f"        [nullchk] global-scan sites={len(x86_sites)} "
                  f"map_has_195d2={0x195d2 in rva_map} "
                  f"iat_map={len(self._iat_rva_map or {})}", flush=True)
        for sc in range(0, len(out) - 16):
            if sc in seen_off:
                continue
            broken, work, done = _work_is_bare_ret(sc)
            if not broken:
                continue
            iat_va = None
            iat_nm = None
            entry_rva = None
            best_dist = 0x100000
            for xr, iva, inm in x86_sites:
                raw = rva_map.get(xr)
                if raw is None:
                    continue
                for c in _map_to_off_cands(int(raw)):
                    dist = abs(c - sc)
                    if dist <= 0x80 and dist < best_dist:
                        best_dist = dist
                        iat_va = iva
                        iat_nm = inm
                        entry_rva = xr
            # Always try every x86 site until a slot resolves — map proximity
            # alone is not enough when reconcile leaves the wrapper RVA on a
            # neighbouring ret-sled (cmd 0x195d2 → bare ``ret`` work path).
            tried = []
            if iat_va is not None:
                tried.append((entry_rva, iat_va, iat_nm))
            for xr, iva, inm in x86_sites:
                if (xr, iva, inm) not in tried:
                    tried.append((xr, iva, inm))
            patched_skel = False
            for xr, iva, inm in tried:
                iat_slot = _slot_for_site(iva, inm)
                if iat_slot is None:
                    continue
                if _patch_work(work, done, iat_slot, xr, sc):
                    seen_off.add(sc)
                    fixed += 1
                    patched_skel = True
                    print(f"        [nullchk] force-patched "
                          f"x86={xr:#x} off={sc:#x} slot={iat_slot:#x} "
                          f"span={done - work:#x} name={inm!r}",
                          flush=True)
                    break
            if not patched_skel:
                print(f"        [nullchk] bare-ret unpatched off={sc:#x} "
                      f"span={done - work:#x} tried={len(tried)}",
                      flush=True)
        return fixed

    def _pure_rematerialize_iat_stdcall_forwarders(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Restore swallowed ``push [esp+N]×3; call [iat]; ret N`` wrappers.

        Tiny CRT forwarders (cmd ``0xB627`` → ``wcsncpy``) frequently lose their
        body to a collapsed rva_map slot on the previous function's ``leave; ret``
        / ret-sled.  Call sync then snaps callers onto a nearby align stub
        mid-neighbour (cmd ``0x14D19``), skipping that neighbour's global setup.
        Emit a Win64 stub (args already in rcx/rdx/r8) into the ret-sled and
        retarget every x86 call site.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        if not self._iat_rva_map:
            print("        [fwd] skip: empty _iat_rva_map")
            return 0

        def _map_to_off(v: int) -> Optional[int]:
            # Live rva_map stores blob offsets; dump/_final_rva stores RVAs.
            if 0 <= v < len(out):
                return v
            tr = int(getattr(self, '_pure_heal_text_rva', None) or text_rva or 0)
            if tr and v >= tr and (v - tr) < len(out):
                return v - tr
            return None

        def _is_forwarder(fo: int) -> Optional[Tuple[int, bool]]:
            """Return (iat_va, returns_arg3) for push×3; call [iat]; … forwarders.

            cmd ``0xB627`` ends with ``mov eax,[esp+0x18]`` — that reloads the
            original *count* arg, not wcsncpy's dest pointer.  Callers then
            use EAX as a wchar index (``mov [eax*2+buf],bx``).  Returning
            dest instead writes at ``buf + dest*2`` → AV.
            """
            if fo < 0 or fo + 22 > len(text_data):
                return None
            if text_data[fo:fo + 12] != b'\xff\x74\x24\x0c' * 3:
                return None
            if text_data[fo + 12:fo + 14] != b'\xff\x15':
                return None
            iat = struct.unpack_from('<I', text_data, fo + 14)[0]
            # call [iat] is 6 bytes → next at fo+18
            returns_arg3 = text_data[fo + 18:fo + 22] == b'\x8b\x44\x24\x18'
            return iat, returns_arg3

        def _ret_sled_len(off: int) -> int:
            n = 0
            while off + n < len(out) and out[off + n] in (0xC3, 0x90):
                n += 1
            return n

        def _iat_slot_ok(slot: int) -> bool:
            """Reject stale ``new_base+old_iat_rva`` linear remaps into .text."""
            rva = (slot - self.new_base) & 0xFFFFFFFF
            # PE64 IAT lives in .idata (high RVA); .text is low.
            return rva >= 0x20000 and slot in [
                self.new_base + v for v in self._iat_rva_map.values()]

        fixed = 0
        used_caves: Set[int] = set()
        fwd_rvas: List[Tuple[int, int, bool]] = []
        seen: Set[int] = set()
        for fo in range(len(text_data) - 20):
            parsed = _is_forwarder(fo)
            if parsed is None:
                continue
            iat, returns_arg3 = parsed
            r = (text_rva + fo) & 0xFFFFFFFF
            if r in seen:
                continue
            seen.add(r)
            fwd_rvas.append((r, iat, returns_arg3))

        if not fwd_rvas:
            print("        [fwd] no x86 stdcall forwarders matched")
            return 0
        print(f"        [fwd] candidates={len(fwd_rvas)} iat_map={len(self._iat_rva_map)}",
              flush=True)

        for entry_rva, iat_va, returns_arg3 in fwd_rvas:
            try:
                iat_slot = self._resolve_iat_slot_va(iat_va)
            except Exception as exc:
                print(f"        [fwd] resolve fail {entry_rva:#x}: {exc}",
                      flush=True)
                continue
            print(f"        [fwd] {entry_rva:#x} iat_va={iat_va:#x} "
                  f"slot={iat_slot:#x} ok={_iat_slot_ok(iat_slot)} "
                  f"ret_arg3={returns_arg3}",
                  flush=True)
            if not _iat_slot_ok(iat_slot):
                continue
            cave: Optional[int] = None
            raw = rva_map.get(entry_rva)
            # sub rsp,0x28; [mov [rsp+20h],r8]; movabs; mov; call; [mov rax,[rsp+20h]]; add; ret
            stub_len = 32 if returns_arg3 else 24
            want_prefix = (
                b'\x48\x83\xec\x28'
                + (b'\x4c\x89\x44\x24\x20' if returns_arg3 else b'')
                + b'\x48\xb8' + struct.pack(
                    '<Q', iat_slot & 0xFFFFFFFFFFFFFFFF)
            )

            def _try_range(lo: int, hi: int, kinds: Tuple[int, ...]) -> Optional[int]:
                i = max(0, lo)
                end = min(len(out), hi)
                while i + stub_len <= end:
                    if out[i] not in kinds:
                        i += 1
                        continue
                    j = i
                    while j < end and out[j] == out[i]:
                        j += 1
                    if (j - i >= stub_len and out[i] in kinds
                            and i not in used_caves):
                        return i
                    i = max(j, i + 1)
                return None

            if raw is not None:
                off0 = _map_to_off(int(raw))
                if off0 is not None:
                    # Already a correct shadow-space forwarder?
                    if out[off0:off0 + len(want_prefix)] == want_prefix:
                        cave = off0
                    else:
                        for d in range(0, 64):
                            pos = off0 + d
                            if pos + stub_len > len(out):
                                break
                            if (_ret_sled_len(pos) >= stub_len
                                    and pos not in used_caves):
                                cave = pos
                                break
            if cave is None:
                anchor = self._pure_interior_anchor(
                    rva_map, entry_rva, len(out))
                if anchor is not None:
                    for d in range(0, 128):
                        pos = anchor + d
                        if pos + stub_len > len(out):
                            break
                        if (_ret_sled_len(pos) >= stub_len
                                and pos not in used_caves):
                            cave = pos
                            break
            # Sync often parks the forwarder RVA on a live neighbour align
            # stub (no ret-sled).  Fall back to a global NOP sled, then any
            # long ret-sled, so we can still install a correct IAT wrapper.
            if cave is None:
                cave = _try_range(0, len(out), (0x90,))
            if cave is None:
                cave = _try_range(0, len(out), (0xCC,))
            if cave is None:
                cave = _try_range(0, len(out), (0xC3,))
            # Last resort: grow the blob (post-repair still has section
            # headroom).  Mid-heal ret/nop sleds are often already consumed.
            append_stub = False
            if cave is None:
                cave = len(out)
                append_stub = True
                print(f"        [fwd] appending stub at end for {entry_rva:#x}",
                      flush=True)
            else:
                used_caves.add(cave)
            # Must reserve Win64 shadow space: CRT callees scratch [rsp+8..0x20]
            # above the return address.  A bare ``call`` here smashes the
            # caller's saved r13 / return addr (cmd 0x9f31 → heap execute).
            # When x86 reloads ``[esp+0x18]`` after the call it wants the
            # original *count* (3rd arg / r8), not wcsncpy's dest return.
            if returns_arg3:
                stub = (
                    b'\x48\x83\xec\x28'
                    + b'\x4c\x89\x44\x24\x20'  # mov [rsp+0x20], r8
                    + b'\x48\xb8' + struct.pack(
                        '<Q', iat_slot & 0xFFFFFFFFFFFFFFFF)
                    + b'\x48\x8b\x00'
                    + b'\xff\xd0'
                    + b'\x48\x8b\x44\x24\x20'  # mov rax, [rsp+0x20]
                    + b'\x48\x83\xc4\x28'
                    + b'\xc3'
                )
            else:
                stub = (
                    b'\x48\x83\xec\x28'
                    + b'\x48\xb8' + struct.pack(
                        '<Q', iat_slot & 0xFFFFFFFFFFFFFFFF)
                    + b'\x48\x8b\x00'
                    + b'\xff\xd0'
                    + b'\x48\x83\xc4\x28'
                    + b'\xc3'
                )
            if append_stub:
                out.extend(stub)
            elif out[cave:cave + len(stub)] != stub:
                out[cave:cave + len(stub)] = stub
            rva_map[entry_rva] = cave
            fixed += 1  # count install even if callers already point here
            used_caves.add(cave)
            for off in range(len(text_data) - 5):
                if text_data[off] != 0xE8:
                    continue
                x86_rva = (text_rva + off) & 0xFFFFFFFF
                rel = struct.unpack_from('<i', text_data, off + 1)[0]
                tgt = (x86_rva + 5 + rel) & 0xFFFFFFFF
                if tgt != entry_rva:
                    continue
                anchor = None
                for delta in range(0, 12):
                    for key in ((x86_rva - delta) & 0xFFFFFFFF,
                                (x86_rva + delta) & 0xFFFFFFFF):
                        cand = rva_map.get(key)
                        if cand is not None:
                            a = _map_to_off(int(cand))
                            if a is not None:
                                anchor = a
                                break
                    if anchor is not None:
                        break
                if anchor is None:
                    continue
                best = None
                best_d = 99999
                for j in range(max(0, anchor - 8),
                               min(len(out) - 5, anchor + 96)):
                    if out[j] != 0xE8:
                        continue
                    d = abs(j - anchor)
                    if d < best_d:
                        best_d = d
                        best = j
                if best is None:
                    continue
                cur = best + 5 + struct.unpack_from('<i', out, best + 1)[0]
                if cur != cave:
                    struct.pack_into('<i', out, best + 1, cave - (best + 5))
                    fixed += 1
        return fixed

    def _pure_fix_jcc_to_mismatched_epilogue(self, out: bytearray) -> int:
        """Retarget Jcc that land on a shared epilogue with the wrong pop count.

        Frameless helpers like cmd ``0x1480E`` (``push esi`` … ``mov eax,esi;
        pop esi; ret 4``) often get their early-exit ``je`` snapped onto a
        neighbouring shared ``pop rdi; pop rsi; ret``.  That pops one too many
        and ``ret``s into heap garbage.  When the function body already has a
        local matching epilogue (``mov eax,esi; pop rsi; ret``), point every
        mismatched Jcc there.
        """
        if not self._cmd_no_hacks or not HAS_CAPSTONE:
            return 0
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        fixed = 0
        # Local good epilogue: 89 f0 5e c3  or  89 c6-ish; prefer 89 f0 5e c3
        # (mov eax,esi; pop rsi; ret).  Also accept 48 89 f0 5e c3.
        local_pats = (b'\x89\xf0\x5e\xc3', b'\x48\x89\xf0\x5e\xc3')

        def _pop_count(off: int) -> int:
            """How many GP pops before ret at *off* (0 if not an epilogue)."""
            n = 0
            p = off
            while p < len(out) and n < 8:
                b = out[p]
                if b in (0x58, 0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F):
                    n += 1
                    p += 1
                    continue
                if b == 0x41 and p + 1 < len(out) and 0x58 <= out[p + 1] <= 0x5F:
                    n += 1
                    p += 2
                    continue
                if b == 0xC3:
                    return n
                if b == 0xC2:
                    return n
                break
            return -1

        def _pushes_before(entry: int, limit: int = 24) -> int:
            n = 0
            p = entry
            end = min(entry + limit, len(out))
            while p < end:
                b = out[p]
                if b in (0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57):
                    n += 1
                    p += 1
                    continue
                if b == 0x41 and p + 1 < end and 0x50 <= out[p + 1] <= 0x57:
                    n += 1
                    p += 2
                    continue
                # stop at first non-push / non-mov-home
                if b in (0x48, 0x4C) and p + 1 < end and out[p + 1] in (0x89, 0x8B):
                    p += 4 if out[p + 2] >= 0x40 else 3
                    continue
                if out[p:p + 3] == b'\x48\x83\xec':
                    break
                if b == 0xE8 or b in (0x0F, 0x74, 0x75, 0xEB, 0xE9):
                    break
                if b in (0x8B, 0x89, 0x33, 0x31, 0x85, 0x3B, 0x39):
                    break
                # movzx / test start of body
                if out[p:p + 2] in (b'\x0f\xb7', b'\x0f\xb6', b'\x66\x8b'):
                    break
                break
            return n

        # Scan for push rsi; mov rsi, rcx  (common 0x1480E shape) bodies
        pos = 0
        while pos < len(out) - 20:
            if out[pos] != 0x56:  # push rsi
                pos += 1
                continue
            if out[pos + 1:pos + 4] not in (b'\x48\x89\xce', b'\x48\x89\xf1'):
                # also: push rsi; mov rsi, rcx = 56 48 89 ce
                if out[pos + 1:pos + 4] != b'\x48\x89\xce':
                    pos += 1
                    continue
            entry = pos
            pushes = _pushes_before(entry)
            # Find local epilogue within 0x80 bytes
            local = None
            for pat in local_pats:
                j = out.find(pat, entry, min(entry + 0xC0, len(out)))
                if j > entry:
                    local = j
                    break
            if local is None:
                # pop rsi; ret alone after mov eax,esi encoded differently
                j = out.find(b'\x5e\xc3', entry + 8, min(entry + 0xC0, len(out)))
                if j > entry and out[j - 2:j] in (b'\x89\xf0', b'\x89\xc6'):
                    local = j - 2
            if local is None:
                pos += 1
                continue
            # Walk body Jcc
            body_end = local
            try:
                for insn in md.disasm(bytes(out[entry:body_end]), entry):
                    if insn.mnemonic not in (
                            'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 'jae', 'jbe',
                            'jg', 'jl', 'jge', 'jle', 'jmp'):
                        continue
                    if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                        continue
                    tgt = int(insn.operands[0].imm)
                    if not (0 <= tgt < len(out)):
                        continue
                    # Only near/short encodings we can rewrite in place
                    raw_off = int(insn.address)
                    if out[raw_off] in (0x74, 0x75, 0xEB):
                        enc = 'rel8'
                        imm_at = raw_off + 1
                    elif out[raw_off] == 0x0F and out[raw_off + 1] in (
                            0x84, 0x85, 0x86, 0x87, 0x8C, 0x8D, 0x8E, 0x8F,
                            0x88, 0x89, 0x8A, 0x8B):
                        enc = 'rel32'
                        imm_at = raw_off + 2
                    elif out[raw_off] == 0xE9:
                        enc = 'rel32'
                        imm_at = raw_off + 1
                    else:
                        continue
                    pops = _pop_count(tgt)
                    if pops < 0:
                        continue
                    if pops == pushes:
                        continue
                    # Mismatch — retarget to local epilogue
                    if enc == 'rel8':
                        disp = local - (raw_off + 2)
                        if not (-128 <= disp <= 127):
                            continue
                        out[imm_at] = disp & 0xFF
                    else:
                        disp = local - (raw_off + (6 if out[raw_off] == 0x0F else 5))
                        if out[raw_off] == 0x0F:
                            disp = local - (raw_off + 6)
                        else:
                            disp = local - (raw_off + 5)
                        struct.pack_into('<i', out, imm_at, disp)
                    fixed += 1
            except CsError:
                pass
            pos = max(pos + 1, local)
        return fixed

    def _pure_fix_sbb_mask_add64(self, out: bytearray) -> int:
        """Fix ``sbb r32,r32; add r64, imm`` boolean-mask widening.

        MSVC ``neg edi; sbb edi, edi; add edi, 3`` yields 2 or 3.  When the
        add is wrongly emitted as ``add rdi, 3``, the 0xFFFFFFFF mask becomes
        0x100000002 and breaks every consumer that expects a small integer
        (cmd REPL mode flag → infinite ``ef42`` loop, no ``/c`` execution).

        Same-sized rewrite: strip the REX.W from ``48 83 /0 ib`` / ``48 81 /0
        id`` when it immediately follows ``sbb r32, r32`` on the same register.
        """
        # sbb r32,r32 encodings: 19 C0/C9/D2/DB/E4/ED/F6/FF
        sbb_same = {
            0xC0: 0, 0xC9: 1, 0xD2: 2, 0xDB: 3,
            0xE4: 4, 0xED: 5, 0xF6: 6, 0xFF: 7,
        }
        fixed = 0
        i = 0
        while i + 5 < len(out):
            if out[i] == 0x19 and out[i + 1] in sbb_same:
                reg = sbb_same[out[i + 1]]
                j = i + 2
                # Optional REX.W add/sub r64, imm8/imm32 on the same reg.
                if (j + 3 < len(out) and out[j] == 0x48
                        and out[j + 1] in (0x83, 0x81)
                        and (out[j + 2] & 0xC0) == 0xC0
                        and (out[j + 2] & 0x07) == reg
                        and ((out[j + 2] >> 3) & 7) == 0):  # /0 = add
                    # Drop REX.W: 48 83 c7 03 → 83 c7 03 90
                    if out[j + 1] == 0x83:
                        imm = out[j + 3]
                        out[j:j + 4] = bytes([0x83, 0xC0 | reg, imm, 0x90])
                        fixed += 1
                        i = j + 4
                        continue
                    if out[j + 1] == 0x81 and j + 6 < len(out):
                        # 48 81 c7 xx xx xx xx → 81 c7 xx xx xx xx (same len
                        # without REX — shrink by shifting? keep length with
                        # leading NOP)
                        imm32 = out[j + 3:j + 7]
                        out[j:j + 7] = (
                            bytes([0x90, 0x81, 0xC0 | reg]) + imm32)
                        fixed += 1
                        i = j + 7
                        continue
            i += 1
        return fixed

    def _pure_fix_push_imm_jmp_to_mov_rcx_call(self, out: bytearray) -> int:
        """Fix MSVC ``push imm; jmp call`` diamonds that leak stack on x64.

        Compilers emit locale/flag selectors as::

            push 0x409 / 0x404 / …
            jmp  common
            push 0x411
        common:
            call esi          ; 1-arg stdcall (e.g. SetThreadLocale)

        The translator turns the fall-through ``push; call`` into
        ``mov rcx, imm; push r13; … call``, but predecessor arms keep a
        hardware ``push imm32`` and jump at the ``mov rcx``.  Each REPL
        iteration then leaves 8 bytes per arm and eventually stack-overflows.

        Same-sized rewrite: ``push imm32`` (``68 xx``) → ``mov ecx, imm32``
        (``B9 xx``).  When the join is ``mov rcx`` then align, retarget the
        ``jmp`` to skip that mov so the predecessor's ECX wins.  When arms
        jump straight at the align stub (cmd locale CP fan-in), leave the
        target alone — ``mov ecx`` already supplies arg0 for ``call rN``.
        """
        fixed = 0
        i = 0
        join_prefix = b'\x48\xc7\xc1'  # mov rcx, imm32
        align = b'\x41\x55\x49\x89\xe5'  # push r13; mov r13, rsp

        def _window_has_call_reg(window: bytes) -> bool:
            for j in range(len(window) - 1):
                if window[j] == 0xFF and 0xD0 <= window[j + 1] <= 0xD7:
                    return True
                if (j + 2 < len(window) and window[j] == 0x41
                        and window[j + 1] == 0xFF
                        and 0xD0 <= window[j + 2] <= 0xD7):
                    return True
            return False

        while i + 10 <= len(out):
            if out[i] != 0x68 or out[i + 5] != 0xE9:
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 6)[0]
            tgt = i + 10 + rel
            if tgt < 0 or tgt + 12 > len(out):
                i += 1
                continue
            if (out[tgt:tgt + 3] == join_prefix
                    and out[tgt + 7:tgt + 12] == align):
                out[i] = 0xB9
                struct.pack_into('<i', out, i + 6, rel + 7)
                fixed += 1
                i += 10
                continue
            if (out[tgt:tgt + 5] == align
                    and _window_has_call_reg(bytes(out[tgt:tgt + 0x20]))):
                out[i] = 0xB9
                fixed += 1
                i += 10
                continue
            # Join is ``movabs r14, iat; mov r14,[r14]; mov rcx, 0x411; align``.
            if (out[tgt:tgt + 2] == b'\x49\xbe'
                    and tgt + 20 <= len(out)
                    and out[tgt + 10:tgt + 13] == b'\x4d\x8b\x36'
                    and out[tgt + 13:tgt + 16] == b'\x48\xc7\xc1'):
                out[i] = 0xB9
                # Skip movabs(10)+ld(3)+mov rcx(7) = 20 bytes → land on align.
                struct.pack_into('<i', out, i + 6, rel + 20)
                fixed += 1
                i += 10
                continue
            i += 1
        return fixed

    def _pure_fix_locale_call_reg_iat_reload(self, out: bytearray) -> int:
        """Reload IAT into ``rN`` before locale CP ``call rN`` diamonds.

        MSVC emits ``push LCID; call [SetThreadLocale]`` (or ``mov esi,[iat];
        call esi``).  Some pe64 sites keep a live ``call r14`` after a prior
        diamond loaded r14, but the standalone GetACP fan-in (cmd ``0x24CF``)
        never materializes the IAT — ``call r14`` then hits a stale MSVCRT
        pointer (e.g. ``wcslen``) and AVs on the LCID as a string.

        When a CP diamond joins an align stub + ``call rN`` without a recent
        ``movabs rN; mov rN,[rN]``, retarget that call through a cave that
        reloads the SetThreadLocale IAT address learned from a sibling site.
        """
        if not self._cmd_no_hacks:
            return 0
        align = b'\x41\x55\x49\x89\xe5'
        # Learn IAT VA from ``movabs r14, imm; mov r14, [r14]`` (49 be / 4c 8b 36)
        # or r12-r15 variants near a mov rcx,0x411 locale join.
        iat_va = None
        k = 0
        tip411 = bytes.fromhex('48c7c111040000')
        while True:
            j = out.find(tip411, k)
            if j < 0:
                break
            window = out[max(0, j - 0x20):j]
            # 49 be imm64 = movabs r14, imm
            for reg_mov, reg_ld in (
                    (b'\x49\xbe', b'\x4d\x8b\x36'),  # r14: movabs; mov r14,[r14]
                    (b'\x49\xbc', b'\x4d\x8b\x24\x24'),  # unlikely
                    (b'\x4c\x8d', None),
            ):
                at = window.rfind(reg_mov)
                if at >= 0 and at + 10 <= len(window):
                    iat_va = struct.unpack_from('<Q', window, at + 2)[0]
                    break
            if iat_va:
                break
            # Also: movabs r14 immediately before tip411
            if j >= 13 and out[j - 13] == 0x49 and out[j - 12] == 0xBE:
                iat_va = struct.unpack_from('<Q', out, j - 11)[0]
                break
            k = j + 1
        if not iat_va:
            # broader scan: movabs r14 + mov r14,[r14] + mov rcx,0x411
            sig = bytes.fromhex('49be')
            k = 0
            while True:
                j = out.find(sig, k)
                if j < 0 or j + 20 > len(out):
                    break
                if (out[j + 10:j + 13] == b'\x4d\x8b\x36'
                        and out[j + 13:j + 20] == tip411):
                    iat_va = struct.unpack_from('<Q', out, j + 2)[0]
                    break
                k = j + 1
        if not iat_va:
            return 0
        fixed = 0
        ind_mov = {
            6: bytes.fromhex('4d8b36'),  # mov r14,[r14]
            7: bytes.fromhex('4d8b3f'),  # mov r15,[r15]
        }
        i = 0
        while i + 20 <= len(out):
            if out[i:i + 5] != align:
                i += 1
                continue
            p = i + 5
            end = min(len(out) - 3, i + 0x18)
            call_at = None
            reg = None
            while p < end:
                if (out[p] == 0x41 and out[p + 1] == 0xFF
                        and 0xD0 <= out[p + 2] <= 0xD7):
                    call_at = p
                    reg = out[p + 2] - 0xD0
                    break
                p += 1
            if call_at is None or reg not in ind_mov:
                i += 1
                continue
            prev = bytes(out[max(0, i - 0x50):i])
            if not any(imm in prev for imm in (
                    b'\x09\x04\x00\x00', b'\x04\x04\x00\x00',
                    b'\x12\x04\x00\x00', b'\x04\x08\x00\x00',
                    b'\x11\x04\x00\x00')):
                i += 1
                continue
            movabs_op = bytes([0x49, 0xBC + (reg - 4)])
            # Always reload: push-imm arms may jmp past a sibling movabs onto
            # this same align stub, leaving rN stale (cmd SetThreadLocale).
            if out[call_at + 3:call_at + 6] != b'\x4c\x89\xec':
                i = call_at + 3
                continue
            cave = bytearray()
            cave += movabs_op + struct.pack('<Q', iat_va)
            cave += ind_mov[reg]
            cave += bytes([0x41, 0xFF, 0xD0 + reg])
            cave += b'\x4c\x89\xec'  # mov rsp, r13
            need = len(cave) + 5
            pad_at = None
            run = 0
            for p in range(len(out) - 1, max(0, len(out) - 0x8000), -1):
                if out[p] in (0x00, 0x90, 0xCC):
                    run += 1
                    if run >= need:
                        pad_at = p - run + 1
                        if abs(pad_at - call_at) > 0x20:
                            break
                else:
                    run = 0
            if pad_at is None:
                pad_at = len(out)
                out.extend(b'\x00' * need)
            back = (call_at + 6) - (pad_at + len(cave) + 5)
            cave += b'\xe9' + struct.pack('<i', back)
            if pad_at + len(cave) > len(out):
                out.extend(b'\x00' * (pad_at + len(cave) - len(out)))
            out[pad_at:pad_at + len(cave)] = cave
            rel32 = pad_at - (call_at + 5)
            out[call_at:call_at + 6] = (
                b'\xe9' + struct.pack('<i', rel32) + b'\x90')
            fixed += 1
            i = call_at + 6
        return fixed

    def _pure_fix_rep_stos_dest_clobber(self, out: bytearray) -> int:
        """Keep ``rep stos`` dest when Win64 count reload clobbers RCX.

        CRT ``wmemset``/``memset`` bodies become::

            mov [rsp+8], rcx          ; home dest
            …
            mov eax, r8d              ; count
            mov ecx, eax              ; clobbers dest
            …
            mov rdi, rcx              ; wrongly loads count

        Native kept dest in EDI across the count setup.  Reclaim the unused
        r9 home spill for an early ``mov rdi, rcx``, and NOP the late reload.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        homes = bytes.fromhex('48894c240848895424104c894424184c894c2420')
        body = bytes.fromhex('4489c089c148ffc885c9')  # mov eax,r8d; mov ecx,eax; dec rax; test ecx,ecx
        late = bytes.fromhex('574889cf')  # push rdi; mov rdi, rcx
        i = 0
        while True:
            at = out.find(homes + body, i)
            if at < 0:
                break
            # Late reload must exist shortly after.
            rel = out.find(late, at + len(homes), at + 0x40)
            if rel < 0:
                i = at + 5
                continue
            # Replace r9 home (last 5 bytes of homes) with mov rdi, rcx; nop nop.
            r9_at = at + len(homes) - 5
            out[r9_at:r9_at + 5] = bytes.fromhex('4889cf9090')
            # NOP late mov rdi, rcx (keep push rdi).
            out[rel + 1:rel + 4] = b'\x90\x90\x90'
            fixed += 1
            i = rel + 4
        return fixed

    def _pure_fix_heaprealloc_mem_arg_after_getprocessheap(
            self, out: bytearray) -> int:
        """Fix ``HeapReAlloc(heap, 0, heap, size)`` after ``GetProcessHeap``.

        Native does ``push size; push mem; push 0; call GetProcessHeap;
        push eax; call HeapReAlloc``.  Translation keeps ``mov [rbp+0x10], mem``
        then ``call GetProcessHeap`` into RAX, but sets both RCX and R8 from
        RAX — so the block pointer becomes the heap handle and ntdll AVs.

        Rewrite the arg block to keep mem from ``[rbp+0x10]``::

            mov rcx, rax
            xor edx, edx
            mov r8, [rbp+0x10]
            mov r9, rdi
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rcx, rax; mov rdx, 0; mov r8, rax; mov r9, rdi
        sig = bytes.fromhex('4889c148c7c2000000004989c04989f9')
        repl = bytes.fromhex('4889c131d24c8b45104989f990909090')
        # 3+2+4+3+4nops = 16, same as 3+7+3+3
        assert len(sig) == len(repl) == 16
        i = 0
        while True:
            at = out.find(sig, i)
            if at < 0:
                break
            window = bytes(out[max(0, at - 0x30):at])
            if (b'\x48\x89\x45\x10' not in window
                    and b'\x48\x89\x85\x10\x00\x00\x00' not in window):
                i = at + 1
                continue
            out[at:at + 16] = repl
            fixed += 1
            i = at + 16
        return fixed

    def _pure_fix_heapsize_args_after_getprocessheap(self, out: bytearray) -> int:
        """Supply ``rdx=0; r8=rbx`` for ``HeapSize`` after ``GetProcessHeap``.

        Native ``push mem; push 0; call GetProcessHeap; push eax; call HeapSize``
        becomes ``call GetProcessHeap; mov rcx, rax; align; call HeapSize`` with
        flags/mem dropped — ntdll then AVs on a NULL/junk block (cmd grow
        helper ``0x1a05c``).

        Anchored on the grow-helper shape only: ``mov [rbx], edi`` stores the
        size into the new block, then GetProcessHeap is called via ``r14/r15``
        and restored immediately before ``mov rcx, rax``.  Looser matching
        previously corrupted unrelated sites.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rcx,rax; push r13  — 5 bytes, enough for a near jmp
        head = bytes.fromhex('4889c14155')
        align_rest = bytes.fromhex('4989e54883ec204883e4f0')
        # call r14/r15; mov rsp,r13; pop r13  immediately before
        gph_tails = (
            bytes.fromhex('41ffd64c89ec415d'),
            bytes.fromhex('41ffd74c89ec415d'),
        )
        i = 0
        while True:
            at = out.find(head + align_rest, i)
            if at < 0:
                break
            i = at + 1
            if at < 8 or out[at - 8:at] not in gph_tails:
                continue
            lookback = bytes(out[max(0, at - 0x80):at])
            if b'\x48\x89\xc3' not in lookback or b'\x89\x3b' not in lookback:
                continue
            trail = bytes(out[at:at + 0x50])
            if b'\x48\xb8' not in trail and b'\x49\xbb' not in trail:
                continue
            # Cave: xor edx,edx; mov r8,rbx; mov rcx,rax; push r13; jmp align_rest
            stub = bytearray()
            stub += b'\x31\xd2'      # xor edx, edx
            stub += b'\x49\x89\xd8'  # mov r8, rbx
            stub += b'\x48\x89\xc1'  # mov rcx, rax
            stub += b'\x41\x55'      # push r13
            back = at + 5  # resume at mov r13,rsp
            cave = self._pure_find_padding_cave(out, len(stub) + 5)
            if cave < 0:
                continue
            stub += b'\xe9' + struct.pack(
                '<i', back - (cave + len(stub) + 5))
            out[cave:cave + len(stub)] = stub
            out[at:at + 5] = b'\xe9' + struct.pack('<i', cave - (at + 5))
            fixed += 1
            i = at + 5
        return fixed

    def _pure_fix_je_skipping_rbx_iat_reload(self, out: bytearray) -> int:
        """Retarget ``je`` that skips ``movabs rbx, IAT`` before ``call rbx``.

        Flag-gated prompt builders do::

            cmp byte [r11], 0
            je  join              ; wrongly skips the reload block
            ... format path ...
            jmp after
        reload:                   ; unreferenced after bad branch tip
            movabs rbx, &IAT
            mov rbx, [rbx]
            ...
        join:
            ...
            call rbx              ; rbx still holds alloc buffer → execute@string

        When ``join`` is only reached by that ``je`` and the reload block is
        unreferenced, retarget the ``je`` onto the reload entry.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # cmp byte [r11], 0; je rel32
        sig = bytes.fromhex('41803b000f84')
        i = 0
        while True:
            at = out.find(sig, i)
            if at < 0:
                break
            i = at + 1
            jcc = at + 4
            join = jcc + 6 + struct.unpack_from('<i', out, jcc + 2)[0]
            if not (0 <= join < len(out) - 8):
                continue
            # Reload block must sit between jcc-fallthrough and join.
            region = bytes(out[jcc + 6:join])
            # movabs rbx, imm64; mov rbx, [rbx]
            rel = region.find(b'\x48\xbb')
            if rel < 0:
                continue
            reload = jcc + 6 + rel
            if out[reload + 10:reload + 13] != b'\x48\x8b\x1b':
                continue
            # join path must call rbx.
            join_win = bytes(out[join:min(len(out), join + 0x40)])
            if b'\xff\xd3' not in join_win:
                continue
            # Reload must be unreferenced (no jmp/jcc/call onto it).
            referenced = False
            for s in range(len(out) - 6):
                if s == jcc:
                    continue
                if out[s] in (0xE8, 0xE9):
                    d = struct.unpack_from('<i', out, s + 1)[0]
                    if s + 5 + d == reload:
                        referenced = True
                        break
                elif out[s] == 0x0F and 0x80 <= out[s + 1] <= 0x8F:
                    d = struct.unpack_from('<i', out, s + 2)[0]
                    if s + 6 + d == reload:
                        referenced = True
                        break
            if referenced:
                continue
            struct.pack_into('<i', out, jcc + 2, reload - (jcc + 6))
            fixed += 1
        return fixed

    def _pure_fix_push_push_jmp_past_win64_args(self, out: bytearray) -> int:
        """Fix ``push imm; push reg; jmp call-align`` that skips Win64 arg setup.

        x86 2-arg stdcall loops rematerialize as::

            mov rcx, <haystack_reg>
            mov rdx, imm
            push r13; mov r13, rsp; …; call

        but the loop-back arm keeps the x86 shape ``push imm8; push reg;
        jmp`` aimed at the *call-align*, skipping the ``mov rcx/rdx``.
        RCX then still holds a leftover character from ``movzx`` compares
        (e.g. ``L'1'`` = 0x31) and the IAT wrapper AVs inside MSVCRT.

        Retarget the jmp to the ``mov rcx`` and replace the pushes with
        ``mov <haystack_reg>, <pushed_reg>`` (same 8-byte footprint for
        the common ``6A xx 5x E9`` form).
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        align = b'\x41\x55\x49\x89\xe5'
        i = 0
        while i + 8 <= len(out):
            # push imm8; push r64 (50-57); jmp rel32
            if not (out[i] == 0x6A and 0x50 <= out[i + 2] <= 0x57
                    and out[i + 3] == 0xE9):
                i += 1
                continue
            imm = out[i + 1]
            src_reg = out[i + 2] & 7  # eax..edi from 50-57
            rel = struct.unpack_from('<i', out, i + 4)[0]
            align_off = i + 8 + rel
            if align_off < 0 or align_off + 5 > len(out):
                i += 1
                continue
            if out[align_off:align_off + 5] != align:
                i += 1
                continue
            # Look backward from call-align for ``mov rcx, r64; mov rdx/edx, imm``
            setup = None  # (setup_off, dst_haystack_reg encoding in mov rcx)
            for back in range(4, 24):
                s = align_off - back
                if s < 0:
                    break
                # mov rcx, r64: 48 89 /r with modrm = 0xC1 | (reg<<3)
                #   48 89 c1 = mov rcx, rax; 48 89 d9 = mov rcx, rbx; …
                #   48 89 f9 = mov rcx, rdi; 48 89 f1 = mov rcx, rsi
                if (out[s:s + 2] == b'\x48\x89'
                        and (out[s + 2] & 0xC7) == 0xC1):
                    hay_reg = (out[s + 2] >> 3) & 7
                    # mov rdx, imm32: 48 c7 c2 imm32  OR mov edx, imm32: ba imm32
                    after = s + 3
                    ok_imm = False
                    if (after + 7 <= len(out)
                            and out[after:after + 3] == b'\x48\xc7\xc2'
                            and struct.unpack_from('<I', out, after + 3)[0] == imm):
                        ok_imm = True
                    elif (after + 5 <= len(out)
                          and out[after] == 0xBA
                          and struct.unpack_from('<I', out, after + 1)[0] == imm):
                        ok_imm = True
                    elif (after + 7 <= len(out)
                          and out[after:after + 3] == b'\x48\xc7\xc2'):
                        # imm may be zero-extended differently — accept any
                        ok_imm = True
                    if ok_imm:
                        setup = (s, hay_reg)
                        break
            if setup is None:
                i += 1
                continue
            setup_off, hay_reg = setup
            # Rewrite 8-byte site: mov <hay32>, <src32>; nop; jmp setup
            # 89 /r : mov r/m32, r32  with modrm = 0xC0 | dst | (src<<3)
            # mov edi, eax = 89 c7 when hay=rdi(7), src=rax(0)
            modrm = 0xC0 | hay_reg | (src_reg << 3)
            patch = bytes([0x89, modrm, 0x90])  # 3 bytes; zero-extends to 64
            new_rel = setup_off - (i + 3 + 5)
            patch += b'\xe9' + struct.pack('<i', new_rel)
            if len(patch) != 8:
                i += 1
                continue
            out[i:i + 8] = patch
            fixed += 1
            i += 8
        return fixed

    def _pure_fix_int3_after_wchar_newline_store(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Fill omitted ``mov eax,[esp+disp]; mov [eax+8],esi`` after ``\\n`` store.

        Large-frame epilogues (cmd ``0xA4E7``) end with
        ``mov word [esi+eax*2], 0xA; mov eax, [esp+disp]; mov [eax+8], esi;
        pops; add esp,N; ret``.  The middle load is sometimes dropped and
        replaced with a single ``int3``, leaving no room to re-emit it
        in-place.  Trampoline through a nearby NOP/INT3 sled: restore the
        store, reload arg0 from the homed ``[r15+4]`` (``lea r15,[rsp+4]``
        before chkstk), then the ``mov [rax+8],esi``, then jump back to the
        pops.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        pat = bytes.fromhex('66c704460a00cc897008')
        local_epi = bytes.fromhex('5f5e5d5b')  # pop rdi;rsi;rbp;rbx
        large_add = bytes.fromhex('4881c468240000')  # add rsp, 0x2468
        fixed = 0
        # Prefer long NOP sleds; then INT3; avoid RET padding (those sleds are
        # often live landing pads — overwriting them crashes early).
        def _find_cave(start: int = 0) -> tuple:
            best_i, best_n, best_rank = -1, 0, 99
            i = max(0, start)
            while i < len(out):
                if out[i] not in (0x90, 0xCC):
                    i += 1
                    continue
                j = i
                kind = out[i]
                while j < len(out) and out[j] == kind:
                    j += 1
                n = j - i
                rank = 0 if kind == 0x90 else 1
                if n >= 24 and (rank < best_rank or (rank == best_rank and n > best_n)):
                    best_n = n
                    best_i = i
                    best_rank = rank
                i = j
            return best_i, best_n

        cave, best = _find_cave()
        # Collect matching sites; prefer large-frame epilogues (0xA4E7).
        sites: List[int] = []
        pos = 0
        while True:
            i = out.find(pat, pos)
            if i < 0:
                break
            if out[i + 10:i + 14] == local_epi:
                sites.append(i)
            pos = i + 1
        if not sites:
            return 0
        sites.sort(key=lambda s: 0 if out[s + 14:s + 21] == large_add else 1)
        # Fall back to appending stubs when mid-heal has no NOP/INT3 caves
        # (common after call-sync consumes padding).
        append_at: Optional[int] = None
        if cave < 0 or best < 24:
            append_at = len(out)
        for i in sites:
            if append_at is None and (cave < 0 or best < 24):
                cave, best = _find_cave(cave + best if cave >= 0 else 0)
            use_append = append_at is not None or cave < 0 or best < 24
            body = (
                bytes.fromhex('66c704460a00')   # mov word [rsi+rax*2], 0xa
                + bytes.fromhex('498b4704')     # mov rax, [r15+4]
                + bytes.fromhex('48897008')     # mov qword [rax+8], rsi
            )
            if use_append:
                stub_at = len(out)
                jmp_at = stub_at + len(body)
                back = i + 10
                disp = back - (jmp_at + 5)
                body += b'\xe9' + struct.pack('<i', disp)
                out.extend(body)
                while len(out) % 16:
                    out.append(0x90)
                site_disp = stub_at - (i + 5)
            else:
                back = i + 10
                jmp_at = cave + len(body)
                disp = back - (jmp_at + 5)
                body += b'\xe9' + struct.pack('<i', disp)
                if len(body) > best:
                    continue
                out[cave:cave + len(body)] = body
                site_disp = cave - (i + 5)
                cave = jmp_at + 5
                best = 0
            out[i:i + 10] = b'\xe9' + struct.pack('<i', site_disp) + b'\x90' * 5
            # x86 ``add esp,0x2464`` must stay a large-frame teardown.  A wrong
            # chkstk-size heal can shrink this to ``add rsp,0x1018`` and the
            # following ``ret`` pops a non-return (cmd heal5 → execute AV).
            if (out[i + 10:i + 14] == local_epi
                    and out[i + 14:i + 17] == b'\x48\x81\xc4'
                    and out[i + 14:i + 21] != large_add):
                out[i + 14:i + 21] = large_add
            fixed += 1
        return fixed

    def _pure_fix_int3_after_iat_call_ebp8_store(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Restore ``mov [ebp+8],eax/edi`` joins swallowed into INT3 gaps.

        Pattern (cmd ``0x76F4``): after an IAT call wrapper
        ``…; pop r13; int3; jmp join; int3; join: …`` where x86 had
        ``mov [ebp+8],eax; jmp join`` / ``mov [ebp+8],edi``.  The INT3 is
        hit as STATUS_BREAKPOINT; with a corrupt GS:[0] SEH chain the VEH
        then hangs.  Emit a tiny trampoline that performs both stores and
        returns to the shared join.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        fixed = 0
        # pop r13; int3; jmp rel32; int3
        pat = bytes.fromhex('415dcc')
        pos = 0
        while True:
            i = out.find(pat, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 10 > len(out) or out[i + 3] != 0xE9 or out[i + 8] != 0xCC:
                continue
            # Confirm x86 side: mov [ebp+8], e?x near a mapped neighbour.
            join_off = i + 9  # byte after second int3 — usual join start
            # Prefer mapping via any rva_map entry whose PE64 lands near here.
            x86_hit = False
            for x86, pe64 in rva_map.items():
                cands = []
                if 0 <= pe64 < len(out):
                    cands.append(pe64)
                if pe64 >= (text_rva or 0):
                    o = pe64 - (text_rva or 0)
                    if 0 <= o < len(out):
                        cands.append(o)
                if not any(abs(c - i) <= 0x80 for c in cands):
                    continue
                fo = x86 - text_rva
                if fo < 0 or fo + 8 > len(text_data):
                    continue
                # mov [ebp+8], eax (89 45 08) or mov [ebp+8], edi (89 7d 08)
                window = text_data[max(0, fo - 0x20):fo + 0x20]
                if (b'\x89\x45\x08' in window or b'\x89\x7d\x08' in window):
                    x86_hit = True
                    break
            if not x86_hit:
                continue
            # Build trampoline at end of blob.
            # x86 ``mov [ebp+8],r32`` is the first stdcall arg home → Win64
            # MSVC ``[rbp+0x10]`` (saved RBP at +0, retaddr at +8).
            call_entry = len(out)
            stub = bytearray()
            stub += bytes.fromhex('894510')          # mov [rbp+0x10], eax
            stub += b'\xeb\x03'                       # jmp join_lbl
            null_entry = call_entry + len(stub)
            stub += bytes.fromhex('897d10')          # mov [rbp+0x10], edi
            join_lbl = call_entry + len(stub)
            # Jump back to original join (byte after second INT3).
            back = join_off
            stub += b'\xe9' + struct.pack('<i', back - (join_lbl + 5))
            out.extend(stub)
            while len(out) % 16:
                out.append(0x90)
            # pop r13 stays; replace int3+jmp+int3 (6 bytes from i+2) with
            # jmp call_entry + nops.  Site at i+2 (the first INT3).
            site = i + 2
            rel = call_entry - (site + 5)
            out[site:site + 7] = (
                b'\xe9' + struct.pack('<i', rel) + b'\x90\x90')
            # Retarget any Jcc that landed on the second INT3 (i+8) onto
            # null_entry (mov [rbp+0x10], edi).
            second_cc = i + 8
            for j in range(max(0, i - 0x40), i):
                if out[j] == 0x0F and j + 5 < len(out) and out[j + 1] in (
                        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B,
                        0x8C, 0x8D, 0x8E, 0x8F):
                    rel32 = struct.unpack_from('<i', out, j + 2)[0]
                    tgt = j + 6 + rel32
                    if tgt == second_cc:
                        struct.pack_into('<i', out, j + 2,
                                         null_entry - (j + 6))
                elif out[j] in (0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
                                0x7B, 0x7C, 0x7D, 0x7E, 0x7F):
                    rel8 = struct.unpack_from('<b', out, j + 1)[0]
                    tgt = j + 2 + rel8
                    if tgt == second_cc:
                        # Promote to near Jcc if needed — only fix when a
                        # near form already exists nearby; skip short.
                        pass
            fixed += 1
        return fixed

    def _pure_fix_rbp8_homed_arg_loads(self, out: bytearray) -> int:
        """Rewrite ``mov r64,[rbp+8]`` to ``[rbp+0x10]`` after frame arg homes.

        x86 ``[ebp+8]`` is stdcall arg0; Win64 MSVC homes it at ``[rbp+0x10]``
        (``[rbp+8]`` is the return address).  A rare emit path still keeps the
        raw x86 disp; only rewrite when the enclosing frame spilled
        ``mov [rbp+0x10],rcx`` so we do not touch unrelated ``[rbp+8]`` uses.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        home = bytes.fromhex('48894d10')  # mov qword [rbp+0x10], rcx
        # REX.W mov r64, [rbp+disp8]: 48 8B /r with modrm = 01_reg_101 (rbp)
        i = 0
        while i + 4 <= len(out):
            if (out[i] == 0x48 and out[i + 1] == 0x8B
                    and (out[i + 2] & 0xC7) == 0x45 and out[i + 3] == 0x08):
                # Confirm a frame-arg home spill in the preceding 0x80 bytes.
                window = bytes(out[max(0, i - 0x80):i])
                if home in window:
                    out[i + 3] = 0x10
                    fixed += 1
                    i += 4
                    continue
            i += 1
        return fixed

    def _pure_fix_rbp_loop_counter_cmp_mismatch(self, out: bytearray) -> int:
        """Fix ``inc [rbp+X]; jmp L`` loops whose ``cmp [rbp+Y]`` uses Y≠X.

        Frame expansion sometimes remaps the loop counter for ``and``/``inc``
        (cmd ``ebp-0x34`` → ``rbp-0x44``) while leaving the header
        ``cmp [rbp-disp],N; jge`` on a stale neighbouring disp (``-0x4a``).
        The counter then never satisfies the exit test → infinite spin.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i + 8 < len(out):
            # inc dword [rbp+disp8] ; jmp rel32
            if (out[i] == 0xFF and out[i + 1] == 0x45
                    and out[i + 3] == 0xE9):
                inc_disp = struct.unpack_from('<b', out, i + 2)[0]
                rel = struct.unpack_from('<i', out, i + 4)[0]
                tgt = i + 8 + rel
                if 0 <= tgt + 4 <= len(out) and out[tgt:tgt + 2] == b'\x83\x7d':
                    cmp_disp = struct.unpack_from('<b', out, tgt + 2)[0]
                    if cmp_disp != inc_disp:
                        # Require a matching ``and [rbp+inc_disp],0`` shortly
                        # before the cmp (loop init).
                        window = out[max(0, tgt - 0x20):tgt]
                        and_pat = bytes([0x83, 0x65, inc_disp & 0xFF, 0x00])
                        if and_pat in window:
                            out[tgt + 2] = inc_disp & 0xFF
                            fixed += 1
                i += 3
                continue
            i += 1
        return fixed

    def _pure_resolve_scaled_old_disp(self, out: bytearray, i: int,
                                        disp: int) -> int:
        """Map a PE32 absolute ``disp`` used in ``[rax*2+disp]`` to a PE64 VA."""
        old_base = int(getattr(self, 'old_base', 0) or 0)
        new_base = int(getattr(self, 'new_base', 0) or 0)
        if not (old_base and new_base
                and old_base <= disp < old_base + 0x30000):
            return 0
        relocate = getattr(self, '_relocate_imm', None)
        new_va = None
        if callable(relocate):
            try:
                new_va = relocate(disp) & 0xFFFFFFFFFFFFFFFF
            except Exception:
                new_va = None
        if not new_va or not (new_base <= new_va < new_base + 0x200000):
            suffix = disp & 0xFFFF
            lo = max(0, i - 0x200)
            for j in range(lo, min(len(out) - 10, i + 0x40)):
                if out[j:j + 2] in (b'\x49\xbb', b'\x48\xb8'):
                    imm = struct.unpack_from('<Q', out, j + 2)[0]
                    if ((imm & 0xFFFF) == suffix
                            and new_base <= imm < new_base + 0x200000):
                        new_va = imm
                        break
        if not new_va or not (new_base <= new_va < new_base + 0x200000):
            return 0
        return int(new_va)

    def _pure_fix_scaled_index_old_image_disp(self, out: bytearray) -> int:
        """Rewrite ``[rax*2+old_va]`` forms whose disp32 is still a PE32 VA.

        High PE64 image bases cannot live in a sign-extended disp32, so the
        translator sometimes leaves the raw x86 absolute (cmd ``0x4AD1FBE2``)
        in ``cmp/lea [rax*2+disp32]``.  Trampoline:
        ``movabs r11,new; op [r11+rax*2]``.
        """
        if not self._cmd_no_hacks:
            return 0
        old_base = int(getattr(self, 'old_base', 0) or 0)
        new_base = int(getattr(self, 'new_base', 0) or 0)
        if not old_base or not new_base:
            return 0
        fixed = 0
        # cmp word ptr [rax*2+disp32], imm8
        pat = b'\x66\x83\x3c\x45'
        pos = 0
        while True:
            i = out.find(pat, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 9 > len(out):
                continue
            disp = struct.unpack_from('<I', out, i + 4)[0]
            new_va = self._pure_resolve_scaled_old_disp(out, i, disp)
            if not new_va:
                continue
            imm8 = out[i + 8]
            has_lea = (i + 16 <= len(out)
                       and out[i + 9:i + 12] == b'\x48\x8d\x14'
                       and out[i + 12] == 0x45
                       and struct.unpack_from('<I', out, i + 13)[0] == disp)
            span = 16 if has_lea else 9
            tramp_at = len(out)
            body = bytearray()
            body += b'\x49\xbb' + struct.pack('<Q', new_va)
            body += b'\x66\x41\x83\x3c\x43' + bytes([imm8])
            if has_lea:
                body += b'\x49\x8d\x14\x43'
            back = i + span
            body += b'\xe9' + struct.pack('<i', back - (tramp_at + len(body) + 5))
            out.extend(body)
            while len(out) % 16:
                out.append(0x90)
            rel = tramp_at - (i + 5)
            out[i:i + span] = (
                b'\xe9' + struct.pack('<i', rel)
                + b'\x90' * (span - 5))
            fixed += 1
            pos = i + span
        # lea rax, [rax*2+disp32]  (ReadFile buffer = base + index*2)
        pat_lea = b'\x48\x8d\x04\x45'
        pos = 0
        while True:
            i = out.find(pat_lea, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 8 > len(out):
                continue
            disp = struct.unpack_from('<I', out, i + 4)[0]
            new_va = self._pure_resolve_scaled_old_disp(out, i, disp)
            if not new_va:
                continue
            span = 8
            tramp_at = len(out)
            body = bytearray()
            body += b'\x49\xbb' + struct.pack('<Q', new_va)
            body += b'\x49\x8d\x04\x43'  # lea rax, [r11+rax*2]
            back = i + span
            body += b'\xe9' + struct.pack('<i', back - (tramp_at + len(body) + 5))
            out.extend(body)
            while len(out) % 16:
                out.append(0x90)
            rel = tramp_at - (i + 5)
            out[i:i + span] = (
                b'\xe9' + struct.pack('<i', rel)
                + b'\x90' * (span - 5))
            fixed += 1
            pos = i + span
        # and word [rbx*2+disp32], imm8  (cmd strip-quotes terminator
        # ``0x147f9`` / pe64 ``0x27ed8`` — x86 abs still in the disp32)
        pat_and = b'\x66\x83\x24\x5d'
        pos = 0
        while True:
            i = out.find(pat_and, pos)
            if i < 0:
                break
            pos = i + 1
            if i + 9 > len(out):
                continue
            disp = struct.unpack_from('<I', out, i + 4)[0]
            imm8 = out[i + 8]
            new_va = self._pure_resolve_scaled_old_disp(out, i, disp)
            if not new_va:
                continue
            span = 9
            body = bytearray()
            body += b'\x49\xbb' + struct.pack('<Q', new_va)  # movabs r11,va
            # and word [r11+rbx*2], imm8
            body += b'\x66\x41\x83\x24\x5b' + bytes([imm8])
            cave = self._pure_find_padding_cave(out, len(body) + 5)
            if cave < 0:
                tramp_at = len(out)
                body += b'\xe9' + struct.pack(
                    '<i', (i + span) - (tramp_at + len(body) + 5))
                out.extend(body)
                while len(out) % 16:
                    out.append(0x90)
                out[i:i + span] = (
                    b'\xe9' + struct.pack('<i', tramp_at - (i + 5))
                    + b'\x90' * (span - 5))
            else:
                body += b'\xe9' + struct.pack(
                    '<i', (i + span) - (cave + len(body) + 5))
                out[cave:cave + len(body)] = body
                out[i:i + span] = (
                    b'\xe9' + struct.pack('<i', cave - (i + 5))
                    + b'\x90' * (span - 5))
            fixed += 1
            pos = i + span
        # Epilogue paired with the strip-quotes terminator above:
        # x86 ``pop ebx; pop esi; pop edi; ret`` became
        # ``pop rbx; pop rsi; pop rsi; leave; ret`` (cmd ``0x14802``).
        epi_bad = b'\x5b\x5e\x5e\xc9\xc3'
        epi_good = b'\x5b\x5e\x5f\x90\xc3'  # pop rbx; pop rsi; pop rdi; nop; ret
        pos = 0
        while True:
            i = out.find(epi_bad, pos)
            if i < 0:
                break
            pos = i + 1
            # Require the scaled-and site (or its trampoline jmp) shortly above.
            window = bytes(out[max(0, i - 0x40):i])
            if (b'\x66\x83\x24\x5d' not in window
                    and not (b'\xe9' in window[-16:] and b'\x5b\x5e' in window)):
                # Accept a near jmp into this epilogue from an and-trampoline
                # (site replaced with E9 ... nops).
                if out[i - 9:i - 4] != b'\xe9' and 0xE9 not in out[max(0, i - 12):i]:
                    continue
            out[i:i + 5] = epi_good
            fixed += 1
            pos = i + 5
        return fixed

    def _pure_fix_clobber_before_callee_save_pushes(
            self, out: bytearray) -> int:
        """Reorder ``xor rbx; movabs rsi; push rsi; push rbx`` to save first.

        x86 strip-quotes (cmd ``0x147b6``) does ``push esi; push ebx; xor ebx;
        mov esi, buf``.  Translation clobbers RSI/RBX *before* the pushes, so
        the pushes store the buffer/zero instead of the caller's values and
        the Win64 non-volatiles are lost (heap corruption on return).
        Length-neutral reorder::

            xor rbx,rbx; movabs rsi,imm; push rsi; push rbx
            → push rsi; push rbx; xor rbx,rbx; movabs rsi,imm
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 20:
            if out[i:i + 3] != b'\x48\x31\xdb':
                i += 1
                continue
            if out[i + 3:i + 5] != b'\x48\xbe':
                i += 1
                continue
            if out[i + 13:i + 15] != b'\x56\x53':
                i += 1
                continue
            # Prefer sites that then load rcx/rdx from rsi/rbx (memset shape).
            if out[i + 15:i + 21] not in (
                    b'\x48\x89\xf1\x48\x89\xda',
                    b'\x48\x89\xf1\x48\x89\xd3'):
                if out[i + 15:i + 18] != b'\x48\x89\xf1':
                    i += 1
                    continue
            imm = bytes(out[i + 5:i + 13])
            out[i:i + 15] = (
                b'\x56\x53\x48\x31\xdb\x48\xbe' + imm)
            fixed += 1
            i += 15
        return fixed

    def _pure_fix_heapfree_missing_win64_args(self, out: bytearray) -> int:
        """Stub: HeapFree arg heal disabled until old-pointer source is known."""
        return 0

    def _pure_fix_ff35_helper_calls(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Force calls to ``push [global]; call API`` helpers onto VA entries.

        Authoritative CALL sync uses a global ``used`` set of align-stub E8s,
        so an earlier unrelated x86 ``call`` can claim the stub that belongs to
        a CRT ``push [&CS]; call EnterCriticalSection`` helper.  The stolen
        stub then keeps a mid-function ``movabs r11, &slot`` landing (same VA
        fingerprint as the real helper) and InitCS is re-entered with RCX=0.
        This pass ignores ``used`` and only considers ``ff 35`` callees.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt_x86 = (x86_rva + 5 + rel) & 0xFFFFFFFF
            fo = tgt_x86 - text_rva
            if fo < 0 or fo + 6 > len(text_data):
                continue
            if text_data[fo:fo + 2] != b'\xff\x35':
                continue
            new_tgt = self._pure_find_sane_entry_for_x86(
                out, tgt_x86, rva_map, text_data, text_rva)
            if new_tgt is None:
                # find_sane can miss when relocate/deferred VA disagrees with
                # already-patched movabs immediates.  Scan both the relocated
                # and original global VAs; keep only post-``ret`` entries.
                disp = struct.unpack_from('<I', text_data, fo + 2)[0]
                cand_vas = {disp & 0xFFFFFFFFFFFFFFFF,
                            self._relocate_imm(disp) & 0xFFFFFFFFFFFFFFFF}
                ranked: List[Tuple[int, int]] = []
                for va in cand_vas:
                    va_le = struct.pack('<Q', va)
                    for prefix in (b'\x49\xbb', b'\x48\xb8'):
                        pos = 0
                        while pos < len(out) - 10:
                            j = out.find(prefix, pos)
                            if j < 0:
                                break
                            if (out[j + 2:j + 10] == va_le
                                    and self._x64_entry_prologue_ok(out, j)
                                    and self._pure_call_target_plausible(
                                        out, j)):
                                ranked.append(
                                    (self._pure_ff35_entry_rank(out, j), j))
                            pos = j + 1
                if ranked:
                    ranked.sort(key=lambda x: x[0])
                    new_tgt = ranked[0][1]
            if new_tgt is None:
                continue
            anchor: Optional[int] = None
            for delta in range(0, 16):
                for key in ((x86_rva - delta) & 0xFFFFFFFF,
                            (x86_rva + delta) & 0xFFFFFFFF):
                    cand = rva_map.get(key)
                    if cand is not None and 0 <= cand < len(out):
                        anchor = cand
                        break
                if anchor is not None:
                    break
            if anchor is None:
                continue
            best_j: Optional[int] = None
            best_dist = 999999
            closest_ok: Optional[int] = None
            closest_ok_dist = 999999
            for j in range(max(0, anchor - 16),
                           min(len(out) - 5, anchor + 160)):
                if out[j] != 0xE8:
                    continue
                if not self._e8_byte_is_real_call(out, j):
                    continue
                cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
                dist = abs(j - anchor)
                if (0 <= cur < len(out)
                        and cur == new_tgt
                        and self._x64_entry_prologue_ok(out, cur)):
                    if dist < closest_ok_dist:
                        closest_ok_dist = dist
                        closest_ok = j
                    continue
                if (0 <= cur < len(out)
                        and self._pure_mapped_entry_sane(
                            out, cur, tgt_x86, text_data, text_rva)
                        and self._x64_entry_prologue_ok(out, cur)):
                    # Valid for this helper but not the chosen body — ignore.
                    continue
                if dist < best_dist:
                    best_dist = dist
                    best_j = j
            # Prefer the E8 nearest the call site.  A farther stub that already
            # points at the helper must not suppress fixing the local E8
            # (cmd 0x9ED2 stayed on mid-function movabs while a distant stub
            # was already correct).
            if closest_ok is not None and closest_ok_dist <= best_dist:
                rva_map[tgt_x86] = new_tgt
                continue
            if best_j is None:
                if closest_ok is not None:
                    rva_map[tgt_x86] = new_tgt
                continue
            cur = best_j + 5 + struct.unpack_from('<i', out, best_j + 1)[0]
            if cur != new_tgt:
                struct.pack_into('<i', out, best_j + 1,
                                 new_tgt - (best_j + 5))
                fixed += 1
            rva_map[tgt_x86] = new_tgt
        return fixed

    def _pure_fix_bad_align_stub_targets(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget align-stub E8s whose current landing is clearly wrong.

        Only touches stubs that land mid-movabs-imm or off a prologue.  Uses a
        wide window from the containing function entry so large-frame bodies
        (``mov eax,imm; call __chkstk`` + wipe) still get fixed without the
        whole-function zip that breaks CRT.
        """
        if not self._cmd_no_hacks or not HAS_CAPSTONE:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        fn_rvas = sorted(r for r in (self._fn_entry_rvas or set()) if r in rva_map)
        if not fn_rvas:
            return 0
        x64_entries = sorted(set(rva_map[r] for r in fn_rvas))
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        fixed = 0

        def _is_thin_iat_thunk(tgt: int) -> bool:
            """Align-wrapped ``movabs rax, iat; mov rax,[rax]; call rax`` stub."""
            if tgt < 0 or tgt + pl + 16 > len(out):
                return False
            body = tgt
            if out[tgt:tgt + pl] == pro:
                body = tgt + pl
            if body + 15 > len(out):
                return False
            if out[body] not in (0x48, 0x49, 0x4C, 0x4D):
                return False
            if not (0xB8 <= out[body + 1] <= 0xBF):
                return False
            # mov rax, [rax]; call rax  — or call via other low reg
            if out[body + 10:body + 13] == b'\x48\x8b\x00' and out[body + 13] == 0xFF:
                return True
            if out[body + 10:body + 12] == b'\xFF\xD0':
                return True
            return False

        def _bad(tgt: int) -> bool:
            if tgt < 0 or tgt >= len(out):
                return True
            if self._pure_off_in_imm_operand(out, tgt):
                return True
            if _is_thin_iat_thunk(tgt):
                return True
            return not self._x64_entry_prologue_ok(out, tgt)

        for i, fn in enumerate(fn_rvas):
            foff = fn - text_rva
            if foff < 0 or foff >= len(text_data):
                continue
            x86_end = fn_rvas[i + 1] if i + 1 < len(fn_rvas) else None
            end_off = (x86_end - text_rva) if x86_end is not None else len(text_data)
            end_off = min(end_off, len(text_data))
            x86_calls: List[int] = []
            for ins in md32.disasm(bytes(text_data[foff:end_off]),
                                   self.old_base + fn):
                if (ins.mnemonic == 'call' and ins.operands
                        and ins.operands[0].type == X86_OP_IMM):
                    t = (ins.operands[0].imm - self.old_base) & 0xFFFFFFFF
                    if not self._is_alloca_probe_rva(t):
                        x86_calls.append(t)
            if not x86_calls:
                continue
            x64_off = rva_map[fn]
            x64_end = len(out)
            for e in x64_entries:
                if e > x64_off:
                    x64_end = e
                    break
            stubs: List[int] = []
            scan = max(0, x64_off)
            while scan < min(x64_end, len(out) - pl - el - 5):
                if out[scan:scan + pl] == pro:
                    j = scan + pl
                    if out[j] == 0xE8 and out[j + 5:j + 5 + el] == epi:
                        stubs.append(j)
                scan += 1
            # Only rewrite stubs that are clearly wrong.  An exact stub/call
            # count zip mis-pairs when the translator inlines/elides calls and
            # paints good stubs with interior offsets (e.g. 0x2fdac mid-jne).
            pairs: List[Tuple[int, int]] = []
            ti = 0
            for j in stubs:
                cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
                if not _bad(cur):
                    continue
                while ti < len(x86_calls):
                    t86 = x86_calls[ti]
                    ti += 1
                    pairs.append((j, t86))
                    break
            for best_j, t86 in pairs:
                cur = best_j + 5 + struct.unpack_from('<i', out, best_j + 1)[0]
                new_tgt = self._pure_find_sane_entry_for_x86(
                    out, t86, rva_map, text_data, text_rva)
                if new_tgt is None:
                    new_tgt = self._pure_resolve_x86_call_target(
                        out, t86, rva_map, text_data, text_rva)
                if new_tgt is None or new_tgt == cur:
                    continue
                new_tgt = self._pure_snap_chkstk_home_spill_entry(out, new_tgt)
                if self._pure_off_in_imm_operand(out, new_tgt):
                    continue
                if not self._x64_entry_prologue_ok(out, new_tgt):
                    continue
                if _is_thin_iat_thunk(new_tgt):
                    continue
                struct.pack_into('<i', out, best_j + 1,
                                 new_tgt - (best_j + 5))
                fixed += 1
        return fixed

    def _pure_fixup_named_align_calls(self, out: bytearray,
                                      rva_map: Dict[int, int],
                                      text_data: bytes, text_rva: int) -> int:
        """Surgical align-stub fixes for x86 call sites whose anchors share a stub."""
        if not self._cmd_no_hacks:
            return 0
        pairs = (
            (0xAC12, 0x6581),
            (0xAC1C, 0x640E),
        )
        fixed = 0
        used: Set[int] = set()
        for x86_e8, fn_rva in pairs:
            new_tgt = rva_map.get(fn_rva)
            if new_tgt is None or not self._pure_call_target_plausible(out, new_tgt):
                continue
            anchor: Optional[int] = rva_map.get(x86_e8)
            if anchor is None:
                for delta in range(0, 8):
                    anchor = rva_map.get((x86_e8 - delta) & 0xFFFFFFFF)
                    if anchor is not None:
                        break
            if anchor is None:
                continue
            sites = [s for s in self._pure_call_e8_sites_near_anchor(out, anchor)
                     if s not in used]
            if not sites:
                continue
            site = min(sites, key=lambda s: abs(s - anchor))
            cur = site + 5 + struct.unpack_from('<i', out, site + 1)[0]
            if cur != new_tgt:
                struct.pack_into('<i', out, site + 1, new_tgt - (site + 5))
                fixed += 1
            used.add(site)
        return fixed

    def _pure_fixup_teb_indirect_field_disps(self, out: bytearray) -> int:
        """Remap ``[teb+4/8]`` d8 fields after ``gs:[0x30]`` self loads."""
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 12:
            if (out[i] != 0x65 or out[i + 1] != 0x48 or out[i + 2] != 0x8B
                    or out[i + 4] != 0x25
                    or struct.unpack_from('<I', out, i + 5)[0] != 0x30):
                i += 1
                continue
            base = (out[i + 3] >> 3) & 7
            j = i + 9
            for k in range(j, min(j + 96, len(out) - 3)):
                if out[k] not in (0x8B, 0x89, 0x3B, 0x39, 0x85):
                    continue
                m = out[k + 1]
                if (m & 7) != base:
                    continue
                mod = (m >> 6) & 3
                if mod == 1:
                    disp_i = k + 2
                    if disp_i >= len(out):
                        break
                    old = out[disp_i]
                    if old in (4, 8):
                        new = TEB_FS_TO_GS[old]
                    elif old == 0xFF:
                        new = 0x10
                    else:
                        continue
                    if new != old and new < 0x80:
                        out[disp_i] = new
                        fixed += 1
                elif mod == 2:
                    disp_i = k + 2
                    if disp_i + 4 > len(out):
                        break
                    old = struct.unpack_from('<I', out, disp_i)[0]
                    if old not in (4, 8):
                        continue
                    new = TEB_FS_TO_GS[old]
                    if new != old:
                        struct.pack_into('<I', out, disp_i, new)
                        fixed += 1
            i += 9
        return fixed

    def _pure_fixup_teb_stack_bounds_idiom(self, out: bytearray) -> int:
        """Promote pointer-width ops in TEB stack-range validators (universal).

        MSVC CRT helpers (``_chkstk``-adjacent stack/SEH validators present in
        *any* Win2000 binary) read TEB StackBase/StackLimit via ``fs:[0x18]`` →
        ``[teb+4]`` / ``[teb+8]`` and bounds-check pointers against them.  On x64
        these fields and the validated pointers are 64-bit, so the naive 32-bit
        translation truncates them and the check fails.

        This keys off the universal ``mov rX, gs:[0x30]`` self-load already used
        for TEB fixups: when a self-load is followed by StackBase(+8)/StackLimit
        (+0x10) reads, the surrounding validation cluster is promoted to qword.
        No per-binary RVAs are used.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        n = len(out)
        si = 0
        while si < n - 12:
            # gs:[0x30] self-load: 65 48 8B /r 25 30 00 00 00
            if (out[si] != 0x65 or out[si + 1] != 0x48 or out[si + 2] != 0x8B
                    or out[si + 4] != 0x25
                    or struct.unpack_from('<I', out, si + 5)[0] != 0x30):
                si += 1
                continue
            base = (out[si + 3] >> 3) & 7
            # Confirm a StackBase/StackLimit read off the self-load base within a
            # short window (8B /r with modrm.rm==base and disp8 in {8, 0x10}).
            wlo = si + 9
            whi = min(n - 3, si + 40)
            idiom = False
            k = wlo
            while k < whi:
                if (out[k] == 0x8B or (out[k] == 0x48 and k + 1 < n and out[k + 1] == 0x8B)):
                    mpos = k + (1 if out[k] == 0x48 else 0)
                    m = out[mpos + 1] if mpos + 1 < n else 0
                    if (m >> 6) & 3 == 1 and (m & 7) == base and out[mpos + 2] in (8, 0x10):
                        idiom = True
                        break
                k += 1
            if not idiom:
                si += 9
                continue
            # Promote the validation cluster to qword within the function window.
            lo = max(0, si - 0x30)
            hi = min(n, si + 0x120)
            i = lo
            while i < hi - 2:
                b0, b1, b2 = out[i], out[i + 1], out[i + 2]
                # mov [rsi+0xc], eax / mov eax,[rsi+0xc]  (lea'd stack ptr store/load)
                if b0 in (0x89, 0x8B) and b1 == 0x46 and b2 == 0x0C:
                    out.insert(i, 0x48); fixed += 1; hi += 1; n += 1; i += 4; continue
                # mov edx,[rbase+8] StackBase / mov ecx,[rbase+0x10] StackLimit
                if b0 == 0x8B and b1 == 0x50 and b2 == 0x08:
                    out.insert(i, 0x48); fixed += 1; hi += 1; n += 1; i += 4; continue
                if b0 == 0x8B and b1 == 0x48 and b2 == 0x10:
                    out.insert(i, 0x48); fixed += 1; hi += 1; n += 1; i += 4; continue
                # cmp [rbp+0x10], edx/ecx (homed pointer arg vs StackBase/StackLimit)
                if b0 in (0x39, 0x3B) and b1 in (0x55, 0x4D) and b2 == 0x10:
                    out.insert(i, 0x48); fixed += 1; hi += 1; n += 1; i += 5; continue
                # cmp eax,edx / cmp eax,ecx (validated ptr vs bounds)
                if b0 == 0x39 and b1 in (0xD0, 0xC8):
                    out.insert(i, 0x48); fixed += 1; hi += 1; n += 1; i += 3; continue
                i += 1
            si = hi
        return fixed

    def _pure_fixup_crt_initterm_push_imm_pairs(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Re-sync ``push end; push start; call _initterm`` movabs RCX/RDX in CRT startup."""
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        n = len(text_data)
        lo = self.old_base + 0x1C000
        hi = self.old_base + 0x1C020
        for off in range(n - 10):
            if text_data[off] != 0x68 or text_data[off + 5] != 0x68:
                continue
            end_imm = struct.unpack_from('<I', text_data, off + 1)[0]
            start_imm = struct.unpack_from('<I', text_data, off + 6)[0]
            if not (lo <= end_imm < hi and lo <= start_imm < hi):
                continue
            call_at = off + 10
            if call_at >= n or text_data[call_at] != 0xE8:
                continue
            rel = struct.unpack_from('<i', text_data, call_at + 1)[0]
            tgt_x86 = (text_rva + call_at + 5 + rel) & 0xFFFFFFFF
            if tgt_x86 != 0x1A98C:
                continue
            anchor = rva_map.get((text_rva + off) & 0xFFFFFFFF)
            if anchor is None:
                anchor = rva_map.get((text_rva + off + 5) & 0xFFFFFFFF)
            if anchor is None:
                continue
            exp_rcx = self._relocate_imm(start_imm) & 0xFFFFFFFFFFFFFFFF
            exp_rdx = self._relocate_imm(end_imm) & 0xFFFFFFFFFFFFFFFF
            scan_lo = max(0, anchor - 8)
            scan_hi = min(len(out) - 10, anchor + 48)
            rcx_site: Optional[int] = None
            rdx_site: Optional[int] = None
            for i in range(scan_lo, scan_hi):
                if out[i] != 0x48 or out[i + 1] != 0xB9:
                    continue
                imm = struct.unpack_from('<Q', out, i + 2)[0]
                if imm == exp_rcx:
                    rcx_site = i
                    break
                if rcx_site is None:
                    rcx_site = i
            for i in range(scan_lo, scan_hi):
                if out[i] != 0x48 or out[i + 1] != 0xBA:
                    continue
                imm = struct.unpack_from('<Q', out, i + 2)[0]
                if imm == exp_rdx:
                    rdx_site = i
                    break
                if rdx_site is None:
                    rdx_site = i
            if rcx_site is not None:
                got = struct.unpack_from('<Q', out, rcx_site + 2)[0]
                if got != exp_rcx:
                    struct.pack_into('<Q', out, rcx_site + 2, exp_rcx)
                    fixed += 1
            if rdx_site is not None:
                got = struct.unpack_from('<Q', out, rdx_site + 2)[0]
                if got != exp_rdx:
                    struct.pack_into('<Q', out, rdx_site + 2, exp_rdx)
                    fixed += 1
        return fixed

    def _pure_retarget_xor_jmp_epilogue_jccs(self, out: bytearray,
                                              rva_map: Dict[int, int],
                                              text_data: bytes,
                                              text_rva: int) -> int:
        """Retarget Jccs that should hit ``xor eax,eax; jmp epi`` but land wrong.

        Late heals often remap the x86 label onto a mid-epilogue ``pop``
        (cmd 0x4B62 → pop rsi).  Walk x86 ``jcc`` sites whose target is the
        xor-jmp idiom and force the PE64 rel32 onto the translated xor blob.
        """
        if not self._cmd_no_hacks or not HAS_CAPSTONE or not text_data:
            return 0
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        fixed = 0

        for off in range(len(text_data) - 6):
            b0 = text_data[off]
            if not (b0 == 0x0F or 0x70 <= b0 <= 0x7F):
                continue
            xrva = text_rva + off
            insns = list(md32.disasm(
                bytes(text_data[off:off + 16]),
                self.old_base + xrva, count=1))
            if not insns:
                continue
            insn = insns[0]
            mnem = insn.mnemonic
            if not mnem.startswith('j') or mnem == 'jmp':
                continue
            if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                continue
            tgt_x86 = (insn.operands[0].imm - self.old_base) & 0xFFFFFFFF
            if not self._x86_is_xor_eax_jmp_epilogue(text_data, text_rva, tgt_x86):
                continue
            want = self._resolve_jcc_target_off(out, tgt_x86, rva_map)
            if want is None:
                continue
            # Find the PE64 jcc whose rva_map site is this x86 insn.
            site = rva_map.get(xrva)
            if site is None:
                continue
            # Search a small window for a near Jcc encoding.
            patched = False
            for p in range(max(0, site - 8), min(len(out) - 5, site + 48)):
                if out[p] == 0x0F and p + 6 <= len(out) and 0x80 <= out[p + 1] <= 0x8F:
                    rel = struct.unpack_from('<i', out, p + 2)[0]
                    cur = p + 6 + rel
                    if cur == want:
                        patched = True
                        break
                    # Retarget whenever the landing is not the xor blob.
                    struct.pack_into('<i', out, p + 2, want - (p + 6))
                    fixed += 1
                    patched = True
                    break
                elif 0x70 <= out[p] <= 0x7F and p + 2 <= len(out):
                    # short jcc — expand not handled; skip
                    continue
            if not patched and site + 6 <= len(out):
                # Direct site may already be the jcc opcode.
                p = site
                if out[p] == 0x0F and 0x80 <= out[p + 1] <= 0x8F:
                    struct.pack_into('<i', out, p + 2, want - (p + 6))
                    fixed += 1
        return fixed

    def _pure_materialize_call_epilogues(self, out: bytearray,
                                         rva_map: Dict[int, int]) -> int:
        """Ensure every x86 call target that is a pop/ret or bare-ret label is emitted."""
        if not self._cmd_no_hacks or not self._x86_cf:
            return 0
        cf = self._x86_cf
        done = 0
        need = set(cf.call_targets) | set(cf.branch_targets)
        for ep_rva in sorted(need):
            if ep_rva not in cf.epilogue_labels:
                continue
            if self._materialize_epilogue_label(out, rva_map, ep_rva) is not None:
                done += 1
        return done

    def _pure_snap_calls_to_epilogue_targets(self, out: bytearray,
                                             rva_map: Dict[int, int],
                                             text_data: bytes,
                                             text_rva: int) -> int:
        """Patch E8 rel32 that should call materialized epilogue/ret labels."""
        if not self._cmd_no_hacks or not HAS_CAPSTONE or not self._x86_cf:
            return 0
        cf = self._x86_cf
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        fixed = 0

        def _old_rva_for_out_off(off: int) -> Optional[int]:
            candidates = [(mapped, rva) for rva, mapped in rva_map.items()
                          if mapped <= off]
            if not candidates:
                return None
            return max(candidates, key=lambda x: x[0])[1]

        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            old_rva = _old_rva_for_out_off(i)
            if old_rva is None:
                continue
            off_in_sec = old_rva - text_rva
            if off_in_sec < 0 or off_in_sec >= len(text_data):
                continue
            found_target = None
            for insn in md32.disasm(text_data[max(0, off_in_sec - 8):off_in_sec + 8],
                                    self.old_base + text_rva + max(0, off_in_sec - 8),
                                    count=16):
                if insn.address - self.old_base != old_rva:
                    continue
                if insn.mnemonic != 'call':
                    break
                if insn.operands and insn.operands[0].type == X86_OP_IMM:
                    found_target = (insn.operands[0].imm - self.old_base) & 0xFFFFFFFF
                break
            if found_target is None or found_target not in cf.epilogue_labels:
                continue
            new_tgt = self._materialize_epilogue_label(out, rva_map, found_target)
            if new_tgt is None:
                new_tgt = self._resolve_call_target_off(out, found_target, rva_map)
            if new_tgt is None:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            if i + 5 + rel == new_tgt:
                continue
            struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
            fixed += 1
        return fixed

    def _snap_calls_past_add_rsp_epilogue(self, out: bytearray) -> int:
        """Redirect E8 targets that land on ``add rsp, N`` tails to the next entry."""
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt + 4 > len(out) or out[tgt:tgt + 3] != b'\x48\x83\xc4':
                continue
            for delta in range(0, 20):
                pos = tgt + delta
                if pos >= len(out):
                    break
                if out[pos] in (0x53, 0x56, 0x55) or out[pos:pos + 2] == b'\x48\xb8':
                    if pos != tgt:
                        struct.pack_into('<i', out, i + 1, pos - (i + 5))
                        fixed += 1
                    break
        return fixed

    def _fix_align_epilogue_x86_gaps(self, out: bytearray) -> int:
        """NOP/jmp over orphaned x86 bytes between align epilogue and next PE64 insn."""
        if self._cmd_no_hacks:
            return 0
        epi = b'\x4c\x89\xec\x41\x5d'
        fixed = 0
        i = 0
        while i < len(out) - len(epi) - 4:
            if out[i:i + len(epi)] != epi:
                i += 1
                continue
            j = i + len(epi)
            if self._orphan_byte_protected(j):
                i = j
                continue
            if self._looks_like_x64_insn_start(out, j):
                i = j
                continue
            # Only scrub when the gap still contains obvious x86 orphans.
            head = out[j:min(j + 6, len(out))]
            if not (head[:2] == b'\x84\x45' or head[:1] in (b'\xc2', b'\x8b', b'\x89')
                    or (len(head) >= 3 and head[0] == 0x00)):
                i = j
                continue
            target = self._gap_target_after_align_epilogue(out, j)
            if target is None or target <= j:
                i = j
                continue
            if self._orphan_byte_protected(target):
                i = j
                continue
            gap = target - j
            if gap <= 8:
                out[j:target] = b'\x90' * gap
            else:
                rel = target - (j + 5)
                out[j:j + 5] = b'\xE9' + struct.pack('<i', rel)
                if gap > 5:
                    out[j + 5:target] = b'\x90' * (gap - 5)
            fixed += 1
            i = target
        return fixed

    def _scrub_stray_x86_before_call(self, out: bytearray) -> int:
        """Drop orphaned x86 ``test byte ptr [ebp], al`` before PE64 CALL slots."""
        pat = b'\x84\x45\x00\x00\xe8'
        repl = b'\x90' * 4 + b'\xe8'
        scrubbed = 0
        i = 0
        while i + len(pat) <= len(out):
            if out[i:i + len(pat)] == pat:
                out[i:i + len(pat)] = repl
                scrubbed += 1
                i += len(repl)
                continue
            i += 1
        return scrubbed

    def _repair_unfixed_calls(self, out: bytearray, rva_map: Dict[int, int],
                              text_data: bytes, text_rva: int) -> int:
        """
        Last resort: for E8 rel32=0 placeholders, read the x86 CALL target from
        the source PE and patch using the global rva_map.
        """
        md32 = Cs(CS_ARCH_X86, CS_MODE_32)
        md32.detail = True
        # section offset → best-known old RVA (floor of mapped insn)
        off_to_old: Dict[int, int] = {}
        for old_rva, new_off in rva_map.items():
            off_to_old[new_off] = old_rva

        def _old_rva_for_out_off(off: int) -> Optional[int]:
            candidates = [(mapped, rva) for rva, mapped in rva_map.items() if mapped <= off]
            if not candidates:
                return None
            return max(candidates, key=lambda x: x[0])[1]

        fixed = 0
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._e8_byte_is_real_call(out, i):
                continue
            if struct.unpack_from('<i', out, i + 1)[0] != 0:
                continue
            old_rva = _old_rva_for_out_off(i)
            if old_rva is None:
                continue
            off_in_sec = old_rva - text_rva
            if off_in_sec < 0 or off_in_sec >= len(text_data):
                continue
            # Disassemble a few insns around the mapped site to find CALL
            start = max(0, off_in_sec - 16)
            found_target = None
            for insn in md32.disasm(text_data[start:], self.old_base + text_rva + start, count=32):
                if insn.address - self.old_base == old_rva and insn.mnemonic == 'call':
                    if insn.operands and insn.operands[0].type == X86_OP_IMM:
                        found_target = (insn.operands[0].imm - self.old_base) & 0xFFFFFFFF
                    break
            if found_target is None:
                continue
            if self._cmd_no_hacks:
                tgt_off = self._resolve_call_target_off(out, found_target, rva_map)
            else:
                tgt_off = rva_map.get(found_target)
            if tgt_off is None:
                continue
            rel = tgt_off - (i + 5)
            struct.pack_into('<i', out, i + 1, rel)
            fixed += 1
        return fixed

    def _snap_zero_byte_call_targets(self, out: bytearray) -> int:
        """Redirect E8/E9 branches that target mid-instruction or zero bytes.

        Universal for any Win2000 pure binary.  Two checks:
        1. Target byte is ``0x00`` → skip past zeros to next mapped offset.
        2. Target is not a known instruction start → snap backward to the
           nearest preceding instruction start (the insn containing tgt).
        """
        if not self.rva_map:
            return 0
        mapped = set(self.rva_map)
        starts = self._pure_insn_start_set(out) if self._cmd_no_hacks else None
        fixed = 0
        for i in range(len(out) - 5):
            if out[i] not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if tgt <= 0 or tgt >= len(out):
                continue
            # Check 1: zero-byte target
            if out[tgt] == 0x00:
                new_tgt = tgt
                while new_tgt < len(out) and out[new_tgt] == 0x00:
                    new_tgt += 1
                if new_tgt >= len(out):
                    continue
                for pos in range(new_tgt, min(new_tgt + 64, len(out))):
                    if pos in mapped:
                        new_tgt = pos
                        break
                if new_tgt != tgt:
                    struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
                    fixed += 1
                continue
            # Check 2: mid-instruction — snap BACKWARD to containing insn start
            if starts is not None and tgt not in starts:
                new_tgt = tgt
                for pos in range(tgt - 1, max(tgt - 16, 0), -1):
                    if pos in starts:
                        new_tgt = pos
                        break
                if new_tgt != tgt:
                    struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
                    fixed += 1
        return fixed

    def _snap_jcc_misaligned_targets(self, out: bytearray) -> int:
        """Fix Jcc rel32 targets that land mid-instruction (esp. after rva_map skew)."""
        if not HAS_CAPSTONE:
            return 0
        # Pure mode: use the authoritative instruction-start set, which is built
        # from function entries and never desyncs on interleaved data (the old
        # local-window disasm could miss mid-instruction targets and leave an
        # illegal-instruction fault).
        starts = self._pure_insn_start_set(out) if self._cmd_no_hacks else None
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        fixed = 0
        for i in range(len(out) - 6):
            if out[i] != 0x0F or not (0x80 <= out[i + 1] <= 0x8F):
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = i + 6 + rel
            if tgt <= 0 or tgt >= len(out):
                continue
            # Universal: a branch target landing on NUL bytes (``00``) is
            # always wrong — ``add [rax], al`` crashes when RAX == 0 and
            # real translated code never starts with a zero byte.  Skip
            # forward to the first mapped non-zero byte.
            if out[tgt] == 0x00:
                new_tgt = None
                for pos in range(tgt, min(tgt + 64, len(out))):
                    if out[pos] != 0x00:
                        # Prefer a position that is a known instruction start
                        # or has an rva_map entry (i.e. was emitted by the
                        # translator, not padding).
                        if (starts is None or pos in starts
                                or pos in self.rva_map):
                            new_tgt = pos
                            break
                        if new_tgt is None:
                            new_tgt = pos
                if new_tgt is not None and new_tgt != tgt:
                    struct.pack_into('<i', out, i + 2, new_tgt - (i + 6))
                    fixed += 1
                continue
            if starts is not None:
                if tgt in starts and out[tgt] != 0x00:
                    continue
                new_tgt = None
                for pos in range(tgt, min(tgt + 64, len(out))):
                    if pos in starts and out[pos] != 0x00:
                        new_tgt = pos
                        break
                if new_tgt is None or new_tgt == tgt:
                    continue
                struct.pack_into('<i', out, i + 2, new_tgt - (i + 6))
                fixed += 1
                continue
            insns = list(md.disasm(out[max(0, tgt - 16):tgt + 16],
                                   max(0, tgt - 16), count=6))
            mid = False
            for ins in insns:
                end = ins.address + ins.size
                if ins.address <= tgt < end and ins.address != tgt:
                    mid = True
                    break
            if not mid:
                continue
            new_tgt = tgt
            for pos in range(tgt, min(tgt + 64, len(out) - 2)):
                if out[pos:pos + 2] in (b'\x49\xbb', b'\x48\xb8', b'\x48\x8b'):
                    new_tgt = pos
                    break
            else:
                for start in range(max(0, tgt - 16), tgt + 1):
                    one = list(md.disasm(out[start:start + 8], start, count=1))
                    if one and one[0].address == start:
                        new_tgt = start
                        break
            if new_tgt != tgt:
                struct.pack_into('<i', out, i + 2, new_tgt - (i + 6))
                fixed += 1
        return fixed

    def _repair_jcc_targets_from_rva_map(self, out: bytearray,
                                         rva_map: Dict[int, int]) -> int:
        """Re-resolve Jcc targets that rva_map aims at the wrong PE64 offset."""
        fixed = 0
        for i in range(len(out) - 6):
            if out[i] != 0x0F or not (0x80 <= out[i + 1] <= 0x8F):
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = i + 6 + rel
            for x86_rva, mapped in rva_map.items():
                if mapped != tgt:
                    continue
                refined = self._refine_shim_target_off(out, x86_rva, tgt)
                if refined != tgt:
                    struct.pack_into('<i', out, i + 2, refined - (i + 6))
                    fixed += 1
                    break
        return fixed

    def _pure_snap_interior_rva_map_back_past_ret(
            self, out: bytearray, rva_map: Dict[int, int]) -> int:
        """Move rva_map slots past a foreign ``setne; ret`` back to the real entry.

        Only the narrow case that broke cmd 0xF548→0xF590 (map landed on
        ``mov rdx,0x2d`` past BA38's ``setne al; ret``).  A broad interior
        scan retargeted thousands of slots onto wrong bodies (univ104:
        ``call`` into ``mov eax,ebx; pop; ret`` → RBP corruption).
        """
        if not self._cmd_no_hacks:
            return 0
        jccs: List[Tuple[int, int]] = []
        for i in range(len(out) - 6):
            if out[i] == 0x0F and 0x80 <= out[i + 1] <= 0x8F:
                rel = struct.unpack_from('<i', out, i + 2)[0]
                jccs.append((i, i + 6 + rel))

        fixed = 0
        # Restrict to x86 sites that are real control-flow targets.
        need: Set[int] = set(self._fn_entry_rvas or ())
        cf = self._x86_cf
        if cf:
            need |= set(cf.call_targets or ())
            need |= set(getattr(cf, 'epilogue_labels', None) or ())
        for x86_rva in need:
            pe = rva_map.get(x86_rva)
            if pe is None or pe < 8 or pe >= len(out):
                continue
            entry: Optional[int] = None
            for back in range(1, 24):
                pos = pe - back
                if pos < 3:
                    break
                # Require ``setne al; ret`` (or setne; nop; ret) immediately
                # before the candidate entry — the BA38/F590 collision shape.
                if out[pos] != 0xC3:
                    continue
                p = pos - 1
                while p > 0 and out[p] in (0x90, 0xCC):
                    p -= 1
                if p < 2 or out[p - 2:p + 1] != b'\x0f\x95\xc0':
                    continue
                cand = pos + 1
                while cand < pe and out[cand] in (0x90, 0xCC, 0x00):
                    cand += 1
                if cand >= pe:
                    continue
                if out[cand:cand + 2] not in (
                        b'\x48\xb8', b'\x48\xb9', b'\x48\xba', b'\x48\xbb',
                        b'\x49\xbb', b'\x49\xb8'):
                    continue
                if not self._pure_call_target_plausible(out, cand):
                    continue
                entry = cand
                break
            if entry is None or entry == pe:
                continue
            old_pe = pe
            rva_map[x86_rva] = entry
            fixed += 1
            lo = min(old_pe, entry) - 8
            for site, tgt in jccs:
                if tgt == old_pe or (lo <= tgt < entry):
                    struct.pack_into('<i', out, site + 2, entry - (site + 6))
        return fixed

    def _pure_snap_jcc_off_setne_ret_epilogue(self, out: bytearray) -> int:
        """Snap Jcc off ``setne al; ret`` onto the next plausible entry.

        cmd 0xF548 ``je 0xF590`` was repaired onto BA38's ``setne al; ret``
        (the previous function), leaving ``RDI=2`` / ``RIP=2`` after return.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        for i in range(len(out) - 6):
            if out[i] != 0x0F or not (0x80 <= out[i + 1] <= 0x8F):
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = i + 6 + rel
            if tgt < 0 or tgt + 4 > len(out):
                continue
            # setne al; ret   OR   setne al; nop*; ret
            if out[tgt:tgt + 3] != b'\x0f\x95\xc0':
                continue
            p = tgt + 3
            while p < len(out) and out[p] in (0x90, 0xCC):
                p += 1
            if p >= len(out) or out[p] != 0xC3:
                continue
            entry = p + 1
            while entry < len(out) and out[entry] in (0x90, 0xCC, 0x00):
                entry += 1
            if entry >= len(out) or not self._pure_call_target_plausible(out, entry):
                continue
            if entry == tgt:
                continue
            struct.pack_into('<i', out, i + 2, entry - (i + 6))
            fixed += 1
        return fixed

    def _pure_snap_jcc_off_bare_ret_to_epilogue(self, out: bytearray) -> int:
        """Snap Jcc off a lone ``ret`` / ``nop; ret`` onto a real shared epi.

        cmd 0xFD72 ``je 0xFDC3`` landed on a rematerialized bare ``ret`` six
        bytes before the real shared epilogue (``mov eax,edi; pop*; ret``),
        so the abort path after ``/c`` parse returned with a trashed stack
        (``RIP=2``).  Same class: malloc helpers (``db95``) with
        ``test esi; jne shared_epi`` where the shared slot is ``nop; ret``
        instead of ``mov eax,esi; pop rsi; ret`` — success returns without
        restoring RSI and the caller then executes into heap.

        Also covers path-helper success (univ261 ``0x29A0D``): tip on
        ``nop; ret`` five bytes before ``mov eax,1; pop*; leave; ret``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0

        def _epi_head_at(q: int) -> Optional[int]:
            """Return start of a sane return epi at *q*, or None."""
            if q < 0 or q >= len(out):
                return None
            start = q
            # mov eax,imm32 / mov rax,imm32 / xor rax,rax / mov eax,e[sd]i
            if out[q] == 0xB8 and q + 5 <= len(out):
                q += 5
            elif (out[q:q + 3] == bytes([0x48, 0xC7, 0xC0])
                  and q + 7 <= len(out)):
                q += 7
            elif out[q:q + 3] == bytes([0x48, 0x31, 0xC0]):
                q += 3
            elif out[q:q + 2] in (
                    b'\x89\xf8', b'\x89\xf0', b'\x8b\xc7', b'\x8b\xc6',
                    b'\x89\xd8', b'\x8b\xc3'):
                q += 2
            else:
                return None
            pops = 0
            r = q
            while r < start + 20 and r < len(out):
                b = out[r]
                if 0x58 <= b <= 0x5F:
                    pops += 1
                    r += 1
                    continue
                if b == 0x41 and r + 1 < len(out) and 0x58 <= out[r + 1] <= 0x5F:
                    pops += 1
                    r += 2
                    continue
                if b == 0xC9:  # leave
                    r += 1
                    continue
                if b in (0xC3, 0xC2) and pops >= 1:
                    return start
                break
            return None

        for i in range(len(out) - 6):
            if out[i] != 0x0F or not (0x80 <= out[i + 1] <= 0x8F):
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = i + 6 + rel
            if tgt < 0 or tgt >= len(out):
                continue
            # Accept bare ret, or nop/int3/zero sled ending at ret.
            # Also ``leave; ret`` tips that belong on ``pop*; pop rbp; ret``
            # (univ262 ``jne`` after ``_setjmp3`` → ``0x387DC``).
            p = tgt
            while p < len(out) and p < tgt + 8 and out[p] in (0x90, 0xCC, 0x00):
                p += 1
            leave_ret = False
            if p < len(out) and out[p] == 0xC9:
                p2 = p + 1
                while p2 < len(out) and p2 < p + 4 and out[p2] in (0x90, 0xCC):
                    p2 += 1
                if p2 < len(out) and out[p2] == 0xC3:
                    leave_ret = True
                    p = p2
            if p >= len(out) or out[p] != 0xC3:
                continue
            if not leave_ret and p != tgt and out[tgt] not in (0x90, 0xCC, 0x00, 0xC3):
                continue
            # Prefer a nearby real epi *after* the bare ret.  Backward search
            # can land on a different function's epi (univ261 over-snaps).
            dest = None
            q = p + 1
            limit = min(len(out), p + 1 + 32)
            while q < limit:
                if out[q] in (0x90, 0xCC, 0x00):
                    q += 1
                    continue
                dest = _epi_head_at(q)
                break
            # For leave;ret tips, prefer nearby ``pop rsi; pop rbx; pop rbp; ret``
            if leave_ret and dest is None:
                for q in range(max(0, tgt - 8), min(len(out), tgt + 24)):
                    if out[q:q + 4] == bytes([0x5E, 0x5B, 0x5D, 0xC3]):
                        dest = q
                        break
                    if out[q:q + 5] == bytes([0x5F, 0x5E, 0x5B, 0x5D, 0xC3]):
                        dest = q
                        break
            # Prefer an in-function success epi near the Jcc itself
            # (cmd ``0x29A0D`` → local ``0x29A20`` rather than a far
            # rematerialized island that shares a bare-ret tip).
            local = None
            for q in range(i + 6, min(len(out), i + 6 + 0x40)):
                if out[q] in (0x90, 0xCC):
                    continue
                cand = _epi_head_at(q)
                if cand is not None and out[cand] in (0xB8, 0x48):
                    # mov eax/rax, imm — typical BOOL/success return
                    local = cand
                    break
                break
            if local is not None and not leave_ret:
                dest = local
            if dest is None:
                # Fallback: epi packed a few bytes *before* the bare ret.
                q = max(0, tgt - 16)
                limit = tgt
                while q < limit:
                    if out[q] in (0x90, 0xCC, 0x00):
                        q += 1
                        continue
                    cand = _epi_head_at(q)
                    # Only accept mov eax/esi-style shuffle epis backward —
                    # not ``mov eax,1`` (those belong after the bare ret).
                    if (cand is not None
                            and out[cand:cand + 2] in (
                                b'\x89\xf8', b'\x89\xf0', b'\x8b\xc7',
                                b'\x8b\xc6', b'\x89\xd8', b'\x8b\xc3')):
                        dest = cand
                    break
            if dest is None or dest == tgt:
                continue
            struct.pack_into('<i', out, i + 2, dest - (i + 6))
            fixed += 1
        return fixed

    def _pure_fix_jcc_short_pop_ret_to_local_leave_epi(self, out: bytearray) -> int:
        """Retarget Jcc off short shared ``pop*; ret`` onto local leave epi.

        cmd ``0x1D783`` / ``0x1D7A1`` ``je`` tipped on a rematerialized
        ``pop rbx; pop rbp; ret`` island while the real body epi
        ``mov eax,esi; pop rdi; pop rsi; pop rbx; leave; ret`` sat ~0x60
        bytes ahead.  Taking the short tip left RSI/RDI on the stack;
        ``pop rbp`` then loaded the sentinel ``0x4000`` and ``ret`` walked
        into ``RIP=0``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # Local leave epis that restore rdi/rsi/rbx then leave.
        local_pats = (
            b'\x89\xf0\x5f\x5e\x5b\xc9\xc3',  # mov eax,esi; pop rdi;rsi;rbx; leave; ret
            b'\x89\xf8\x5f\x5e\x5b\xc9\xc3',  # mov eax,edi; …
            b'\x89\xd8\x5f\x5e\x5b\xc9\xc3',  # mov eax,ebx; …
            b'\x8b\xc6\x5f\x5e\x5b\xc9\xc3',  # mov eax,esi (alt)
            b'\x8b\xc7\x5f\x5e\x5b\xc9\xc3',  # mov eax,edi (alt)
            # Frameless helpers (cmd skip-leading-space ``0x27EF0``): tip on
            # bare ``pop rsi; ret`` drops the ``mov eax,esi`` and returns 0.
            b'\x89\xf0\x5e\xc3',  # mov eax,esi; pop rsi; ret
            b'\x89\xf8\x5e\xc3',  # mov eax,edi; pop rsi; ret
            b'\x89\xd8\x5e\xc3',  # mov eax,ebx; pop rsi; ret
            b'\x8b\xc6\x5e\xc3',
            b'\x8b\xc7\x5e\xc3',
            b'\x89\xf0\x5f\xc3',  # mov eax,esi; pop rdi; ret
            b'\x89\xf8\x5f\xc3',
        )

        def _is_short_pop_ret(off: int) -> bool:
            if off < 0 or off >= len(out):
                return False
            p = off
            while p < len(out) and p < off + 4 and out[p] in (0x90, 0xCC, 0x00):
                p += 1
            start = p
            pops = 0
            has_leave = False
            while p < len(out) and p < start + 12:
                b = out[p]
                if 0x58 <= b <= 0x5F:
                    pops += 1
                    p += 1
                    continue
                if b == 0x41 and p + 1 < len(out) and 0x58 <= out[p + 1] <= 0x5F:
                    pops += 1
                    p += 2
                    continue
                if b == 0xC9:
                    has_leave = True
                    p += 1
                    continue
                if b in (0xC3, 0xC2):
                    # Short shared tip: 1–3 pops, no leave, starts with a pop
                    # (not mov eax,* / xor).  ``pop rbx; pop rbp; ret`` is the
                    # failure mode that ate the 1d5b4 frame.
                    if has_leave or pops < 1 or pops > 3:
                        return False
                    return out[start] in range(0x58, 0x60) or (
                        out[start] == 0x41
                        and start + 1 < len(out)
                        and 0x58 <= out[start + 1] <= 0x5F)
                break
            return False

        for i in range(len(out) - 6):
            if out[i] != 0x0F or not (0x80 <= out[i + 1] <= 0x8F):
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            tgt = i + 6 + rel
            if not _is_short_pop_ret(tgt):
                continue
            local = None
            window = min(len(out), i + 6 + 0xC0)
            for pat in local_pats:
                j = out.find(pat, i + 6, window)
                if j >= i + 6:
                    local = j
                    break
            if local is None or local == tgt:
                continue
            struct.pack_into('<i', out, i + 2, local - (i + 6))
            fixed += 1
        return fixed

    def _pure_fix_bp_scratch_clobbering_frame(self, out: bytearray) -> int:
        """Rewrite ``mov bp, mem`` / ``mov rcx,rbp`` that trash the frame pointer.

        x86 B00C uses ``ebp`` as a wchar scratch (``mov bp,[eax-4]; push ebp``)
        without an ``mov ebp,esp`` frame.  The pe64 translation keeps an RBP
        frame then emits ``mov bp,mem; mov rcx,rbp``, destroying the frame and
        looping with ``RBP=character``.

        Keep the wchar in ``r15`` (survives the subsequent ``movabs rcx``) and
        fold ``sub rsp,0x20; and rsp,-16`` into ``sub rsp,0x28`` so the longer
        ``movzx r15d`` / ``mov ecx,r15d`` sequence fits.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 24:
            # 66 8B 68 xx … = mov bp, word ptr [reg+disp8] (reg ≠ rsp/rbp/SIB)
            if not (out[i] == 0x66 and out[i + 1] == 0x8B
                    and (out[i + 2] & 0xF8) == 0x68
                    and out[i + 2] not in (0x6C, 0x6D)):
                i += 1
                continue
            if out[i + 4:i + 7] != b'\x48\x89\xe9':  # mov rcx, rbp
                i += 1
                continue
            # Prefer the align-wrapped form so we can free bytes via sub/and fold.
            # 41 55 49 89 e5 48 83 ec 20 48 83 e4 f0
            align = out[i + 7:i + 7 + 13]
            disp = out[i + 3]
            modrm_src = out[i + 2]
            # r/m field selects base; movzx r15d uses REX.R + reg=111
            new_modrm = (modrm_src & 0xC7) | 0x38  # reg=r15
            if align == bytes.fromhex('41554989e54883ec204883e4f0'):
                # movzx r15d,[base+disp]; mov ecx,r15d; push r13; mov r13,rsp;
                # sub rsp,0x28; nop*3
                chunk = bytearray()
                chunk += bytes([0x44, 0x0F, 0xB7, new_modrm, disp])  # 5
                chunk += b'\x44\x89\xf9'  # mov ecx, r15d (3)
                chunk += b'\x41\x55'  # push r13
                chunk += b'\x49\x89\xe5'  # mov r13, rsp
                chunk += b'\x48\x83\xec\x28'  # sub rsp, 0x28 (aligned shadow)
                while len(chunk) < 20:
                    chunk.append(0x90)
                out[i:i + 20] = chunk[:20]
                fixed += 1
                scan_from = i + 20
            else:
                # Fallback: movzx ecx (char lost after next rcx write — still
                # better than clobbering RBP for the first call).
                out[i:i + 7] = bytes([
                    0x0F, 0xB7, (modrm_src & 0xC7) | 0x08, disp,
                    0x90, 0x90, 0x90])
                fixed += 1
                scan_from = i + 7
            for j in range(scan_from, min(scan_from + 0x50, len(out) - 3)):
                if out[j:j + 3] == b'\x48\x89\xea':  # mov rdx, rbp
                    # Prefer r15 if we saved there; else ecx.
                    if align == bytes.fromhex('41554989e54883ec204883e4f0'):
                        out[j:j + 3] = b'\x44\x89\xfa'  # mov edx, r15d
                    else:
                        out[j:j + 3] = b'\x89\xca\x90'  # mov edx, ecx; nop
                    fixed += 1
                elif out[j:j + 3] == b'\x48\x89\xe9':  # mov rcx, rbp
                    if align == bytes.fromhex('41554989e54883ec204883e4f0'):
                        out[j:j + 3] = b'\x44\x89\xf9'  # mov ecx, r15d
                    else:
                        out[j:j + 3] = b'\x89\xc1\x90'
                    fixed += 1
                if out[j:j + 2] == b'\x55\x48' or out[j] == 0xC3:
                    break
            i = scan_from
            continue
        return fixed

    def _pure_fix_rbp_imm_scratch_before_cmp(self, out: bytearray) -> int:
        """Rewrite ``mov rbp, imm32; cmp eax, ebp`` to ``cmp eax, imm32``.

        MSVC uses ``ebp`` as a 32-bit immediate scratch (``mov ebp, 0x4000;
        cmp eax, ebp``) after ``push ebp`` in a frameless callee-save prologue.
        On PE64 the translator emits ``mov rbp, imm``, which destroys the
        saved frame pointer; a later ``leave``/caller frame then sets
        ``rsp=imm`` and returns to NULL (univ262 after ``/c`` path setup).

        Same-sized rewrite: ``3D imm32`` + 4 NOPs replaces the 9-byte pair.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i + 9 <= len(out):
            if (out[i:i + 3] == bytes([0x48, 0xC7, 0xC5])
                    and out[i + 7:i + 9] == bytes([0x39, 0xE8])):
                imm = bytes(out[i + 3:i + 7])
                out[i:i + 9] = bytes([0x3D]) + imm + b'\x90\x90\x90\x90'
                fixed += 1
                i += 9
            else:
                i += 1
        return fixed

    def _pure_restore_r13_after_align_call(self, out: bytearray) -> int:
        """Insert ``mov rsp,r13; pop r13`` after align-wrapped calls before ``pop; ret``.

        Pattern ``push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16; call;
        pop rsi; ret`` leaves RSP in the shadow area so ``ret`` pops a
        homed immediate (e.g. ``0x2D``) as the return address.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        prefix = bytes.fromhex('41554989e54883ec204883e4f0e8')
        restore = bytes.fromhex('4c89ec415d')  # mov rsp,r13; pop r13
        i = 0
        while True:
            j = out.find(prefix, i)
            if j < 0:
                break
            after = j + len(prefix) + 4
            if after + 7 > len(out):
                i = j + 1
                continue
            # Already restored?
            if out[after:after + 5] == restore:
                i = j + 1
                continue
            # pop r64; ret; nop*  → need 7 bytes for restore+pop+ret
            if (0x58 <= out[after] <= 0x5F and out[after + 1] == 0xC3
                    and all(b in (0x90, 0xCC, 0x00) for b in out[after + 2:after + 7])):
                pop_ret = bytes([out[after], 0xC3])
                out[after:after + 7] = restore + pop_ret
                fixed += 1
            i = j + 1
        return fixed

    def _pure_fix_empty_data_text_constant_movabs(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget movabs of empty .data slots onto rematerialized .text strings.

        ``push 0x…13e0`` (L\")\") was relocated into ``.data+…`` which stayed
        zero-filled, so ``lstrcmpiW(buffer, \")\")`` always failed.
        """
        if not self._cmd_no_hacks or not rva_map or not self._old_to_new_section:
            return 0
        pe = self.pe
        if pe is None:
            return 0
        nb = int(self.new_base or 0)
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))
        # .data span in the PE64 image
        data_lo = data_hi = 0
        for old_sec, new_sec in self._old_to_new_section.items():
            osec = pe.section_for_rva(old_sec)
            if not osec or (osec['flags'] & 0x20000000):
                continue
            name = osec.get('name') or ''
            if isinstance(name, bytes):
                name = name.split(b'\0')[0].decode('ascii', 'replace')
            else:
                name = str(name).split('\0')[0]
            if name.startswith('.data'):
                sz = max(osec.get('vsize', 0), osec.get('raw_sz', 0), 1)
                data_lo = nb + new_sec
                data_hi = data_lo + sz
                break
        if not data_lo:
            return 0

        def _blob_off(v: int) -> Optional[int]:
            v = int(v)
            if 0 <= v < len(out):
                return v
            if v >= text_new and (v - text_new) < len(out):
                return v - text_new
            return None

        # old_rva → pe64 VA of matching embedded bytes
        want: Dict[int, int] = {}
        n = len(text_data)
        for off in range(max(0, n - 5)):
            if text_data[off] != 0x68:
                continue
            imm = struct.unpack_from('<I', text_data, off + 1)[0]
            if not (self.old_base <= imm < self.old_base + pe.image_size):
                continue
            old_rva = imm - self.old_base
            sec = pe.section_for_rva(old_rva)
            if not sec or not (sec['flags'] & 0x20000000):
                continue
            src_off = old_rva - text_rva
            if src_off < 0 or src_off + 4 > n:
                continue
            chunk = text_data[src_off:src_off + 4]
            # wchar string / sentinel (xx 00 00 00) or utf16 pair
            if chunk[1] != 0 and chunk[1] != chunk[3]:
                continue
            raw = rva_map.get(old_rva)
            if raw is None:
                continue
            base = _blob_off(raw)
            if base is None:
                continue
            # Scan forward for the real bytes (rematerialize may insert a prefix).
            hit = None
            for delta in range(0, 64):
                p = base + delta
                if p + 4 <= len(out) and bytes(out[p:p + 4]) == chunk:
                    hit = p
                    break
            if hit is None:
                continue
            want[imm] = (nb + text_new + hit) & 0xFFFFFFFFFFFFFFFF
            want[nb + old_rva] = want[imm]

        # Also map common mistaken landings: .data + (old_rva - text_rva)
        # and nearby empty slots keyed for lookup by got VA.
        data_raw = None
        data_new = 0
        for old_sec, new_sec in self._old_to_new_section.items():
            osec = pe.section_for_rva(old_sec)
            if not osec or (osec['flags'] & 0x20000000):
                continue
            nm = osec.get('name') or ''
            if isinstance(nm, bytes):
                nm = nm.split(b'\0')[0].decode('ascii', 'replace')
            if str(nm).startswith('.data'):
                data_raw = pe.get_section_data(osec)
                data_new = new_sec
                break

        extra: Dict[int, int] = {}
        for imm, exp in list(want.items()):
            if imm >= nb:
                continue
            old_rva = (imm - self.old_base) & 0xFFFFFFFF
            candidates = [
                data_new + (old_rva - text_rva),
            ]
            # Observed cmd L")" 0x13e0 → .data+0x1040 / +0x1048 empty slots
            if old_rva == 0x13E0:
                candidates.append(data_new + 0x1040)
                candidates.append(data_new + 0x1048)
            for wrong_rva in candidates:
                wva = (nb + wrong_rva) & 0xFFFFFFFFFFFFFFFF
                if not (data_lo <= wva < data_hi):
                    continue
                if data_raw is not None:
                    off = wrong_rva - data_new
                    if not (0 <= off + 4 <= len(data_raw)):
                        continue
                    if data_raw[off:off + 4] != b'\x00\x00\x00\x00':
                        continue
                extra[wva] = exp
        want.update(extra)

        fixed = 0
        i = 0
        while i < len(out) - 10:
            if (out[i] in (0x48, 0x49, 0x4C, 0x4D)
                    and 0xB8 <= out[i + 1] <= 0xBF):
                got = struct.unpack_from('<Q', out, i + 2)[0]
                if data_lo <= got < data_hi:
                    exp = want.get(got)
                    if exp is not None and exp != got:
                        struct.pack_into('<Q', out, i + 2, exp)
                        fixed += 1
            i += 1
        return fixed

    def _pure_fix_text_string_arg_movabs(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Reclaim ``push <text-string>`` movabs that tipped into empty .data.

        Collapsed rva_map windows leave RegOpenKey/RegQueryValueEx name args as
        empty ``.data`` VAs (cmd ``0x196c`` / AutoRun ``0x1890`` → ``0x5e844`` /
        ``0x5e878``), so ``RegOpenKeyW`` opens with ``L\"\"`` and later queries
        raise ``STATUS_INVALID_HANDLE``.  Anchor from the nearby ``call`` and
        rewrite backward movabs whose immediate sits in zero-filled .data.
        """
        if not self._cmd_no_hacks or not rva_map or not self._old_to_new_section:
            return 0
        pe = self.pe
        if pe is None:
            return 0
        nb = int(self.new_base or 0)
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))
        data_lo = data_hi = 0
        data_raw = None
        data_new = 0
        for old_sec, new_sec in self._old_to_new_section.items():
            osec = pe.section_for_rva(old_sec)
            if not osec or (osec['flags'] & 0x20000000):
                continue
            nm = osec.get('name') or b''
            if isinstance(nm, bytes):
                nm = nm.split(b'\0')[0].decode('ascii', 'replace')
            if str(nm).startswith('.data'):
                data_new = new_sec
                data_lo = nb + new_sec
                sz = max(osec.get('vsize', 0), osec.get('raw_sz', 0), 1)
                data_hi = data_lo + sz
                data_raw = pe.get_section_data(osec)
                break
        if not data_lo:
            return 0

        def _blob_off(v: int) -> Optional[int]:
            v = int(v)
            if 0 <= v < len(out):
                return v
            if v >= text_new and (v - text_new) < len(out):
                return v - text_new
            return None

        def _string_exp(old_rva: int) -> Optional[int]:
            src_off = old_rva - text_rva
            if src_off < 0 or src_off + 4 > len(text_data):
                return None
            chunk = text_data[src_off:src_off + 4]
            # UTF-16 / ASCII-ish literals
            if chunk[1] != 0 and chunk[1] != chunk[3]:
                return None
            hit = None
            raw = rva_map.get(old_rva)
            base = _blob_off(int(raw)) if raw is not None else None
            if base is not None:
                for delta in range(-32, 96):
                    p = base + delta
                    if 0 <= p + 4 <= len(out) and bytes(out[p:p + 4]) == chunk:
                        hit = p
                        break
            if hit is None:
                for blob_start, blob_size in getattr(
                        self, '_orphan_blob_out_ranges', []):
                    lim = blob_start + max(blob_size - 3, 0)
                    for p in range(blob_start, lim):
                        if bytes(out[p:p + 4]) == chunk:
                            hit = p
                            break
                    if hit is not None:
                        break
            if hit is None:
                # Last resort: search whole translated blob for the chunk once.
                # Cap to avoid O(n*m) blowups — strings are rematerialized near
                # the end / orphan ranges already covered above.
                return None
            return (nb + text_new + hit) & 0xFFFFFFFFFFFFFFFF

        def _data_is_empty(va: int) -> bool:
            if not (data_lo <= va < data_hi):
                return False
            if data_raw is None:
                return True
            off = int(va - nb) - data_new
            if not (0 <= off + 4 <= len(data_raw)):
                return False
            return data_raw[off:off + 4] == b'\x00\x00\x00\x00'

        n = len(text_data)
        # Correct relocations of *other* abs data operands.  Only reclaim when
        # got equals one of these (stolen tip) — never rewrite an arbitrary
        # empty .data slot that may be a writable buffer (univ157 wrote into
        # rematerialized .text after a false-positive string-arg heal).
        foreign_ok: Set[int] = set()
        img_end = self.old_base + pe.image_size
        for _off in range(max(0, n - 5)):
            _b0 = text_data[_off]
            _imm: Optional[int] = None
            if _b0 == 0x68:
                _imm = struct.unpack_from('<I', text_data, _off + 1)[0]
            elif _b0 in (0xA0, 0xA1, 0xA2, 0xA3) and _off + 5 <= n:
                _imm = struct.unpack_from('<I', text_data, _off + 1)[0]
            elif (_off + 6 <= n and text_data[_off:_off + 2] == b'\x66\xa3'):
                _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
            elif (_off + 7 <= n and text_data[_off] == 0x66
                    and text_data[_off + 1] == 0x89
                    and (text_data[_off + 2] & 0xC7) == 0x05):
                _imm = struct.unpack_from('<I', text_data, _off + 3)[0]
            elif _b0 in (0x89, 0x8B) and _off + 6 <= n and (
                    text_data[_off + 1] & 0xC7) == 0x05:
                _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
            elif _b0 in (0xC6, 0xC7) and _off + 7 <= n and text_data[_off + 1] == 0x05:
                _imm = struct.unpack_from('<I', text_data, _off + 2)[0]
            elif 0xB8 <= _b0 <= 0xBF and _off + 5 <= n:
                _imm = struct.unpack_from('<I', text_data, _off + 1)[0]
            if _imm is None or not (self.old_base <= _imm < img_end):
                continue
            _or = _imm - self.old_base
            _sec = pe.section_for_rva(_or)
            if not _sec or (_sec['flags'] & 0x20000000):
                continue
            foreign_ok.add(
                self._relocate_imm(_imm, 0, 0) & 0xFFFFFFFFFFFFFFFF)

        def _is_abs_mem_consumer(scan: int) -> bool:
            after = scan + 10
            if after + 3 > len(out):
                return False
            if out[after:after + 3] in (
                    b'\x66\x41\x89', b'\x66\x41\x83', b'\x66\x41\x8b',
                    b'\x66\x41\x39', b'\x66\x41\x3b'):
                return True
            if out[after:after + 2] in (
                    b'\x66\x89', b'\x66\x8b', b'\x41\x89', b'\x41\x8b',
                    b'\x41\x83', b'\x41\x80', b'\x41\x39', b'\x41\x3b'):
                return True
            return False

        def _feeds_call_arg(scan: int) -> bool:
            # Only ``movabs rdx, …`` (opcode BA).  RCX is often the writable
            # dest / hKey (cmd ``push .data-buf; call wcscpy`` — univ157/158
            # rewrote rcx to a .text string and AV'd on write @ 0x476E8).
            # RegOpenKey subkey and RegQueryValueEx value names are rdx.
            if out[scan + 1] != 0xBA:
                return False
            for j in range(scan + 10, min(len(out) - 1, scan + 80)):
                if out[j] == 0xE8:
                    return True
                if out[j] == 0xFF and out[j + 1] in (
                        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
                        0x15):
                    return True
            return False

        fixed = 0
        for off in range(max(0, n - 5)):
            if text_data[off] != 0x68:
                continue
            imm = struct.unpack_from('<I', text_data, off + 1)[0]
            if not (self.old_base <= imm < self.old_base + pe.image_size):
                continue
            old_rva = imm - self.old_base
            sec = pe.section_for_rva(old_rva)
            if not sec or not (sec['flags'] & 0x20000000):
                continue
            exp = _string_exp(old_rva)
            if exp is None:
                continue
            call_x86 = None
            for k in range(off + 5, min(off + 28, n - 1)):
                b = text_data[k]
                if b == 0xE8 and k + 5 <= n:
                    call_x86 = k
                    break
                if b == 0xFF and k + 1 < n and text_data[k + 1] in (
                        0x15, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7):
                    call_x86 = k
                    break
            if call_x86 is None:
                continue
            anchors: List[int] = []
            for site in (call_x86, off, call_x86 - 1, call_x86 + 1):
                if site < 0:
                    continue
                raw = rva_map.get((text_rva + site) & 0xFFFFFFFF)
                if raw is None:
                    continue
                a = _blob_off(int(raw))
                if a is not None and a not in anchors:
                    anchors.append(a)
            if not anchors:
                continue
            for anchor in anchors:
                lo = max(0, anchor - 160)
                hi = min(len(out) - 10, anchor + 8)
                for scan in range(hi - 1, lo - 1, -1):
                    if out[scan] not in (0x48, 0x49, 0x4C, 0x4D):
                        continue
                    if not (0xB8 <= out[scan + 1] <= 0xBF):
                        continue
                    if _is_abs_mem_consumer(scan):
                        continue
                    if self._movabs_is_abs_load_pair(out, scan):
                        continue
                    if not _feeds_call_arg(scan):
                        continue
                    got = struct.unpack_from('<Q', out, scan + 2)[0]
                    if got == exp:
                        break
                    if got not in foreign_ok:
                        continue
                    if not _data_is_empty(got):
                        continue
                    struct.pack_into('<Q', out, scan + 2, exp)
                    fixed += 1
                    break
        if fixed:
            self._pure_insn_starts_cache = None
        return fixed

    def _pure_guard_ef42_init_return_as_pointer(self, out: bytearray) -> int:
        """Reject tiny EF42 return values used as pointers during CRT init.

        Win2000 cmd's locale init does::

            call EF42(flags, 0, 0)
            mov ebx, eax
            cmp ebx, 1 / -1 → retry
            else treat ebx as a string pointer (CmdGetEnv / path setup)

        When translation leaves switch parsing half-broken, EF42 may return a
        small integer (e.g. 2) that is neither 1 nor -1; using it as a pointer
        yields ``execute @ 2`` / ``read @ 0x3C``.  Require a plausible pointer.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 20:
            if out[i:i + 2] != b'\x89\xc3':  # mov ebx, eax
                i += 1
                continue
            if out[i + 2] != 0x89 or out[i + 3] != 0x5D:  # mov [rbp+d8], ebx
                i += 1
                continue
            if out[i + 5:i + 8] != b'\x83\xfb\x01':  # cmp ebx, 1
                i += 1
                continue
            je_at = i + 8
            # Accept short je (74) or near je (0f 84)
            if out[je_at] == 0x74:
                je_rel = out[je_at + 1]
                if je_rel > 127:
                    je_rel -= 256
                loop_tgt = je_at + 2 + je_rel
                cmp2 = je_at + 2
            elif out[je_at:je_at + 2] == b'\x0f\x84':
                je_rel = struct.unpack_from('<i', out, je_at + 2)[0]
                loop_tgt = je_at + 6 + je_rel
                cmp2 = je_at + 6
            else:
                i += 1
                continue
            if out[cmp2:cmp2 + 3] != b'\x83\xfb\xff':  # cmp ebx, -1
                i += 1
                continue
            jne_at = cmp2 + 3
            if out[jne_at] == 0x75:
                jne_rel = out[jne_at + 1]
                if jne_rel > 127:
                    jne_rel -= 256
                old_jne_tgt = jne_at + 2 + jne_rel
                jne_is_short = True
            elif out[jne_at:jne_at + 2] == b'\x0f\x85':
                jne_rel = struct.unpack_from('<i', out, jne_at + 2)[0]
                old_jne_tgt = jne_at + 6 + jne_rel
                jne_is_short = False
            else:
                i += 1
                continue

            # ``jae`` must jump *directly* to the original use-pointer arm.
            # A trampoline at the end of this stub was getting overwritten by
            # later pad-seeking heals (frameless dual-local epi), turning a
            # valid pointer into ``pop; ret`` → execute@0x70.
            stub = bytearray()
            stub += b'\x81\xfb\x00\x00\x01\x00'  # cmp ebx, 0x10000
            jae_at = len(stub)
            stub += b'\x0f\x83\x00\x00\x00\x00'  # jae → old_jne_tgt
            # Tiny return: force ebx=-1 and take the fall-through of the
            # original ``cmp ebx,-1 / jne use_ptr`` (soft failure), NOT the
            # use-as-pointer arm (that AVs / recurses on -1 or a fake node).
            stub += b'\xbb\xff\xff\xff\xff'        # mov ebx, -1
            stub += b'\x89\x5d\xa8'                # mov [rbp-0x58], ebx
            jmp_fail_at = len(stub)
            stub += b'\xe9\x00\x00\x00\x00'         # jmp fallthrough

            need = len(stub) + 8
            pad_at = len(out)
            out.extend(b'\x00' * need)

            fallthrough = jne_at + (2 if jne_is_short else 6)
            struct.pack_into(
                '<i', stub, jae_at + 2,
                old_jne_tgt - (pad_at + jae_at + 6))
            struct.pack_into(
                '<i', stub, jmp_fail_at + 1,
                fallthrough - (pad_at + jmp_fail_at + 5))
            out[pad_at:pad_at + len(stub)] = stub
            if jne_is_short:
                rel8 = pad_at - (jne_at + 2)
                if -128 <= rel8 <= 127:
                    out[jne_at + 1] = rel8 & 0xFF
                    fixed += 1
            else:
                struct.pack_into('<i', out, jne_at + 2,
                                 pad_at - (jne_at + 6))
                fixed += 1
            i = fallthrough
        return fixed

    def _pure_fix_formatmessage_arg_homes(self, out: bytearray) -> int:
        """Fix ``FormatMessage`` stack homes that copy nSize into Arguments.

        CmdPutMsg loads ``FormatMessageW`` into RBX then emits::

            mov rax, 0x1770
            mov [rsp+0x28], rax   ; nSize
            mov [rsp+0x30], rax   ; Arguments ← BUG (should be 0 / va_list)
            call rbx

        Win64 then treats 0x1770 as an argument pointer (AV / execute@garbage).
        Same-size rewrite: keep nSize, zero Arguments.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # 48 c7 c0 70 17 00 00 | 48 89 44 24 28 | 48 89 44 24 30 | ff d3
        pat = bytes.fromhex('48c7c07017000048894424284889442430ffd3')
        repl = bytes.fromhex('b870170000488944242831c04889442430ffd3')
        # mov eax,0x1770; mov [rsp+0x28],rax; xor eax,eax; mov [rsp+0x30],rax; call rbx
        assert len(pat) == len(repl)
        i = 0
        while True:
            at = out.find(pat, i)
            if at < 0:
                break
            out[at:at + len(repl)] = repl
            fixed += 1
            i = at + len(repl)
        return fixed

    def _pure_fix_formatmessage_insert_string_vas(self, out: bytearray) -> int:
        """Force CmdPutMsg insert-string movabs onto real UTF-16 sites.

        ``shifted-data`` / ``text-constant`` passes sometimes rewrite the
        Application tip onto an empty ``.data`` cell (cmd ``0x5e860``), which
        makes the version banner recurse into itself.  Also rewrites the
        classic ``nb+0x1B78`` / ``0x1B68`` / ``0x1B58`` tips.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(self.new_base or 0)
        pe_text_rva = int(getattr(self, 'text_rva', 0) or 0x1000)
        app_needle = b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00'
        sys_needle = b'S\x00y\x00s\x00t\x00e\x00m\x00\x00\x00'
        app_idx = bytes(out).find(app_needle)
        if app_idx < 0:
            return 0
        app_va = nb + pe_text_rva + app_idx
        sys_idx = bytes(out).rfind(sys_needle, max(0, app_idx - 0x40), app_idx)
        if sys_idx < 0:
            sys_idx = bytes(out).find(sys_needle)
        sys_va = (nb + pe_text_rva + sys_idx) if sys_idx >= 0 else 0
        fixed = 0
        # Pattern: cmp eax, 0x2328; movabs rax, X; jae; movabs rax, Y
        pat = b'\x3d\x28\x23\x00\x00\x48\xb8'
        k = 0
        while True:
            at = out.find(pat, k)
            if at < 0:
                break
            tip1 = at + 5
            if tip1 + 18 > len(out):
                break
            if out[tip1:tip1 + 2] != b'\x48\xb8':
                k = at + 1
                continue
            # jae rel8 or near
            after1 = tip1 + 10
            if out[after1] == 0x73 and out[after1 + 2:after1 + 4] == b'\x48\xb8':
                tip2 = after1 + 2
            elif out[after1:after1 + 2] == b'\x0f\x83' and out[after1 + 6:after1 + 8] == b'\x48\xb8':
                tip2 = after1 + 6
            else:
                k = at + 1
                continue
            old1 = struct.unpack_from('<Q', out, tip1 + 2)[0]
            if old1 != app_va:
                out[tip1 + 2:tip1 + 10] = struct.pack('<Q', app_va)
                fixed += 1
            if sys_va:
                old2 = struct.unpack_from('<Q', out, tip2 + 2)[0]
                if old2 != sys_va:
                    out[tip2 + 2:tip2 + 10] = struct.pack('<Q', sys_va)
                    fixed += 1
            k = tip2 + 10
        # Also rewrite classic bad tips.
        for good, bad_offs in (
                (app_va, (0x1B78,)),
                (sys_va, (0x1B68, 0x1B58)),
        ):
            if not good:
                continue
            tip_g = struct.pack('<Q', good)
            for bad_off in bad_offs:
                tip_b = struct.pack('<Q', nb + bad_off)
                if tip_b == tip_g:
                    continue
                s = 0
                while True:
                    at = out.find(tip_b, s)
                    if at < 0:
                        break
                    if at >= 2 and out[at - 2:at] in (b'\x48\xb8', b'\x48\xbb'):
                        out[at:at + 8] = tip_g
                        fixed += 1
                    s = at + 1
        return fixed

    def _pure_fix_formatmessage_x86_fallback(self, out: bytearray) -> int:
        """Repair CmdPutMsg FormatMessage fallback that still uses x86 pushes.

        Win2000 `CmdPutMsg` ends one path with::

            lea eax, [ebp-0x14]   ; Argument array {&local, L"Application"}
            push 0x1770 / edi / 0 / 0x13d / 0 / 0x3000
            jmp shared_call_FormatMessage

        After translation the shared tail is Microsoft x64 (rcx/rdx/r8/r9 +
        stack homes) but the fallback still *pushes* then `jmp` mid-tail,
        leaving garbage in the arg regs.  Insert-string immediates are also
        often `new_base+old_rva` instead of the stretched UTF-16 site.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(self.new_base or 0)
        rva_map = getattr(self, 'rva_map', None) or {}
        pe_text_rva = int(getattr(self, 'text_rva', 0) or 0x1000)

        def _va_for_old_rva(old_rva: int, needle: bytes,
                              prefer_before: int = -1) -> int:
            # Search the PE64 text blob first — the x86 .text offset equals
            # old_rva and would produce nb+old_rva (the broken tip).
            if needle:
                if prefer_before > 0:
                    idx = bytes(out).rfind(
                        needle, max(0, prefer_before - 0x40), prefer_before)
                    if idx >= 0:
                        return nb + pe_text_rva + idx
                idx = bytes(out).find(needle)
                if idx >= 0 and prefer_before < 0:
                    return nb + pe_text_rva + idx
                # Multiple hits: prefer the one near rva_map / Application.
                if idx >= 0 and old_rva in rva_map:
                    mapped_off = int(rva_map[old_rva]) - pe_text_rva
                    best = idx
                    best_dist = abs(idx - mapped_off)
                    start = idx + 1
                    while True:
                        j = bytes(out).find(needle, start)
                        if j < 0:
                            break
                        dist = abs(j - mapped_off)
                        if dist < best_dist:
                            best, best_dist = j, dist
                        start = j + 1
                    return nb + pe_text_rva + best
                if idx >= 0:
                    return nb + pe_text_rva + idx
            if old_rva in rva_map:
                mapped = nb + int(rva_map[old_rva])
                if needle:
                    off = int(rva_map[old_rva]) - pe_text_rva
                    if 0 <= off < len(out):
                        hit = bytes(out).find(needle, max(0, off - 0x20),
                                              min(len(out), off + 0x40))
                        if hit >= 0:
                            return nb + pe_text_rva + hit
                return mapped
            return nb + old_rva

        app_needle = b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00'
        sys_needle = b'S\x00y\x00s\x00t\x00e\x00m\x00\x00\x00'
        app_va = _va_for_old_rva(0x1B78, app_needle)
        app_off = (app_va - nb - pe_text_rva) if app_va else -1
        sys_va = _va_for_old_rva(0x1B68, sys_needle, prefer_before=app_off)

        fixed = 0
        for bad, good in (
                (nb + 0x1B78, app_va),
                (nb + 0x1B68, sys_va),
                (nb + 0x1B58, sys_va),
        ):
            needle_imm = struct.pack('<I', bad & 0xFFFFFFFF)
            repl_imm = struct.pack('<I', good & 0xFFFFFFFF)
            if needle_imm == repl_imm:
                continue
            start = 0
            while True:
                at = out.find(needle_imm, start)
                if at < 0:
                    break
                if at >= 3 and out[at - 3:at] in (
                        b'\xc7\x45\xf0',
                        b'\xc7\x45\xec',
                        b'\xc7\x45\xf4',
                ):
                    out[at:at + 4] = repl_imm
                    fixed += 1
                start = at + 1

        i = 0
        while i < len(out) - 40:
            if out[i:i + 4] != b'\x48\x8d\x45\xec':
                i += 1
                continue
            p = i + 4
            if p + 23 > len(out):
                break
            if not (out[p:p + 5] == b'\x68\x70\x17\x00\x00'
                    and out[p + 5] == 0x57
                    and out[p + 6] == 0x56
                    and out[p + 7:p + 12] == b'\x68\x3d\x01\x00\x00'
                    and out[p + 12] == 0x56
                    and out[p + 13:p + 18] == b'\x68\x00\x30\x00\x00'
                    and out[p + 18] == 0xE9):
                i += 1
                continue
            jmp_at = p + 18
            rel = struct.unpack_from('<i', out, jmp_at + 1)[0]
            targ = jmp_at + 5 + rel
            if out[targ:targ + 5] != b'\x41\x55\x49\x89\xe5':
                i = p
                continue

            tramp = bytearray()
            # Build FORMAT_MESSAGE_ARGUMENT_ARRAY as two qwords.
            tramp += b'\x48\x8d\x45\x8c'                      # lea rax, [rbp-0x74]
            tramp += b'\x48\x89\x45\xec'                      # mov [rbp-0x14], rax
            tramp += b'\x8b\x45\x10'                          # mov eax, [rbp+0x10]
            tramp += b'\x3d\x28\x23\x00\x00'                  # cmp eax, 0x2328
            tramp += b'\x48\xb8' + struct.pack('<Q', app_va)  # movabs rax, Application
            j_ae = len(tramp)
            tramp += b'\x73\x00'                              # jae keep_app
            tramp += b'\x48\xb8' + struct.pack('<Q', sys_va)  # movabs rax, System
            tramp[j_ae + 1] = (len(tramp) - (j_ae + 2)) & 0xFF
            tramp += b'\x48\x89\x45\xf4'                      # mov [rbp-0x0c], rax
            tramp += b'\x48\x8d\x45\xec'                      # lea rax, [rbp-0x14]
            tramp += b'\x48\x89\x45\x28'                      # mov [rbp+0x28], rax
            tramp += b'\xb9\x00\x30\x00\x00'                  # mov ecx, 0x3000
            tramp += b'\x31\xd2'                              # xor edx, edx
            tramp += b'\x41\xb8\x3d\x01\x00\x00'              # mov r8d, 0x13d
            tramp += b'\x45\x31\xc9'                          # xor r9d, r9d
            tramp += b'\xe9\x00\x00\x00\x00'                  # jmp align_tail
            jmp_off = len(tramp) - 5

            need = len(tramp) + 8
            pad_at = None
            run = 0
            run_start = 0
            for q in range(len(out) - 1, max(0, len(out) - 0x8000), -1):
                if out[q] in (0x00, 0x90, 0xCC):
                    run += 1
                    run_start = q
                    if run >= need:
                        pad_at = run_start
                        break
                else:
                    run = 0
            if pad_at is None:
                pad_at = len(out)
                out.extend(b'\x00' * need)
            struct.pack_into('<i', tramp, jmp_off + 1,
                             targ - (pad_at + jmp_off + 5))
            out[pad_at:pad_at + len(tramp)] = tramp
            cover = (jmp_at + 5) - i
            patch = b'\xe9' + struct.pack('<i', pad_at - (i + 5))
            patch += b'\x90' * (cover - 5)
            out[i:i + cover] = patch
            fixed += 1
            i = jmp_at + 5
        return fixed

    def _pure_redirect_interactive_ef42_for_slash_c(self, out: bytearray) -> int:
        """When main reaches interactive EF42 with (flags,0,0), honor ``/c``.

        Switch parsing can still miss ``/c`` and call EF42 as interactive
        (rdx=0, r8=0) → More?.  If the PEB cmdline contains ``/c``, re-invoke
        EF42 like the batch path: flags=1, rdx=argument text, r8=0.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        i = 0
        while i < len(out) - 40:
            if out[i:i + 7] != b'\x48\xc7\xc2\x00\x00\x00\x00':
                i += 1
                continue
            if out[i + 7:i + 14] != b'\x49\xc7\xc0\x00\x00\x00\x00':
                i += 1
                continue
            # Require ``mov rcx, rdi`` just before the zeroing (interactive
            # C71E shape) so we don't hijack unrelated (0,0) call sites.
            if i < 3 or out[i - 3:i] != b'\x48\x89\xf9':
                i += 1
                continue
            call_at = None
            for j in range(i + 14, min(i + 40, len(out) - 5)):
                if out[j] == 0xE8:
                    call_at = j
                    break
            if call_at is None:
                i += 1
                continue
            ef42_rel = struct.unpack_from('<i', out, call_at + 1)[0]
            ef42_off = call_at + 5 + ef42_rel

            stub = bytearray()
            # Only hijack interactive-style calls (flags in rcx are a small
            # integer).  The same (rdx=0,r8=0) shape is reused during CRT/locale
            # init with rcx holding a pointer — forcing EF42(1,/c-arg) there
            # runs the batch path mid-init and corrupts ebx / the stack.
            stub += b'\x48\x81\xf9\x00\x00\x01\x00'  # cmp rcx, 0x10000
            j_ptr = len(stub); stub += b'\x73\x00'    # jae → original EF42
            # Scan image cmdline at [c8d8] (filled by entry materializer).
            nb = int(self.new_base or 0)
            c8d8 = nb + 0x6A8D8
            stub += b'\x48\xb8' + struct.pack('<Q', c8d8)
            stub += b'\x8b\x10'                          # edx = dword [c8d8]
            stub += b'\x85\xd2'
            jz_no = len(stub); stub += b'\x74\x00'
            loop = len(stub)
            stub += b'\x66\x83\x3a\x00'
            je_no = len(stub); stub += b'\x74\x00'
            stub += b'\x66\x83\x3a\x2f'
            jne_n = len(stub); stub += b'\x75\x00'
            stub += b'\x66\x83\x7a\x02\x63'
            je_f = len(stub); stub += b'\x74\x00'
            stub += b'\x66\x83\x7a\x02\x43'
            jne_n2 = len(stub); stub += b'\x75\x00'
            found = len(stub)
            stub += b'\x48\x83\xc2\x04'
            stub += b'\x66\x83\x3a\x20'
            stub += b'\x75\x04'
            stub += b'\x48\x83\xc2\x02'
            stub += b'\xb9\x01\x00\x00\x00'   # rcx = 1
            stub += b'\x4d\x31\xc0'           # r8 = 0
            # Tail-call EF42: the C71E site already opened the align
            # wrapper + 0x20 shadow; a nested ``call`` would smash it.
            jmp_c = len(stub)
            stub += b'\xe9\x00\x00\x00\x00'
            nextp = len(stub)
            stub += b'\x48\x83\xc2\x02'
            jmp_l = len(stub); stub += b'\xeb\x00'
            no_c = len(stub)
            stub += b'\x48\x31\xd2'           # rdx = 0
            stub += b'\x4d\x31\xc0'           # r8 = 0
            jmp_o = len(stub)
            stub += b'\xe9\x00\x00\x00\x00'

            def _pr8(imm_at: int, tgt: int) -> None:
                stub[imm_at] = (tgt - (imm_at + 1)) & 0xFF

            _pr8(j_ptr + 1, no_c)  # pointer-sized rcx → original interactive
            _pr8(jz_no + 1, no_c)
            _pr8(je_no + 1, no_c)
            _pr8(jne_n + 1, nextp)
            _pr8(je_f + 1, found)
            _pr8(jne_n2 + 1, nextp)
            _pr8(jmp_l + 1, loop)

            need = len(stub) + 8
            pad_at = None
            run = 0
            run_start = 0
            for p in range(len(out) - 1, max(0, len(out) - 0x8000), -1):
                if out[p] in (0x00, 0x90, 0xCC):
                    run += 1
                    run_start = p
                    if run >= need:
                        pad_at = run_start
                        break
                else:
                    run = 0
            if pad_at is None:
                pad_at = len(out)
                out.extend(b'\x00' * need)

            struct.pack_into('<i', stub, jmp_c + 1,
                             ef42_off - (pad_at + jmp_c + 5))
            struct.pack_into('<i', stub, jmp_o + 1,
                             ef42_off - (pad_at + jmp_o + 5))
            out[pad_at:pad_at + len(stub)] = stub
            out[call_at:call_at + 5] = (
                b'\xe8' + struct.pack('<i', pad_at - (call_at + 5)))
            fixed += 1
            i = call_at + 5
        return fixed

    def _pure_materialize_peb_cmdline_at_entry(self, out: bytearray) -> int:
        """Copy PEB CommandLine into the image buffer pointed at by ``c8d8``.

        Win2000 cmd keeps a packed DWORD cmdline pointer at ``.data+0x8d8``.
        On the translated image that slot still points at a BSS buffer, but the
        GetCommandLineW fill path is often lost in translation — leaving an
        empty string.  Switch parsing then misses ``/c`` and falls into the
        interactive ``More?`` loop.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(self.new_base or 0)
        # Resolve packed cmdline slot + BSS buffer from live layout.
        # Never hardcode 0x6A8D8 — .data RVA shifts when .text vsize changes.
        c8d8 = 0
        buf = 0
        pe = getattr(self, 'pe', None)
        old_data_rva = 0
        if pe is not None:
            for sec in getattr(pe, 'sections', []) or []:
                nm = getattr(sec, 'name', b'')
                if isinstance(nm, str):
                    nm = nm.encode()
                nm = nm.split(b'\0')[0].lower()
                if nm == b'.data':
                    old_data_rva = int(getattr(sec, 'vaddr', 0)
                                       or getattr(sec, 'virtual_address', 0)
                                       or getattr(sec, 'rva', 0) or 0)
                    break
        if old_data_rva and hasattr(self, '_relocate_imm') and self.old_base:
            # Classic SP4 cmd: DWORD slot at .data+0x8D8, buffer at +0x8320.
            c8d8 = self._relocate_imm(self.old_base + old_data_rva + 0x8D8) & ((1 << 64) - 1)
            buf = self._relocate_imm(self.old_base + old_data_rva + 0x8320) & ((1 << 64) - 1)
        # Prefer VAs already present in translated movabs (authoritative).
        if c8d8:
            hit = False
            for k in range(len(out) - 10):
                if out[k:k + 2] in (b'\x49\xbb', b'\x48\xb8'):
                    if struct.unpack_from('<Q', out, k + 2)[0] == c8d8:
                        hit = True
                        break
            if not hit:
                # Fall back: densest .data VA matching *8d8 low bits
                for k in range(len(out) - 10):
                    if out[k:k + 2] in (b'\x49\xbb', b'\x48\xb8'):
                        v = struct.unpack_from('<Q', out, k + 2)[0]
                        if (v & 0xFFF) == 0x8D8 and nb < v < nb + 0x200000:
                            c8d8 = v
                            hit = True
                            break
        if not buf and c8d8:
            # Buffer commonly ~0x8320 past the .data base (= c8d8 - 0x8D8).
            data_base = c8d8 - 0x8D8
            cand = data_base + 0x8320
            for k in range(len(out) - 10):
                if out[k:k + 2] in (b'\x49\xbb', b'\x48\xb8'):
                    if struct.unpack_from('<Q', out, k + 2)[0] == cand:
                        buf = cand
                        break
            if not buf:
                buf = cand
        if not c8d8 or not buf:
            return 0
        # Confirm entry shape: and rsp,-16; jmp rel32
        # range must include i == len(out)-9 (stub flush with EOF — no
        # trailing file-alignment zeros yet during the post-append heal).
        entry_candidates = []
        for i in range(max(0, len(out) - 8)):
            if (out[i:i + 4] == b'\x48\x83\xe4\xf0'
                    and out[i + 4] == 0xE9
                    and all(b in (0x00, 0x90) for b in out[i + 9:i + 16])):
                entry_candidates.append(i)
        if not entry_candidates:
            return 0
        # Prefer the latest (PE often places entry stub at end of .text)
        entry = entry_candidates[-1]
        orig_rel = struct.unpack_from('<i', out, entry + 5)[0]
        orig_target = entry + 9 + orig_rel

        helper = bytearray()
        helper += b'\x50\x51\x52\x41\x50\x41\x51\x41\x52'  # push rax,rcx,rdx,r8,r9,r10
        helper += b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00'  # rax = PEB
        helper += b'\x48\x8b\x40\x20'                      # ProcessParameters
        helper += b'\x48\x8b\x50\x78'                      # rdx = CommandLine.Buffer
        helper += b'\x48\x85\xd2'
        jz_pos = len(helper)
        helper += b'\x74\x00'  # → restore
        helper += b'\x49\xb8' + struct.pack('<Q', buf)     # r8 = dest
        helper += b'\x49\xb9' + struct.pack('<Q', c8d8)    # r9 = &c8d8
        helper += b'\x45\x89\x01'                          # mov dword [r9], r8d
        helper += b'\xb9\x00\x08\x00\x00'                  # ecx = 0x800 wchars
        copy_pos = len(helper)
        helper += b'\x66\x8b\x02'                          # ax = [rdx]
        helper += b'\x66\x41\x89\x00'                      # [r8] = ax
        helper += b'\x48\x83\xc2\x02'
        helper += b'\x49\x83\xc0\x02'
        helper += b'\x66\x85\xc0'
        jz2_pos = len(helper)
        helper += b'\x74\x00'  # → restore
        helper += b'\xff\xc9'  # dec ecx
        jne_pos = len(helper)
        helper += b'\x75\x00'  # → copy
        helper += b'\x66\x41\xc7\x00\x00\x00'  # force NUL
        restore_pos = len(helper)
        helper += b'\x41\x5a\x41\x59\x41\x58\x5a\x59\x58'  # pops
        helper += b'\xc3'

        def _prel8(at: int, tgt: int) -> None:
            helper[at] = (tgt - (at + 1)) & 0xFF

        _prel8(jz_pos + 1, restore_pos)
        _prel8(jz2_pos + 1, restore_pos)
        _prel8(jne_pos + 1, copy_pos)

        need = len(helper) + 4
        stub_len = 14  # and rsp,-16; call rel32; jmp rel32
        # Grow the 9-byte align stub site to 14 bytes *before* placing the
        # helper so an EOF append does not land helper at entry+9 and then
        # get clobbered by the expanded stub write.
        if entry + stub_len > len(out):
            out.extend(b'\x00' * (entry + stub_len - len(out)))
        # Place helper in trailing pad / extend — never overlap [entry, entry+14).
        pad_at = None
        # Avoid colliding with the B186 /c seed helper (uses 0x78 too but
        # different register pattern).  Prefer fresh pad.
        run = 0
        run_start = 0
        for p in range(len(out) - 1, max(0, len(out) - 0x8000), -1):
            if out[p] in (0x00, 0x90, 0xCC):
                run += 1
                run_start = p
                if run >= need and run_start >= entry + stub_len:
                    pad_at = run_start
                    break
            else:
                run = 0
        if pad_at is None:
            for p in range(0, len(out) - need + 1):
                if all(out[p + k] in (0x00, 0x90, 0xCC) for k in range(need)):
                    if p < entry + stub_len and p + need > entry:
                        continue
                    pad_at = p
                    break
        if pad_at is None:
            pad_at = len(out)
            out.extend(b'\x00' * need)
        out[pad_at:pad_at + len(helper)] = helper

        # Rewrite entry: and rsp,-16; call helper; jmp orig
        call_rel = pad_at - (entry + 4 + 5)
        jmp_rel = orig_target - (entry + stub_len)
        stub = (
            b'\x48\x83\xe4\xf0'                      # and rsp,-16
            + b'\xe8' + struct.pack('<i', call_rel)  # call helper
            + b'\xe9' + struct.pack('<i', jmp_rel)   # jmp orig
        )
        out[entry:entry + stub_len] = stub
        return 1

    def _pure_seed_stream_cursor_from_parse_buffer(self, out: bytearray) -> int:
        """When the parse cursor is empty, refill from cmdline past ``/c``.

        Earlier AE2A ``mov [fbc8],esi`` always reset the cursor to the full
        GetCommandLine buffer, so add9 tokenized the EXE path (fae0=0x4000)
        instead of the ``/c`` argument.  Native ADAD leaves fbc8 on an empty
        scratch and B186 refills via B21C; when that path is unavailable,
        point an empty cursor at the text after ``/c`` / ``/C``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # Revert any prior always-seed at AE2A (mov [r11],esi → load/save).
        i = 0
        while i < len(out) - 40:
            if out[i:i + 4] != b'\xf6\x45\x18\x21':
                i += 1
                continue
            back = out[max(0, i - 40):i]
            load_at: Optional[int] = None
            for j in range(len(back) - 12):
                if back[j:j + 2] == b'\x49\xbb' and back[j + 10:j + 13] == b'\x41\x89\x33':
                    load_at = max(0, i - 40) + j + 10
                    break
            if load_at is not None:
                out[load_at:load_at + 3] = b'\x41\x8b\x03'
                fixed += 1
            fwd = out[i:i + 30]
            for j in range(len(fwd) - 12):
                if fwd[j:j + 2] == b'\x49\xbb' and fwd[j + 10:j + 13] == b'\x41\x89\x33':
                    sa = i + j + 10
                    if sa != load_at:
                        out[sa:sa + 3] = b'\x41\x89\x03'
                        fixed += 1
                    break
            i += 4

        # B186: cmp word [rcx],0 / jne … / <align call B21C> / reload fbc8
        nb = int(self.new_base or 0)

        def _data_va(offset: int) -> int:
            """Image VA of ``.data + offset`` via relocate (survives .text growth)."""
            pe = getattr(self, 'pe', None)
            old_data_rva = 0
            if pe is not None:
                for sec in getattr(pe, 'sections', []) or []:
                    nm = getattr(sec, 'name', b'')
                    if isinstance(nm, str):
                        nm = nm.encode()
                    nm = nm.split(b'\0')[0].lower()
                    if nm == b'.data':
                        old_data_rva = int(getattr(sec, 'vaddr', 0)
                                           or getattr(sec, 'virtual_address', 0)
                                           or getattr(sec, 'rva', 0) or 0)
                        break
            if old_data_rva and hasattr(self, '_relocate_imm') and self.old_base:
                return self._relocate_imm(
                    self.old_base + old_data_rva + offset) & ((1 << 64) - 1)
            return nb + 0x58000 + offset  # pe64 .data default after 0x57000 .text

        def _find_data_va(hint: int) -> int:
            tip = struct.pack('<Q', hint)
            if tip in out:
                return hint
            # Prefer a *writable* .data hit (reject .rsrc / stale +0x10000 tips).
            data_lo = nb + 0x58000
            data_hi = nb + 0x66000
            for k in range(len(out) - 10):
                if out[k:k + 2] in (b'\x49\xbb', b'\x48\xb8'):
                    v = struct.unpack_from('<Q', out, k + 2)[0]
                    if ((v & 0xFFFF) == (hint & 0xFFFF)
                            and data_lo <= v < data_hi):
                        return v
            return hint

        # SP4 cmd (.data at RVA 0x1C000): cursor DWORD at +0x3BC8 (VA 0x1FBC8),
        # /c-arg scratch at +0x3BE2 (VA 0x1FBE2), cmdline slot at +0x8D8.
        # Do NOT use pe64 absolute low-bits (0x5BC8/0x5BE2) as .data offsets —
        # that wrongly resolves to 0x5DBC8/0x5DBE2 while getchar reads 0x5BBC8.
        c8d8 = _find_data_va(_data_va(0x8D8))
        fbc8 = _find_data_va(_data_va(0x3BC8))
        fbe2 = _find_data_va(_data_va(0x3BE2))

        # Helper: PEB CommandLine UNICODE_STRING → find /c → copy arg into
        # fbe2 → set fbc8.  Bound the scan by UNICODE_STRING.Length — walking
        # until a heap NUL hangs forever under a debugger (Buffer often has
        # non-zero bytes past Length).
        #
        # Re-entry:
        #   - Sticky DWORD at .data+0x3E00. Values: 0=never seeded, 1=PEB
        #     copy done (fbe2 holds ``/c`` arg + CR/LF), 2=stream exhausted,
        #     3=EOF LF already delivered. Set to 1 on store after appending
        #     CR+LF into fbe2. Exhaust with sticky==1 → sticky=2 and wipe
        #     fbe2 (stop ADAD residual re-parse). getchar gate: sticky>=2
        #     delivers one LF (whitespace skip needs LF; isw(0) is nonzero
        #     on this CRT) then sticky=3 and returns 0. Do NOT finalize on
        #     ADAD-empty alone — that raced execute. Discard fbe0 unget when
        #     sticky==1 so the parser cannot bounce forever without empty.
        #     Mirror /c arg into the [c8d8] buffer (keep slot).
        #   - When fbe2 still holds text and fbc8 sits on an in-place token NUL,
        #     skip NULs within fbe2..fbe2+0x40 (tight window).
        #
        # Use ``je try / ret`` style so rel8 stays in range.
        seed_done = _find_data_va(_data_va(0x3E00))
        cmd_buf = _find_data_va(_data_va(0x8320))
        helper = bytearray()
        helper += b'\x49\xbb' + struct.pack('<Q', fbe2)    # r11 = fbe2
        helper += b'\x66\x41\x83\x3b\x00'                  # cmp word [r11], 0
        je_empty_fbe2_pos = len(helper)
        helper += b'\x0f\x84\x00\x00\x00\x00'  # near je → empty_fbe2
        # fbe2[0] has text: skip in-place NULs under fbc8 within window.
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x8b\x0b'                          # mov ecx, [fbc8]
        helper += b'\x49\xbb' + struct.pack('<Q', fbe2)
        helper += b'\x4c\x39\xd9'                          # cmp rcx, r11
        jb_eof_pos = len(helper)
        helper += b'\x72\x00'  # rcx < fbe2 → hard EOF
        helper += b'\x4d\x8d\x53\x40'                      # lea r10, [r11+0x40]
        helper += b'\x4c\x39\xd1'                          # cmp rcx, r10
        jae_eof_pos = len(helper)
        helper += b'\x73\x00'  # rcx >= end → hard EOF
        skip_nul_pos = len(helper)
        helper += b'\x66\x83\x39\x00'                      # cmp word [rcx], 0
        jne_have_pos = len(helper)
        helper += b'\x75\x00'  # → publish cursor
        helper += b'\x48\x83\xc1\x02'                      # add rcx, 2
        helper += b'\x4c\x39\xd1'                          # cmp rcx, r10
        jb_skip_pos = len(helper)
        helper += b'\x72\x00'  # → skip_nul
        # Exhaust: sticky 0→PEB, 1→sticky2+wipe, >=2→hard EOF.
        exhaust_pos = len(helper)
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done)
        helper += b'\x41\x83\x3b\x01'                      # cmp dword [r11], 1
        jb_peb_pos = len(helper)
        helper += b'\x0f\x82\x00\x00\x00\x00'  # near jb → PEB seed
        jne_hard_pos = len(helper)
        helper += b'\x75\x00'  # sticky>1 → hard EOF
        helper += b'\x41\xc7\x03\x02\x00\x00\x00'          # sticky = 2
        # Wipe fbe2 + unget (fbe0) and park fbc8 on wiped fbe2 so the
        # parser cannot bounce through a stale unget wchar forever.
        helper += b'\x48\xbf' + struct.pack('<Q', fbe2 - 2)  # movabs rdi, fbe0
        helper += b'\x31\xc0'                              # xor eax, eax
        helper += b'\xb9\x21\x00\x00\x00'                  # mov ecx, 0x21 dwords
        helper += b'\xf3\xab'                              # rep stosd
        helper += b'\xb8' + struct.pack('<I', fbe2 & 0xFFFFFFFF)
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x89\x03'                          # mov [fbc8], eax
        helper += b'\xc3'
        eof_ret_pos = len(helper)
        helper += b'\xc3'
        have_pos = len(helper)
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x89\x0b'                          # mov [fbc8], ecx
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done + 4)
        helper += b'\x41\x89\x0b'                          # shadow = ecx
        helper += b'\xc3'
        empty_fbe2_pos = len(helper)
        # fbe2 empty: sticky==0 → PEB seed. sticky>=1 → resume/skip in the
        # cmdline buffer (ADAD parks cursor on fbe2 after unget clear — do
        # not residual-skip fbe2 ``cho…`` leftovers from older seeds).
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done)
        helper += b'\x41\x83\x3b\x01'                      # cmp dword [r11], 1
        jb_peb_empty_pos = len(helper)
        helper += b'\x0f\x82\x00\x00\x00\x00'  # near jb → PEB seed
        helper += b'\x41\x83\x3b\x02'                      # cmp dword [r11], 2
        jae_eof2_pos = len(helper)
        helper += b'\x73\x00'  # → eof_ret
        # sticky==1: if cursor below stream (ADAD parked on fbe0/fbe2), snap
        # back to shadow/stream — do NOT finalize (that SO'd mid-parse).
        # In window on NUL → finalize. In window on char → publish.
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x8b\x0b'                          # mov ecx, [fbc8]
        helper += b'\x49\xbb' + struct.pack('<Q', fbe2 + 2)
        helper += b'\x4c\x39\xd9'                          # cmp rcx, r11 (stream)
        jb_resume_pos = len(helper)
        helper += b'\x72\x00'  # → resume_stream
        helper += b'\x4d\x8d\x53\x3e'                      # lea r10, [r11+0x3e]
        helper += b'\x4c\x39\xd1'
        jae_fin_pos = len(helper)
        helper += b'\x73\x00'  # → finalize
        helper += b'\x66\x83\x39\x00'
        jne_cmd_have_pos = len(helper)
        helper += b'\x75\x00'  # → have_pos
        # NUL in window → finalize
        jmp_fin = len(helper)
        helper += b'\xeb\x00'
        resume_pos = len(helper)
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done + 4)  # shadow
        helper += b'\x41\x8b\x0b'
        helper += b'\x48\x85\xc9'
        jnz_have2 = len(helper)
        helper += b'\x75\x00'  # → have_pos
        helper += b'\x4c\x89\xd9'                          # ecx = stream base
        helper += b'\x66\x83\x39\x00'
        jne_have3 = len(helper)
        helper += b'\x75\x00'
        finalize_pos = len(helper)
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done)
        helper += b'\x41\xc7\x03\x02\x00\x00\x00'          # sticky = 2
        helper += b'\x49\xbb' + struct.pack('<Q', fbe2 - 2)
        helper += b'\x66\x41\xc7\x03\x00\x00'
        helper += b'\x49\xbb' + struct.pack('<Q', fbe2)
        helper += b'\x66\x41\xc7\x03\x00\x00'
        helper += b'\xb8' + struct.pack('<I', fbe2 & 0xFFFFFFFF)
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x89\x03'
        helper += b'\xc3'
        seed_body_pos = len(helper)
        helper += b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00'  # mov rax, gs:[0x60]
        helper += b'\x48\x8b\x40\x20'                      # mov rax, [rax+0x20] PP
        helper += b'\x4c\x0f\xb7\x50\x70'                  # movzx r10, word [rax+0x70]
        helper += b'\x48\x8b\x50\x78'                      # mov rdx, [rax+0x78]
        helper += b'\x48\x85\xd2'
        jz_pos = len(helper)
        helper += b'\x0f\x84\x00\x00\x00\x00'  # near je → empty
        helper += b'\x4e\x8d\x14\x12'                      # lea r10, [rdx+r10]
        loop_pos = len(helper)
        helper += b'\x4c\x39\xd2'                          # cmp rdx, r10
        jae_empty_pos = len(helper)
        helper += b'\x0f\x83\x00\x00\x00\x00'  # near jae → empty
        helper += b'\x66\x83\x3a\x00'
        je_empty_pos = len(helper)
        helper += b'\x0f\x84\x00\x00\x00\x00'  # near je → empty
        helper += b'\x66\x83\x3a\x2f'
        jne_next_pos = len(helper)
        helper += b'\x0f\x85\x00\x00\x00\x00'  # near jne → next
        helper += b'\x66\x83\x7a\x02\x63'
        je_found_pos = len(helper)
        helper += b'\x74\x00'
        helper += b'\x66\x83\x7a\x02\x43'
        jne_next2_pos = len(helper)
        helper += b'\x0f\x85\x00\x00\x00\x00'  # near jne → next
        found_pos = len(helper)
        helper += b'\x48\x83\xc2\x04'
        helper += b'\x66\x83\x3a\x20'
        helper += b'\x75\x04'
        helper += b'\x48\x83\xc2\x02'
        # Dest = fbe2+2 stream (ADAD only clears word[fbe2]). Also mirror into
        # [c8d8] so execute sees the line without sharing the parse cursor.
        stream = fbe2 + 2
        # Wipe only the stream window (fbe2 .. fbe2+0x40), not a wide range
        # that might clobber adjacent .data globals.
        helper += b'\x48\xbf' + struct.pack('<Q', fbe2)    # rdi = fbe2
        helper += b'\x31\xc0'
        helper += b'\xb9\x10\x00\x00\x00'                  # 0x10 dwords = 0x40 bytes
        helper += b'\xf3\xab'
        helper += b'\x49\xb8' + struct.pack('<Q', stream)  # r8 = stream
        helper += b'\x41\xb9\x00\x01\x00\x00'              # mov r9d, 0x100
        copy_pos = len(helper)
        helper += b'\x66\x8b\x0a'
        helper += b'\x66\x41\x89\x08'
        helper += b'\x49\x83\xc0\x02'
        helper += b'\x48\x83\xc2\x02'
        helper += b'\x66\x85\xc9'
        je_done_pos = len(helper)
        helper += b'\x74\x00'  # → store
        helper += b'\x41\xff\xc9'
        jne_copy_pos = len(helper)
        helper += b'\x75\x00'
        helper += b'\x66\x41\xc7\x00\x00\x00'
        store_pos = len(helper)
        # Append CR+LF on stream before NUL.
        helper += b'\x48\xbe' + struct.pack('<Q', stream)
        find_nul_pos = len(helper)
        helper += b'\x66\x83\x3e\x00'
        je_nul_pos = len(helper)
        helper += b'\x74\x00'
        helper += b'\x48\x83\xc6\x02'
        jmp_find_pos = len(helper)
        helper += b'\xeb\x00'
        write_eol_pos = len(helper)
        helper += b'\x66\xc7\x06\x0d\x00'
        helper += b'\x66\xc7\x46\x02\x0a\x00'
        helper += b'\x66\xc7\x46\x04\x00\x00'
        # fbc8 = stream; sticky=1; mirror into [c8d8] for execute.
        helper += b'\xb8' + struct.pack('<I', stream & 0xFFFFFFFF)
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x89\x03'
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done + 4)
        helper += b'\x41\x89\x03'                          # shadow = stream
        helper += b'\x49\xbb' + struct.pack('<Q', seed_done)
        helper += b'\x41\xc7\x03\x01\x00\x00\x00'
        helper += b'\x49\xbb' + struct.pack('<Q', c8d8)
        helper += b'\x41\x8b\x3b'                          # edi = [c8d8]
        helper += b'\x48\x85\xff'
        jz_nocopy_pos = len(helper)
        helper += b'\x74\x00'
        helper += b'\x48\xbe' + struct.pack('<Q', stream)
        pub_copy_pos = len(helper)
        helper += b'\x66\x8b\x0e'
        helper += b'\x66\x89\x0f'
        helper += b'\x48\x83\xc6\x02'
        helper += b'\x48\x83\xc7\x02'
        helper += b'\x66\x85\xc9'
        jne_pub_pos = len(helper)
        helper += b'\x75\x00'
        store_ret_pos = len(helper)
        helper += b'\xc3'
        next_pos = len(helper)
        helper += b'\x48\x83\xc2\x02'
        jmp_loop_imm = len(helper)
        helper += b'\xe9\x00\x00\x00\x00'
        empty_pos = len(helper)
        helper += b'\x49\xbb' + struct.pack('<Q', fbe2)
        helper += b'\x66\x41\xc7\x03\x00\x00'
        helper += b'\xb8' + struct.pack('<I', fbe2 & 0xFFFFFFFF)
        helper += b'\x49\xbb' + struct.pack('<Q', fbc8)
        helper += b'\x41\x89\x03'
        helper += b'\xc3'

        def _patch_rel8(imm_at: int, target: int) -> None:
            delta = target - (imm_at + 1)
            if not (-128 <= delta <= 127):
                raise ValueError(
                    f'seed-helper rel8 out of range: {delta} '
                    f'(imm_at={imm_at} target={target})')
            helper[imm_at] = delta & 0xFF

        def _patch_rel32(imm_at: int, target: int) -> None:
            struct.pack_into('<i', helper, imm_at, target - (imm_at + 4))

        _patch_rel32(je_empty_fbe2_pos + 2, empty_fbe2_pos)
        _patch_rel8(jb_eof_pos + 1, eof_ret_pos)
        _patch_rel8(jae_eof_pos + 1, eof_ret_pos)
        _patch_rel8(jne_have_pos + 1, have_pos)
        _patch_rel8(jb_skip_pos + 1, skip_nul_pos)
        _patch_rel32(jb_peb_pos + 2, seed_body_pos)
        _patch_rel8(jne_hard_pos + 1, eof_ret_pos)
        _patch_rel32(jb_peb_empty_pos + 2, seed_body_pos)
        _patch_rel8(jae_eof2_pos + 1, eof_ret_pos)
        _patch_rel8(jb_resume_pos + 1, resume_pos)
        _patch_rel8(jae_fin_pos + 1, finalize_pos)
        _patch_rel8(jne_cmd_have_pos + 1, have_pos)
        _patch_rel8(jmp_fin + 1, finalize_pos)
        _patch_rel8(jnz_have2 + 1, have_pos)
        _patch_rel8(jne_have3 + 1, have_pos)
        _patch_rel32(jz_pos + 2, empty_pos)
        _patch_rel32(jae_empty_pos + 2, empty_pos)
        _patch_rel32(je_empty_pos + 2, empty_pos)
        _patch_rel32(jne_next_pos + 2, next_pos)
        _patch_rel8(je_found_pos + 1, found_pos)
        _patch_rel32(jne_next2_pos + 2, next_pos)
        _patch_rel8(je_done_pos + 1, store_pos)
        _patch_rel8(jne_copy_pos + 1, copy_pos)
        _patch_rel8(je_nul_pos + 1, write_eol_pos)
        _patch_rel8(jmp_find_pos + 1, find_nul_pos)
        _patch_rel8(jz_nocopy_pos + 1, store_ret_pos)
        _patch_rel8(jne_pub_pos + 1, pub_copy_pos)
        _patch_rel32(jmp_loop_imm + 1, loop_pos)

        need = len(helper) + 4
        helper_off = None
        for tip in (
                b'\x49\xbb' + struct.pack('<Q', fbe2) + b'\x66\x41\x83\x3b\x00',
                b'\x4c\x0f\xb7\x50\x70\x48\x8b\x50\x78'):
            p = out.find(tip)
            if p < 0:
                continue
            if tip.startswith(b'\x4c\x0f'):
                back = max(0, p - 0x80)
                q = out.find(
                    b'\x49\xbb' + struct.pack('<Q', fbe2) + b'\x66\x41\x83\x3b\x00',
                    back, p + 1)
                if q >= 0:
                    p = q
                else:
                    continue
            # Always claim this slot; grow the blob if the new helper is larger.
            helper_off = p
            break
        if helper_off is not None:
            end_need = helper_off + len(helper)
            if end_need > len(out):
                out.extend(b'\x00' * (end_need - len(out) + 8))
            out[helper_off:helper_off + len(helper)] = helper
        else:
            pad_at = len(out)
            out.extend(b'\x00' * need)
            out[pad_at:pad_at + len(helper)] = helper
            helper_off = pad_at

        # Wire getchar empty path (align-call → seed helper) AND an entry
        # trampoline: sticky>=2 → one LF then 0; sticky==1 + cursor on fbe0
        # → discard unget and park on fbe2 (do not bump sticky — that raced
        # execute and SO'd).
        fbe0 = fbe2 - 2
        tip_load = (
            b'\x49\xbb' + struct.pack('<Q', fbc8) + b'\x41\x8b\x0b' +
            b'\x66\x83\x39\x00')  # movabs; mov ecx; cmp word [rcx],0
        # Entry trampoline replaces the first movabs r11,fbc8 (10 bytes).
        # Idempotent: skip if already jmp, and only accept a site whose jne
        # lands on ``cmp word [rcx], 0x0d`` (getchar CR check) — not the
        # post-seed reload written by the empty-handler patch (runs twice).
        entry_at = -1
        k_ent = 0
        while True:
            p = out.find(tip_load, k_ent)
            if p < 0:
                break
            if out[p] == 0xE9:
                k_ent = p + 1
                continue
            # Post-seed reload is ``call helper; movabs fbc8; …`` — skip it.
            if p >= 5 and out[p - 5] == 0xE8:
                k_ent = p + 1
                continue
            jne_p = p + len(tip_load)
            if jne_p + 1 >= len(out):
                break
            if out[jne_p] == 0x75:
                rel = out[jne_p + 1]
                if rel >= 128:
                    rel -= 256
                dest = jne_p + 2 + rel
            elif out[jne_p] == 0x0F and jne_p + 5 < len(out) and out[jne_p + 1] == 0x85:
                rel = struct.unpack_from('<i', out, jne_p + 2)[0]
                dest = jne_p + 6 + rel
            else:
                k_ent = p + 1
                continue
            if 0 <= dest < len(out) - 4 and out[dest:dest + 4] == b'\x66\x83\x39\x0d':
                entry_at = p
                break
            k_ent = p + 1
        if entry_at >= 0 and entry_at + 10 <= len(out):
            # Minimal gate: sticky>=2 → EOF 0; null cursor → park on fbe2;
            # else refresh shadow when cursor is in stream window, then
            # fall into cmp word [rcx], CR.
            gate = bytearray()
            gate += b'\x49\xbb' + struct.pack('<Q', seed_done)
            gate += b'\x41\x83\x3b\x02'
            jae_g = len(gate)
            gate += b'\x73\x00'                      # → eof
            gate += b'\x49\xbb' + struct.pack('<Q', fbc8)
            gate += b'\x41\x8b\x0b'
            gate += b'\x48\x85\xc9'
            jnz_ok = len(gate)
            gate += b'\x75\x00'                      # → maybe_shadow
            gate += b'\xb9' + struct.pack('<I', fbe2 & 0xFFFFFFFF)
            gate += b'\x49\xbb' + struct.pack('<Q', fbc8)
            gate += b'\x41\x89\x0b'
            jmp_cmp = len(gate)
            gate += b'\xe9\x00\x00\x00\x00'
            eof_pos = len(gate)
            gate += b'\x31\xc0'
            gate += b'\xc3'
            maybe_shadow = len(gate)
            # if stream <= ecx < stream+0x3e: shadow = ecx
            gate += b'\x49\xbb' + struct.pack('<Q', fbe2 + 2)
            gate += b'\x4c\x39\xd9'                  # cmp rcx, r11
            jb_cmp = len(gate)
            gate += b'\x72\x00'                      # → jmp_cmp
            gate += b'\x4d\x8d\x53\x3e'              # lea r10,[r11+0x3e]
            gate += b'\x4c\x39\xd1'                  # cmp rcx, r10
            jae_cmp = len(gate)
            gate += b'\x73\x00'                      # → jmp_cmp
            gate += b'\x49\xbb' + struct.pack('<Q', seed_done + 4)
            gate += b'\x41\x89\x0b'                  # shadow = ecx
            jmp_cmp2 = len(gate)
            gate += b'\xe9\x00\x00\x00\x00'

            def _g8(imm: int, target: int) -> None:
                d = target - (imm + 1)
                if not (-128 <= d <= 127):
                    raise ValueError(f'getchar-gate rel8 {d}')
                gate[imm] = d & 0xFF

            _g8(jae_g + 1, eof_pos)
            _g8(jnz_ok + 1, maybe_shadow)
            # jb/jae target jmp_cmp via near jmp at jmp_cmp2 path —
            # both branches share the same near jmp to cmp_site.
            # Point jb/jae at jmp_cmp2 (which is the near jmp).
            _g8(jb_cmp + 1, jmp_cmp2)
            _g8(jae_cmp + 1, jmp_cmp2)

            cmp_site = entry_at + 13
            gate_off = len(out)
            # First null-park path jumps to cmp_site
            struct.pack_into(
                '<i', gate, jmp_cmp + 1,
                cmp_site - (gate_off + jmp_cmp + 5))
            # Shadow-refresh path also jumps to cmp_site
            struct.pack_into(
                '<i', gate, jmp_cmp2 + 1,
                cmp_site - (gate_off + jmp_cmp2 + 5))
            out.extend(bytes(gate))
            rel_entry = gate_off - (entry_at + 5)
            out[entry_at:entry_at + 10] = (
                b'\xe9' + struct.pack('<i', rel_entry) + b'\x90' * 5)
            fixed += 1

        pat = bytes.fromhex('66833900')  # cmp word [rcx], 0
        k = 0
        while True:
            j = out.find(pat, k)
            if j < 0:
                break
            if j + 6 >= len(out):
                k = j + 1
                continue
            if out[j + 4] == 0x0F and out[j + 5] == 0x85:
                jne_len = 6
                rel = struct.unpack_from('<i', out, j + 6)[0]
                skip_to = j + 4 + jne_len + rel
            elif out[j + 4] == 0x75:
                jne_len = 2
                rel = out[j + 5]
                if rel >= 128:
                    rel -= 256
                skip_to = j + 4 + jne_len + rel
            else:
                k = j + 1
                continue
            block = j + 4 + jne_len
            if skip_to <= block or skip_to - block < 16 or skip_to > len(out):
                k = j + 1
                continue
            if out[block:block + 2] != b'\x41\x55':
                k = j + 1
                continue
            span = skip_to - block
            if span < 7:
                k = j + 1
                continue
            rel32 = helper_off - (block + 5)
            chunk = bytearray()
            chunk += b'\xe8' + struct.pack('<i', rel32)
            # After seed, re-check empty / sticky: WEOF not NUL.
            if span >= 28:
                chunk += b'\x49\xbb' + struct.pack('<Q', fbc8)
                chunk += b'\x41\x8b\x0b'
                chunk += b'\x66\x83\x39\x00'
                jne_at = len(chunk)
                chunk += b'\x75\x00'
                chunk += b'\x31\xc0'      # xor eax, eax (EOF=0 for parse helpers)
                chunk += b'\xc3'
                rel8 = skip_to - (block + jne_at + 2)
                if not (-128 <= rel8 <= 127):
                    k = j + 1
                    continue
                chunk[jne_at + 1] = rel8 & 0xFF
            elif span >= 15:
                chunk += b'\x49\xbb' + struct.pack('<Q', fbc8)
                chunk += b'\x41\x8b\x0b'
            else:
                chunk += b'\x89\xc1'
            while len(chunk) < span:
                chunk.append(0x90)
            out[block:skip_to] = chunk[:span]
            fixed += 1
            k = skip_to
        return fixed

    def _pure_restore_stdcall_arg4_mem_callback_call(self, out: bytearray) -> int:
        """Restore ``call [ebp+0x14]`` lost after x64 home-arg materialization.

        Win2000 MSVC helpers (cmd ``0xFD5D`` switch diamonds) do::

            push ebx / esi / edi
            call dword ptr [ebp+0x14]   ; 4th stdcall arg = continuation
            mov edi, eax
            mov [ebp+0x14], edi

        Translation saves RCX/RDX/R8/R9 into the x64 homes then emits
        ``mov edi, eax`` / ``mov rdi, rax`` with residual RAX — dropping the
        indirect call.  Arg4 lives at ``[rbp+0x28]``.  Re-insert
        ``sub rsp,0x20; call [rbp+0x28]; add rsp,0x20`` (shadow space)
        before the store-back.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov [rbp+0x28], r9; push rbx; push rsi; push rdi;
        # then either ``mov edi, eax`` (89 c7) or ``mov rdi, rax`` (48 89 c7);
        # mov [rbp+0x28], rdi.
        patterns = (
            (bytes.fromhex('4c894d2853565789c748897d28'), 2),   # mov edi,eax
            (bytes.fromhex('4c894d285356574889c748897d28'), 3),  # mov rdi,rax
        )
        for sig, mov_len in patterns:
            i = 0
            while True:
                at = out.find(sig, i)
                if at < 0:
                    break
                patch_at = at + 7  # start of mov edi/rdi, eax/rax
                store_len = mov_len + 4  # + mov [rbp+0x28], rdi
                stub = bytearray()
                stub += b'\x48\x83\xec\x20'          # sub rsp, 0x20
                stub += b'\xff\x55\x28'              # call qword [rbp+0x28]
                stub += b'\x48\x83\xc4\x20'          # add rsp, 0x20
                stub += b'\x89\xc7'                  # mov edi, eax
                stub += b'\x48\x89\x7d\x28'          # mov [rbp+0x28], rdi
                need = len(stub) + 5
                pad_at = None
                run = 0
                run_start = 0
                for p in range(len(out) - 1, max(0, len(out) - 0x10000), -1):
                    if out[p] in (0x00, 0x90, 0xCC):
                        run += 1
                        run_start = p
                        if run >= need and abs(run_start - patch_at) > 0x20:
                            pad_at = run_start
                            break
                    else:
                        run = 0
                if pad_at is None:
                    pad_at = len(out)
                    out.extend(b'\x00' * need)
                ret_at = patch_at + store_len
                stub += b'\xe9' + struct.pack(
                    '<i', ret_at - (pad_at + len(stub) + 5))
                out[pad_at:pad_at + len(stub)] = stub
                jmp = bytearray(b'\xe9' + struct.pack(
                    '<i', pad_at - (patch_at + 5)))
                while len(jmp) < store_len:
                    jmp.append(0x90)
                out[patch_at:patch_at + store_len] = jmp[:store_len]
                fixed += 1
                i = at + 1
        return fixed

    def _pure_fix_arg0_loaded_from_r8_after_homes(self, out: bytearray) -> int:
        """Fix ``mov rdi, r8`` when stdcall arg0 is in RCX / ``[rsp+8]``.

        Helpers with two stack locals then four CSRs (cmd ``0xFBE4``)::

            push ecx; push ecx          ; locals
            and [esp],0; and [esp+4],0
            push ebx / ebp / esi / edi
            mov edi, [esp+0x1c]         ; stdcall arg0

        become Win64 home spills + ``push rbx; …; push rdi`` then a wrong
        ``mov rdi, r8`` (arg2) instead of ``mov rdi, rcx`` (arg0).  The
        redirect walker then runs with a null list head.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # 4c 894c 24 20  = mov [rsp+0x20], r9
        # 53 55 56 57    = push rbx/rbp/rsi/rdi
        # 4c 89 c7       = mov rdi, r8
        sig = bytes.fromhex('4c894c2420535556574c89c7')
        i = 0
        while True:
            at = out.find(sig, i)
            if at < 0:
                break
            # Require preceding home spills for rcx/rdx/r8.
            if at < 12 or out[at - 12:at - 8] != b'\x48\x89\x4c\x24':
                # allow exact: mov [rsp+8],rcx a bit earlier
                window = bytes(out[max(0, at - 40):at])
                if b'\x48\x89\x4c\x24\x08' not in window:
                    i = at + 1
                    continue
            # 4c 89 c7 → 48 89 cf  (mov rdi, rcx)
            # Layout: [rsp+0x20] home (5) + four pushes (4) + mov (3).
            mov_at = at + 9
            if out[mov_at:mov_at + 3] != b'\x4c\x89\xc7':
                i = at + 1
                continue
            out[mov_at:mov_at + 3] = b'\x48\x89\xcf'
            fixed += 1
            i = at + 1
        # Variant without the r9 home immediately before pushes (some
        # translators only spill rcx/rdx/r8).
        sig2 = bytes.fromhex('535556574c89c7')
        i = 0
        while True:
            at = out.find(sig2, i)
            if at < 0:
                break
            window = bytes(out[max(0, at - 48):at])
            if b'\x48\x89\x4c\x24\x08' not in window:
                i = at + 1
                continue
            # Avoid double-fixing sig1 sites (already rcx).
            if out[at + 4:at + 7] == b'\x48\x89\xcf':
                i = at + 1
                continue
            if out[at + 4:at + 7] != b'\x4c\x89\xc7':
                i = at + 1
                continue
            out[at + 4:at + 7] = b'\x48\x89\xcf'
            fixed += 1
            i = at + 1
        return fixed

    def _pure_snap_calls_into_mov_reg_imm(self, out: bytearray) -> int:
        """Snap E8s that land mid ``mov r64, imm32`` back to the opcode."""
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        tips = (
            b'\x48\xc7\xc0', b'\x48\xc7\xc1', b'\x48\xc7\xc2',
            b'\x48\xc7\xc3', b'\x48\xc7\xc6', b'\x48\xc7\xc7',
            b'\x49\xc7\xc0', b'\x49\xc7\xc1', b'\x49\xc7\xc2',
            b'\x49\xc7\xc3', b'\x49\xc7\xc4', b'\x49\xc7\xc5',
            b'\x49\xc7\xc6', b'\x49\xc7\xc7',
        )
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            if not self._pure_branch_site_ok(out, i):
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if not (0 <= tgt < len(out) - 1):
                continue
            for back in range(1, 7):
                at = tgt - back
                if at < 0:
                    break
                if out[at:at + 3] in tips and at + 7 > tgt:
                    struct.pack_into('<i', out, i + 1, at - (i + 5))
                    fixed += 1
                    break
        return fixed

    def _pure_retarget_calls_to_zero_quad_helper(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget calls onto ``and [esp],0; and [esp+4],0`` scratch helpers.

        Win2000 helpers like cmd ``0xFBE4`` open with::

            push ecx; push ecx
            and dword [esp], 0
            and dword [esp+4], 0
            push ebx / ebp / esi / edi
            …

        After translation the body is at ``and dword [rsp],0; and [rsp+4],0``
        (often preceded by Win64 home spills).  Call-sync frequently pins
        callers onto the *previous* function's epilogue
        (``mov [rbx+0x34], eax`` with RBX still 0) — instant AV.  Snap every
        x86 call to that tip onto the pe64 body entry.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        x86_tip = bytes.fromhex('515183642400008364240400')
        pe_tip = bytes.fromhex('832424008364240400')
        helpers_x86: Set[int] = set()
        k = 0
        while True:
            j = text_data.find(x86_tip, k)
            if j < 0:
                break
            helpers_x86.add((text_rva + j) & 0xFFFFFFFF)
            k = j + 1
        if not helpers_x86:
            return 0
        helpers_pe: List[int] = []
        k = 0
        while True:
            j = out.find(pe_tip, k)
            if j < 0:
                break
            # Prefer Win64 home-spill entry a few bytes later when present.
            ent = j
            if (j + 12 + 20 <= len(out)
                    and out[j + 12:j + 14] == b'\x48\x89'
                    and out[j + 12:j + 16] == b'\x48\x89\x4c\x24'):
                ent = j + 12
            elif (j + 16 <= len(out)
                  and out[j + 12:j + 14] == b'\x48\x89'):
                # nops then homes
                p = j + 12
                while p < j + 20 and out[p] in (0x90, 0xCC, 0x00):
                    p += 1
                if out[p:p + 4] == b'\x48\x89\x4c\x24':
                    ent = p
            helpers_pe.append(ent)
            k = j + 1
        if not helpers_pe:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        fixed = 0
        used: Set[int] = set()

        def _nearest_pe(hint: Optional[int]) -> int:
            if hint is None:
                return helpers_pe[0]
            return min(helpers_pe, key=lambda e: abs(e - hint))

        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt = (x86_rva + 5 + rel) & 0xFFFFFFFF
            if tgt not in helpers_x86:
                continue
            anchor = rva_map.get(x86_rva)
            if anchor is None:
                for d in range(1, 16):
                    anchor = rva_map.get((x86_rva - d) & 0xFFFFFFFF)
                    if anchor is not None:
                        break
            best_j: Optional[int] = None
            best_dist = 999999
            if anchor is not None:
                for scan in range(max(0, anchor - 8),
                                  min(len(out) - pl - el - 5, anchor + 0x100)):
                    if out[scan:scan + pl] != pro:
                        continue
                    j = scan + pl
                    if j in used or out[j] != 0xE8:
                        continue
                    if out[j + 5:j + 5 + el] != epi:
                        continue
                    dist = abs(j - anchor)
                    if dist < best_dist:
                        best_dist = dist
                        best_j = j
            if best_j is None:
                continue
            new_tgt = _nearest_pe(anchor)
            cur = best_j + 5 + struct.unpack_from('<i', out, best_j + 1)[0]
            if cur == new_tgt:
                used.add(best_j)
                continue
            struct.pack_into('<i', out, best_j + 1, new_tgt - (best_j + 5))
            used.add(best_j)
            fixed += 1

        # pe64-only: any E8 that lands in the 0x40 bytes before a tip (prior
        # epilogue) gets snapped onto that tip's entry.
        for ent in helpers_pe:
            tip_at = ent
            for back in range(0, 24):
                if tip_at - back >= 0 and out[tip_at - back:tip_at - back + 9] == pe_tip:
                    tip_at = tip_at - back
                    break
            gap_lo = max(0, tip_at - 0x40)
            for j in range(0, len(out) - 5):
                if out[j] != 0xE8 or j in used:
                    continue
                cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
                if not (gap_lo <= cur < tip_at):
                    continue
                struct.pack_into('<i', out, j + 1, ent - (j + 5))
                used.add(j)
                fixed += 1
        return fixed

    def _pure_fix_geparse_followup_call(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget post-GEParse follow-up ``call`` onto the aux helper.

        Win2000 cmd ``0xEFF7`` does ``push 8; call FF31`` then ``call 0xF4EB``
        (``:`` label drain / switch-diamond entry).  Call-sync often pins that
        second E8 back onto FF31 because both sites sit in a collapsed
        rva_map window, so parse runs twice and overwrites ``fae0`` with LF —
        outer REPL stack-overflows.  Match x86 ``call`` sites whose target
        opens with ``cmp dword [imm],0; push esi; mov esi,0x4000`` and force
        the pe64 stub onto the translated aux entry.
        """
        if not self._cmd_no_hacks or not text_data:
            return 0
        aux_x86: Set[int] = set()
        for off in range(len(text_data) - 13):
            if (text_data[off] == 0x83 and text_data[off + 1] == 0x3D
                    and text_data[off + 6] == 0x00
                    and text_data[off + 7] == 0x56
                    and text_data[off + 8:off + 13]
                    == b'\xbe\x00\x40\x00\x00'):
                aux_x86.add((text_rva + off) & 0xFFFFFFFF)
        if not aux_x86:
            return 0
        aux_pe64: Optional[int] = None
        tip = b'\x48\xc7\xc6\x00\x40\x00\x00'  # mov rsi, 0x4000
        k = 0
        while True:
            j = out.find(tip, k)
            if j < 0:
                break
            # Prefer entry that has ``cmp dword [r11],0`` shortly before.
            window = bytes(out[max(0, j - 24):j])
            if b'\x41\x83\x3b\x00' in window or b'\x83\x3b\x00' in window:
                # Snap to preceding movabs r11 if present.
                ent = j
                for back in range(2, 28):
                    if j - back >= 0 and out[j - back:j - back + 2] == b'\x49\xbb':
                        ent = j - back
                        break
                aux_pe64 = ent
                break
            k = j + 1
        if aux_pe64 is None:
            return 0
        pro, epi = self._pure_align_stub_pro_epilogue()
        pl, el = len(pro), len(epi)
        fixed = 0
        used: Set[int] = set()
        for off in range(len(text_data) - 5):
            if text_data[off] != 0xE8:
                continue
            x86_rva = (text_rva + off) & 0xFFFFFFFF
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt = (x86_rva + 5 + rel) & 0xFFFFFFFF
            if tgt not in aux_x86 and not any(
                    tgt == (a + d) & 0xFFFFFFFF
                    for a in aux_x86 for d in range(1, 8)):
                continue
            anchor = rva_map.get(x86_rva)
            if anchor is None:
                for d in range(1, 12):
                    anchor = rva_map.get((x86_rva - d) & 0xFFFFFFFF)
                    if anchor is not None:
                        break
            if anchor is None or not (0 <= anchor < len(out)):
                continue
            best_j: Optional[int] = None
            best_dist = 999999
            for scan in range(max(0, anchor - 8),
                              min(len(out) - pl - el - 5, anchor + 0xC0)):
                if out[scan:scan + pl] != pro:
                    continue
                j = scan + pl
                if j in used or out[j] != 0xE8:
                    continue
                if out[j + 5:j + 5 + el] != epi:
                    continue
                dist = abs(j - anchor)
                if dist < best_dist:
                    best_dist = dist
                    best_j = j
            if best_j is None:
                continue
            cur = best_j + 5 + struct.unpack_from('<i', out, best_j + 1)[0]
            if cur == aux_pe64:
                used.add(best_j)
                continue
            struct.pack_into('<i', out, best_j + 1,
                             aux_pe64 - (best_j + 5))
            used.add(best_j)
            fixed += 1
        # pe64 pattern fallback: ``dec dword [fae8]`` shortly after an
        # align-stub call that still targets FF31 while an earlier sibling
        # call in the same wrapper already hit FF31 (cmd 0xF027).
        if True:
            fae8_stores = []
            for i in range(len(out) - 14):
                if out[i:i + 2] != b'\x49\xbb':
                    continue
                if out[i + 10:i + 13] == b'\x41\xff\x0b':
                    fae8_stores.append(i)
                elif out[i + 10:i + 12] == b'\xff\x0b':
                    fae8_stores.append(i)
            for st in fae8_stores:
                j = None
                for scan in range(st - 1, max(0, st - 0x80), -1):
                    if out[scan] != 0xE8:
                        continue
                    if scan >= pl and out[scan - pl:scan] == pro \
                            and out[scan + 5:scan + 5 + el] == epi:
                        j = scan
                        break
                if j is None or j in used:
                    continue
                cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
                if cur == aux_pe64 or abs(cur - aux_pe64) < 0x20:
                    continue
                if not (0 <= cur < len(out) - 12):
                    continue
                struct.pack_into('<i', out, j + 1, aux_pe64 - (j + 5))
                used.add(j)
                fixed += 1
        return fixed

    def _pure_fix_push_reg_as_win64_arg0(self, out: bytearray) -> int:
        """Reload RCX from a stdcall ``push reg`` before a Win64 align-call.

        Pattern (cmd Echo / parse)::

            push rsi
            je  L_zero_type          ; L_zero_type IS the align-call prelude
            ...
        L_zero_type:
            push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16
            call helper             ; helper reads arg0 from rcx / [rbp+0x10]

        The ``push rsi`` was the x86 arg0, but the Win64 call never loads RCX.
        Only rewrite when the jcc lands *directly* on the prelude so we do not
        clobber a sibling path that already did ``mov rcx, rax``.

        Also handles the translated shape where the jcc lands on a bare
        ``call`` and a ``mov rcx,reg`` + prelude trampoline sits in the
        preceding nop sled (cmd ``0x18110`` → ``0x18157``)::

            push rsi; je L_call
            ...
            jmp trampoline          ; mov rcx,rsi; prelude; jmp L_call
            nops
        L_call:
            call helper; mov rsp,r13; pop r13
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16  (13 bytes)
        prelude = bytes.fromhex('41554989e54883ec204883e4f0')
        assert len(prelude) == 13
        restore = bytes.fromhex('4c89ec415d')  # mov rsp,r13; pop r13
        for push_op, mov_rcx in (
                (0x56, b'\x48\x89\xf1'),  # mov rcx, rsi
                (0x57, b'\x48\x89\xf9'),  # mov rcx, rdi
        ):
            i = 0
            while i < len(out) - 40:
                if out[i] != push_op:
                    i += 1
                    continue
                # push reg; jcc near
                if not (out[i + 1] == 0x0F and out[i + 2] in (0x84, 0x85)):
                    i += 1
                    continue
                jcc_at = i + 1
                jcc_rel = struct.unpack_from('<i', out, i + 3)[0]
                land = i + 7 + jcc_rel
                if not (0 <= land < len(out) - 20):
                    i += 1
                    continue

                # --- Case A: jcc lands on prelude+call (classic) ---
                if out[land:land + 13] == prelude and out[land + 13] == 0xE8:
                    call_at = land
                    if mov_rcx in bytes(out[i + 1:call_at + 1]):
                        i += 1
                        continue
                    rel = struct.unpack_from('<i', out, call_at + 14)[0]
                    targ = call_at + 18 + rel
                    if not (0 <= targ < len(out) - 8):
                        i += 1
                        continue
                    probe = bytes(out[targ:targ + 0x28])
                    if (b'\x48\x89\x4d\x10' not in probe
                            and b'\x48\x8b\x5d\x10' not in probe):
                        i += 1
                        continue
                    # Small cave: mov rcx,reg; jmp prelude — leave the
                    # inlined prelude intact for sibling fallthroughs and
                    # avoid starving later pad consumers (volatile RDI).
                    cave = self._pure_find_padding_cave(
                        out, len(mov_rcx) + 5)
                    if cave < 0:
                        i += 1
                        continue
                    body = bytearray(mov_rcx)
                    body += b'\xe9' + struct.pack(
                        '<i', land - (cave + len(body) + 5))
                    out[cave:cave + len(body)] = body
                    struct.pack_into(
                        '<i', out, jcc_at + 2, cave - (jcc_at + 6))
                    out[i] = 0x90  # drop stdcall push; arg0 is in RCX
                    fixed += 1
                    # Backward Jcc (land < i): never rewind the scan —
                    # re-scanning from land+13 re-hits the same site and
                    # oscillates forever.
                    i = max(i + 1, land + 13)
                    continue

                # --- Case B: jcc lands on bare call; trampoline in nop sled ---
                if out[land] != 0xE8:
                    i += 1
                    continue
                if out[land + 5:land + 10] != restore:
                    i += 1
                    continue
                # Confirm callee stores arg0 from rcx home.
                rel = struct.unpack_from('<i', out, land + 1)[0]
                targ = land + 5 + rel
                if not (0 <= targ < len(out) - 8):
                    i += 1
                    continue
                probe = bytes(out[targ:targ + 0x28])
                if (b'\x48\x89\x4d\x10' not in probe
                        and b'\x48\x8b\x5d\x10' not in probe):
                    i += 1
                    continue
                # Prefer an existing trampoline just before the call.
                # Scan for ``jmp`` sites whose following gap is a nop sled
                # (do not walk byte-by-byte through a near-jmp's displacement).
                tramp = -1
                lo = max(i + 7, land - 0x28)
                for back in range(land - 5, lo - 1, -1):
                    if out[back] != 0xE9:
                        continue
                    if any(out[b] != 0x90 for b in range(back + 5, land)):
                        continue
                    dest = back + 5 + struct.unpack_from(
                        '<i', out, back + 1)[0]
                    if (0 <= dest < len(out) - 16
                            and out[dest:dest + 3] == mov_rcx
                            and out[dest + 3:dest + 16] == prelude):
                        tramp = back
                        break
                if tramp >= 0:
                    struct.pack_into(
                        '<i', out, jcc_at + 2, tramp - (jcc_at + 6))
                    # Drop the stdcall ``push reg`` — arg0 now lives in RCX
                    # via the trampoline; leaving the push skews the stack
                    # and heap-corrupts on return (cmd ``0x18110``).
                    out[i] = 0x90
                    fixed += 1
                    # Backward Jcc (land < i): never rewind the scan.
                    i = max(i + 1, land + 5)
                    continue
                # Do not invent new caves here: a bare ``call`` without a
                # pre-planted mov-rcx trampoline is often a different ABI
                # shape, and building one caused heap corruption on cmd.
                i += 1

        # Residual: earlier pass NOPed the stdcall push, then a later Jcc
        # retarget stole the mov-rcx cave tip back onto the bare prelude
        # (cmd 0x18110 -> Dispatch with RCX=0 while RSI still holds the node).
        i = 0
        while i < len(out) - 40:
            if out[i] != 0x90:
                i += 1
                continue
            if not (out[i + 1] == 0x0F and out[i + 2] in (0x84, 0x85)):
                i += 1
                continue
            look = bytes(out[max(0, i - 0x30):i])
            if (b"\x8b\x06" in look or b"\x8b\x46" in look
                    or b"\x48\x8b\x06" in look or b"\x48\x8b\x46" in look):
                mov_rcx = bytes([0x48, 0x89, 0xf1])  # mov rcx, rsi
            elif (b"\x8b\x07" in look or b"\x8b\x47" in look
                  or b"\x48\x8b\x07" in look or b"\x48\x8b\x47" in look):
                mov_rcx = bytes([0x48, 0x89, 0xf9])  # mov rcx, rdi
            else:
                i += 1
                continue
            jcc_at = i + 1
            jcc_rel = struct.unpack_from("<i", out, i + 3)[0]
            land = i + 7 + jcc_rel
            if not (0 <= land < len(out) - 20):
                i += 1
                continue
            # Already retargeted onto a mov-rcx cave?
            if (land + 8 <= len(out)
                    and out[land:land + 3] == mov_rcx
                    and out[land + 3] == 0xE9):
                # Backward Jcc (land < i): advancing to land+8 rewinds the
                # scan and re-hits this same site forever — oscillates
                # without state change.  Stay monotonic.
                i = max(i + 1, land + 8)
                continue
            if not (out[land:land + 13] == prelude and out[land + 13] == 0xE8):
                i += 1
                continue
            if mov_rcx in bytes(out[i + 1:land + 1]):
                i += 1
                continue
            rel = struct.unpack_from("<i", out, land + 14)[0]
            targ = land + 18 + rel
            if not (0 <= targ < len(out) - 8):
                i += 1
                continue
            probe = bytes(out[targ:targ + 0x28])
            if (b"\x48\x89\x4d\x10" not in probe
                    and b"\x48\x8b\x5d\x10" not in probe):
                i += 1
                continue
            cave = self._pure_find_padding_cave(out, len(mov_rcx) + 5)
            if cave < 0:
                i += 1
                continue
            body = bytearray(mov_rcx)
            body += b"\xe9" + struct.pack(
                "<i", land - (cave + len(body) + 5))
            out[cave:cave + len(body)] = body
            struct.pack_into(
                "<i", out, jcc_at + 2, cave - (jcc_at + 6))
            fixed += 1
            # Backward Jcc (land < i): never rewind the scan.
            i = max(i + 1, land + 13)

        return fixed

    def _pure_fix_frameless_local_push_arg1_reg(self, out: bytearray) -> int:
        """Fix ``mov rdi/rsi/rbx, r8`` that should be arg1 (RCX) after local pushes.

        MSVC frameless helpers open with ``push ecx; push ecx; and [esp],0``
        then callee-saves, then ``mov edi, [esp+0x1c]`` (stdcall arg1).  When
        deferred local pushes were flushed without bumping ``hw_stack_pushes``,
        the translator mapped that slot to R8.  Rewrite the register move to
        RCX.  Pattern is unique to this prologue shape across Win2000 binaries.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # push rcx; push rcx; and dword [rsp],0; and dword [rsp+4],0
        head = bytes.fromhex('5151832424008364240400')
        # after optional nop + home spills (20 bytes) or directly:
        # push rbx; push rbp; push rsi; push rdi; mov rdi, r8
        callees_r8 = bytes.fromhex('535556574c89c7')
        callees_rcx = bytes.fromhex('535556574889cf')
        i = 0
        while True:
            at = out.find(head, i)
            if at < 0:
                break
            # Search a short window for the callee-save block + bad mov.
            win = out[at:at + 0x40]
            rel = win.find(callees_r8)
            if rel >= 0:
                abs_at = at + rel
                out[abs_at:abs_at + len(callees_rcx)] = callees_rcx
                fixed += 1
                i = abs_at + len(callees_rcx)
                continue
            i = at + 2
        return fixed

    def _pure_nop_midframe_shadow_homes_after_locals(self, out: bytearray) -> int:
        """NOP Win64 shadow spills inserted *after* frameless ``push ecx`` locals.

        Homes belong at true entry (caller shadow).  When they land after
        ``push rcx; push rcx; and [rsp],0`` they overwrite the return address
        (``mov [rsp+0x10], rdx``) — cmd ``fbe4`` execute@0x30.  Translator now
        spills at entry; this heal cleans residual mid-frame copies.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        head = bytes.fromhex('5151832424008364240400')
        homes = bytes.fromhex('48894c240848895424104c894424184c894c2420')
        i = 0
        while True:
            at = out.find(head, i)
            if at < 0:
                break
            win = out[at:at + 0x30]
            rel = win.find(homes)
            if rel >= 0:
                abs_at = at + rel
                # Only when homes sit before the callee-save push rbx.
                after = abs_at + len(homes)
                if after < len(out) and out[after] == 0x53:  # push rbx
                    out[abs_at:after] = b'\x90' * len(homes)
                    fixed += 1
                    i = after
                    continue
            i = at + 2
        return fixed

    def _pure_fix_frameless_local_epilogue_pops(self, out: bytearray) -> int:
        """Restore ``pop ecx; pop ecx`` before ``ret`` after dual-push-ecx locals.

        Native ends ``pop edi..ebx; pop ecx; pop ecx; ret 4``.  Dropped pop ecx
        cleanup leaves RSP high; a plain ``ret`` then pops a local/zero.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        head = bytes.fromhex('5151832424008364240400')
        # xor rax,rax; pop rdi; pop rsi; pop rbp; pop rbx; ret
        epi = bytes.fromhex('4831c05f5e5d5bc3')
        stub = bytes.fromhex('31c05f5e5d5b5959c3')  # xor eax; pops; pop rcx x2; ret
        i = 0
        while True:
            at = out.find(head, i)
            if at < 0:
                break
            # Search forward up to 0x400 bytes for the matching fail-path epi.
            region = out[at:at + 0x400]
            rel = region.find(epi)
            if rel >= 0:
                epi_at = at + rel
                need = len(stub)
                pad_at = None
                run = 0
                for p in range(len(out) - 1, max(0, len(out) - 0x10000), -1):
                    if out[p] in (0x00, 0x90, 0xCC):
                        run += 1
                        if run >= need:
                            cand = p - run + 1
                            # Never steal the EF42 pointer-guard stub
                            # (``cmp ebx, 0x10000``) or its trailing pad.
                            stolen = False
                            for back in range(0, 0x40):
                                s = cand - back
                                if s < 0:
                                    break
                                if out[s:s + 6] == b'\x81\xfb\x00\x00\x01\x00':
                                    stolen = True
                                    break
                            if stolen:
                                run = 0
                                continue
                            pad_at = cand
                            if abs(pad_at - epi_at) > 0x20:
                                break
                    else:
                        run = 0
                if pad_at is None:
                    pad_at = len(out)
                    out.extend(b'\x00' * need)
                out[pad_at:pad_at + need] = stub
                rel32 = pad_at - (epi_at + 5)
                out[epi_at:epi_at + 8] = (
                    b'\xe9' + struct.pack('<i', rel32) + b'\x90\x90\x90')
                fixed += 1
                i = epi_at + 8
                continue
            i = at + 2
        return fixed

    def _pure_fix_frameless_r13_local_reload(self, out: bytearray) -> int:
        """Rewrite post-call ``mov rax,[r13+disp]`` that should be a local [rsp].

        After dual ``push ecx`` locals + callee-saves, ``mov eax,[esp+0x10]``
        was mapped through the had_call r13 path to ``[r13+0x48]``.  Scale the
        x86 local disp to ``[rsp+(disp/4)*8]``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # Full x86 tip, or and-only tip when pushes were dropped.
        heads = (
            bytes.fromhex('5151832424008364240400'),
            bytes.fromhex('832424008364240400'),
        )
        for head in heads:
            i = 0
            while True:
                at = out.find(head, i)
                if at < 0:
                    break
                j = at
                end = min(len(out) - 4, at + 0x400)
                while j < end:
                    # 49 8B 45 ib  = mov rax, [r13+ib]
                    if (out[j] == 0x49 and out[j + 1] == 0x8B
                            and out[j + 2] == 0x45):
                        if (j + 6 <= len(out)
                                and out[j + 4:j + 6] == b'\x85\xc0'):
                            # x86 [esp+0x10] → [rsp+0x20] with 2 locals + 4 CSR.
                            out[j:j + 4] = bytes.fromhex('8b442420')
                            fixed += 1
                            j += 4
                            continue
                    j += 1
                i = at + 2
        return fixed


    def _pure_fix_missing_push_ecx_local_before_csr(self, out: bytearray) -> int:
        """Restore dropped ``push ecx`` local before CSR pushes (Echo flag helper).

        x86 (cmd ``0x138e2``)::

            push ecx                 ; local
            push ebx; push ebp; push esi; push edi
            push 3; xor ebp,ebp
            cmp [esp+0x1c], ebp     ; arg0 (string*)
            pop ebx
            mov [esp+0x10], ebx     ; local = 3

        Translation emits Win64 homes + four CSR pushes but drops the local,
        so ``mov [rsp+0x10], ebx`` overwrites saved RBP (leave ? AV) and
        ``cmp [rsp+0x1c], ebp`` false-matches ? Echo returns 2 ("ECHO is on").
        """
        if not self._cmd_no_hacks:
            return 0
        homes = bytes.fromhex('48894c240848895424104c894424184c894c2420')
        csr = bytes.fromhex('53555657')
        # xor rbp,rbp; push 3; cmp [rsp+0x1c],ebp; pop rbx; mov [rsp+0x10],ebx
        tip = bytes.fromhex('4831ed6a03396c241c5b895c2410')
        fixed = 0
        i = 0
        while True:
            at = out.find(homes + csr + tip, i)
            if at < 0:
                break
            csr_at = at + len(homes)
            tip_at = csr_at + len(csr)
            end_tip = tip_at + len(tip)
            # Cave: push 0; CSR; xor; push 3; cmp [rsp+0x30],ebp; pop rbx;
            #       mov [rsp+0x20],ebx; jmp fallthrough
            def _build(cave, _fall=end_tip):
                stub = bytearray()
                stub += b'\x6a\x00'          # push 0  (x86 push ecx local)
                stub += csr
                stub += b'\x48\x31\xed'     # xor rbp,rbp
                stub += b'\x6a\x03'         # push 3
                stub += b'\x39\x6c\x24\x30' # cmp [rsp+0x30], ebp  (arg0 home)
                stub += b'\x5b'             # pop rbx
                stub += b'\x89\x5c\x24\x20' # mov [rsp+0x20], ebx  (local)
                stub += b'\xe9' + struct.pack(
                    '<i', _fall - (cave + len(stub) + 5))
                return bytes(stub)
            cave = self._pure_find_padding_cave(out, 28)
            if cave < 0:
                cave = len(out)
                out.extend(b"\x00" * 40)
            stub = _build(cave)
            if len(stub) > 40:
                i = at + 1
                continue
            out[cave:cave + len(stub)] = stub
            # Replace CSR+tip with jmp cave; nop pad
            span = len(csr) + len(tip)
            out[csr_at:csr_at + span] = (
                b'\xe9' + struct.pack('<i', cave - (csr_at + 5))
                + b'\x90' * (span - 5))
            # Body fixes until ~0x200 bytes or 4-pop epi
            body_end = min(len(out) - 4, end_tip + 0x200)
            j = end_tip
            while j < body_end:
                # cmp dword [rsp+0x10], 3 ? [rsp+0x20]
                if out[j:j + 5] == bytes.fromhex('837c241003'):
                    out[j + 3] = 0x20
                    j += 5
                    continue
                # cmp dword [rsp+0x1c], imm8 ? [rsp+0x38] (arg1 / rdx home)
                if out[j:j + 4] == bytes.fromhex('837c241c'):
                    out[j + 3] = 0x38
                    j += 4
                    continue
                # mov rax, [rsp+0x20] already correct as local with push 0
                # 4-pop epi: 5f5e5d5bc3 ? trampoline with extra pop
                if out[j:j + 5] == bytes.fromhex('5f5e5d5bc3'):
                    epi_cave = self._pure_find_padding_cave(out, 8)
                    if epi_cave >= 0:
                        out[epi_cave:epi_cave + 6] = bytes.fromhex('5f5e5d5b59c3')
                        out[j:j + 5] = (
                            b'\xe9' + struct.pack('<i', epi_cave - (j + 5)))
                    j += 5
                    continue
                # jmp near to shared 4-pop epi (5f5e5d5bc3): retarget
                if out[j] == 0xE9 and j + 5 <= len(out):
                    rel = struct.unpack_from('<i', out, j + 1)[0]
                    dest = j + 5 + rel
                    if (0 <= dest < len(out) - 4
                            and out[dest:dest + 5] == bytes.fromhex('5f5e5d5bc3')):
                        epi_cave = self._pure_find_padding_cave(out, 8)
                        if epi_cave >= 0:
                            out[epi_cave:epi_cave + 6] = bytes.fromhex(
                                '5f5e5d5b59c3')
                            struct.pack_into(
                                '<i', out, j + 1, epi_cave - (j + 5))
                    j += 5
                    continue
                j += 1
            fixed += 1
            i = end_tip
        return fixed


    def _pure_fix_frameless_dual_local_frame(self, out: bytearray) -> int:
        """Restore dual zero locals for ``and [esp],0; and [esp+4],0`` helpers.

        Translation often keeps the and-tip then emits Win64 homes and four
        CSR pushes *without* the native ``push ecx; push ecx`` locals (cmd
        ``0xFBE4``).  Counter updates hit ``[rsp+0x10]`` (saved RBP) and the
        iswspace-fail path reloads ``[r13+disp]``, so an empty redirect walk
        returns 1 and the caller AVs on a null list head.

        Rebuild in place::

            homes; push 0; push 0; nops; push rbx/rbp/rsi/rdi

        Retarget E8s from the old home entry onto the new home entry, scale
        local ``[rsp+0x10]/[rsp+0x14]`` to ``[rsp+0x20]/[rsp+0x28]``, and give
        exits a six-pop epilogue.
        """
        if not self._cmd_no_hacks:
            return 0
        pe_tip = bytes.fromhex('832424008364240400')
        homes = bytes.fromhex('48894c240848895424104c894424184c894c2420')
        csr = bytes.fromhex('53555657')
        fixed = 0
        i = 0
        while True:
            at = out.find(pe_tip, i)
            if at < 0:
                break
            # Locate homes after optional nops.
            p = at + len(pe_tip)
            while p < at + 24 and p < len(out) and out[p] in (0x90, 0xCC, 0x00):
                p += 1
            if out[p:p + len(homes)] != homes:
                i = at + 1
                continue
            old_ent = p
            csr_at = p + len(homes)
            if out[csr_at:csr_at + 4] != csr:
                i = at + 1
                continue
            # Need at least homes + push0×2 + csr between at and csr_at+4.
            # Layout from `at` to `csr_at` (exclusive) must fit homes + 4.
            gap = csr_at - at
            if gap < len(homes) + 4:
                i = at + 1
                continue
            new_block = bytearray(homes + b'\x6a\x00\x6a\x00')
            new_block.extend(b'\x90' * (gap - len(new_block)))
            if len(new_block) != gap:
                i = at + 1
                continue
            out[at:csr_at] = new_block
            new_ent = at
            # Retarget E8s that landed on the old home entry.
            for j in range(len(out) - 5):
                if out[j] != 0xE8:
                    continue
                if not self._pure_branch_site_ok(out, j):
                    continue
                rel = struct.unpack_from('<i', out, j + 1)[0]
                tgt = j + 5 + rel
                if tgt == old_ent and old_ent != new_ent:
                    struct.pack_into('<i', out, j + 1, new_ent - (j + 5))
            # Scale local stack refs in the body (2 locals + 4 CSR).
            end = min(len(out) - 4, at + 0x400)
            j = csr_at + 4
            while j < end:
                # mov rax, [r13+ib]; test eax,eax → mov eax, [rsp+0x20]
                if (out[j] == 0x49 and out[j + 1] == 0x8B
                        and out[j + 2] == 0x45
                        and j + 6 <= len(out)
                        and out[j + 4:j + 6] == b'\x85\xc0'):
                    out[j:j + 4] = bytes.fromhex('8b442420')
                    j += 4
                    continue
                # inc dword [rsp+0x10] → [rsp+0x20]
                if out[j:j + 4] == bytes.fromhex('ff442410'):
                    out[j + 3] = 0x20
                    j += 4
                    continue
                # inc dword [rsp+0x14] → [rsp+0x28]
                if out[j:j + 4] == bytes.fromhex('ff442414'):
                    out[j + 3] = 0x28
                    j += 4
                    continue
                # cmp dword [rsp+0x14], imm8
                if out[j:j + 4] == bytes.fromhex('837c2414'):
                    out[j + 3] = 0x28
                    j += 4
                    continue
                # cmp dword [rsp+0x14], eax/reg
                if out[j:j + 4] == bytes.fromhex('39442414'):
                    out[j + 3] = 0x28
                    j += 4
                    continue
                if out[j:j + 4] == bytes.fromhex('3b442414'):
                    out[j + 3] = 0x28
                    j += 4
                    continue
                if out[j:j + 4] == bytes.fromhex('8b442410'):
                    out[j + 3] = 0x20
                    j += 4
                    continue
                if out[j:j + 4] == bytes.fromhex('8b442414'):
                    out[j + 3] = 0x28
                    j += 4
                    continue
                j += 1
            # Six-pop epilogue cave for exits that only pop four CSRs.
            stub = bytes.fromhex('5f5e5d5b5959c3')
            pad_at = None
            run = 0
            for p in range(len(out) - 1, max(0, len(out) - 0x8000), -1):
                if out[p] in (0x00, 0x90, 0xCC):
                    run += 1
                    if run >= len(stub):
                        pad_at = p - run + 1
                        if abs(pad_at - at) > 0x20:
                            break
                else:
                    run = 0
            if pad_at is None:
                pad_at = len(out)
                out.extend(b'\x00' * len(stub))
            out[pad_at:pad_at + len(stub)] = stub
            four_pop = bytes.fromhex('5f5e5d5bc3')
            # Inline ``xor rax,rax; four-pop; ret`` → xor + jmp stub.
            xor_epi = bytes.fromhex('4831c05f5e5d5bc3')
            j = at
            while j < end - len(xor_epi):
                if out[j:j + len(xor_epi)] == xor_epi:
                    # 31 c0 ; e9 rel32 ; 90  — jmp displacement from end of e9.
                    rel32 = pad_at - (j + 7)
                    out[j:j + 8] = (
                        b'\x31\xc0\xe9' + struct.pack('<i', rel32) + b'\x90')
                j += 1
            # jmp/call rel32 onto shared 4-pop epi → stub.
            j = at
            while j < end - 5:
                if out[j] in (0xE9, 0xE8):
                    rel = struct.unpack_from('<i', out, j + 1)[0]
                    tgt = j + 5 + rel
                    if 0 <= tgt <= len(out) - 5 and out[tgt:tgt + 5] == four_pop:
                        struct.pack_into('<i', out, j + 1, pad_at - (j + 5))
                j += 1
            fixed += 1
            i = csr_at + 4
        return fixed

    def _pure_fix_parked_arg0_stale_reload(self, out: bytearray) -> int:
        """Drop stale ``mov eax,[rsp-N]; mov r12,rax`` before ``cmp [r12+8],0``.

        Frameless ``sub rsp,0x58`` parks stdcall arg0 in r12.  A later
        ``mov ebp,[esp+0x6c]`` can still emit a bogus negative-[rsp] reload
        that zeroes r12 (cmd 0xA071), then ``cmp [r12+8],0`` AVs at address 8.
        When the prologue parked arg0, keep r12 and delete the reload.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # sub rsp,0x58 ; … ; mov r12, rcx
        pro = bytes.fromhex('4883ec58')
        park = bytes.fromhex('4989cc')  # mov r12, rcx
        # mov eax, [rsp+ib8]; mov r12, rax; cmp dword [r12+8], 0
        # 8b 44 24 xx / 49 89 c4 / 41 83 7c 24 08 00
        i = 0
        while True:
            at = out.find(pro, i)
            if at < 0:
                break
            window = out[at:at + 0x900]
            park_at = window.find(park)
            if park_at < 0:
                i = at + 2
                continue
            j = park_at + 3
            while j < len(window) - 12:
                if (window[j] == 0x8B and window[j + 1] == 0x44
                        and window[j + 2] == 0x24
                        and window[j + 4:j + 7] == bytes.fromhex('4989c4')
                        and window[j + 7:j + 13] == bytes.fromhex('41837c240800')):
                    # Only when the reload displacement is negative / nonsense
                    # relative to a live frame (ib as signed).
                    disp = window[j + 3]
                    if disp >= 0x80:  # negative disp8
                        abs_at = at + j
                        out[abs_at:abs_at + 7] = b'\x90' * 7
                        fixed += 1
                        j += 13
                        continue
                j += 1
            i = at + 2
        return fixed

    def _pure_fix_movzx_wchar_arg_after_partial_ax(
            self, out: bytearray) -> int:
        """Zero-extend ``mov ax,mem`` before ``mov rdx/rcx, rax`` wchar args.

        x86 ``mov ax,[imm]; push eax`` only needs the low 16 bits.  Win64
        ``mov ax,mem; mov rdx,rax; call wcsrchr`` leaves the previous pointer
        in RDX[63:16] so the CRT never matches, returns NULL, then
        ``and word [rax],0`` AVs (cmd echo ``d595``).
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rdx,rax → movzx edx,ax ; mov rcx,rax → movzx ecx,ax
        pairs = (
            (b'\x48\x89\xc2', b'\x0f\xb7\xd0'),
            (b'\x48\x89\xc1', b'\x0f\xb7\xc8'),
        )
        i = 0
        while i < len(out) - 8:
            # 66 41 8B 03 = mov ax,[r11]  or  66 8B 03 = mov ax,[rbx] etc.
            is_ax = False
            ax_end = i
            if out[i:i + 4] == b'\x66\x41\x8b\x03':  # [r11]
                is_ax = True
                ax_end = i + 4
            elif out[i] == 0x66 and out[i + 1] == 0x8B and (
                    (out[i + 2] >> 3) & 7) == 0:
                modrm = out[i + 2]
                mod, rm = modrm >> 6, modrm & 7
                if mod == 3:
                    ax_end = i + 3
                elif mod == 0 and rm == 5:
                    ax_end = i + 7
                elif mod == 0:
                    ax_end = i + 3
                elif mod == 1:
                    ax_end = i + 4
                elif mod == 2:
                    ax_end = i + 7
                else:
                    i += 1
                    continue
                is_ax = True
            if not is_ax:
                i += 1
                continue
            # Within 8 bytes, widen mov r64,rax used as arg before a call.
            for k in range(ax_end, min(ax_end + 8, len(out) - 3)):
                hit = False
                for old, new in pairs:
                    if out[k:k + 3] != old:
                        continue
                    # Call within next 0x28 bytes.
                    win = bytes(out[k:k + 0x28])
                    if not (b'\xe8' in win or b'\xff\xd0' in win
                            or b'\xff\x15' in win or b'\x41\xff' in win
                            or b'\xff\xd3' in win or b'\xff\xd6' in win
                            or b'\xff\xd7' in win or b'\xff\xd4' in win):
                        continue
                    out[k:k + 3] = new
                    fixed += 1
                    hit = True
                    i = k + 3
                    break
                if hit:
                    break
            else:
                i = ax_end
            continue
        return fixed

    def _pure_fix_push_imm_pop_eax_return(
            self, out: bytearray) -> int:
        """Repair ``push imm; pop eax`` epilogues mistranslated via RSI.

        x86 ``push 1; pop eax`` becomes ``mov rsi,1; pop rsi; leave; ret`` —
        EAX never gets the return code (cmd echo ``d9bc``).  Rewrite to
        ``mov eax,imm`` plus the same callee-save pops as the nearby shared
        epilogue (``pop rdi; pop rsi; [pop rbx;] leave; ret``).
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        epi3 = bytes([0x5F, 0x5E, 0x5B, 0xC9, 0xC3])  # pop rdi;rsi;rbx; leave; ret
        epi2 = bytes([0x5F, 0x5E, 0xC9, 0xC3])        # pop rdi;rsi; leave; ret
        for imm in (1, 2, 5, 0, 3, 4):
            imm4 = struct.pack('<I', imm)
            patterns = (
                # broken: mov rsi,imm; pop rsi; leave; ret
                bytes([0x48, 0xc7, 0xc6]) + imm4 + bytes([0x5E, 0xC9, 0xC3]),
                # half-fix: mov eax,imm; nop; nop; pop rsi; leave; ret
                bytes([0xB8]) + imm4 + bytes([0x90, 0x90, 0x5E, 0xC9, 0xC3]),
            )
            for pat in patterns:
                assert len(pat) == 10
                i = 0
                while True:
                    j = out.find(pat, i)
                    if j < 0:
                        break
                    # Prefer a 3-pop shared epilogue in the same function body.
                    window = out[j:min(len(out), j + 0x600)]
                    if epi3 in window:
                        repl = (bytes([0xB8]) + imm4
                                + bytes([0x5F, 0x5E, 0x5B, 0xC9, 0xC3]))
                    elif epi2 in window:
                        repl = (bytes([0xB8]) + imm4
                                + bytes([0x5F, 0x5E, 0x90, 0xC9, 0xC3]))
                    else:
                        # Conservative: set EAX, keep single pop + leave/ret.
                        repl = (bytes([0xB8]) + imm4
                                + bytes([0x90, 0x90, 0x5E, 0xC9, 0xC3]))
                    assert len(repl) == 10
                    out[j:j + 10] = repl
                    fixed += 1
                    i = j + 10
        return fixed

    def _pure_find_padding_cave(self, out: bytearray, need: int) -> int:
        """Reserve ``need`` bytes of inter-function padding, or -1.

        Caves are handed out from a cursor so repeated heals do not overlap.
        Accepts INT3/zero *and* NOP sleds (``0x90``) — late heals otherwise
        starve after early pad consumers leave only NOP runs.
        On a miss past the cursor, wrap once so earlier unused sleds are used.
        """
        pad = (0x00, 0xCC, 0x90)
        cursor = getattr(self, '_pure_cave_cursor', 0)
        n = len(out)

        def _scan(lo: int, hi: int) -> int:
            run = 0
            i = max(lo, 0)
            while i < hi:
                if out[i] in pad:
                    run += 1
                    if run >= need + 2:
                        start = i - run + 2
                        self._pure_cave_cursor = start + need
                        return start
                else:
                    run = 0
                i += 1
            return -1

        hit = _scan(cursor, n)
        if hit >= 0:
            return hit
        if cursor > 0:
            return _scan(0, cursor)
        return -1

    def _pure_fix_code_push_imm_landed_in_empty_data(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Rewrite ``push <code_va>`` movabs that tipped into empty .data.

        Chained helpers push .text callback addresses (cmd ``0xf4eb`` /
        ``0xf5a8``).  Collapsed rva_map tips them into zero-filled ``.data``
        slots, so ``call [rbp+14h]`` / ``call [rbp+28h]`` executes zeros.

        Anchored at each x86 call: the first two preceding ``push <code>``
        become Win64 ``r9`` then ``r8`` (stdcall right-to-left).  Only
        rewrite when the current movabs is empty .data or a near-miss.
        """
        if (not self._cmd_no_hacks or not rva_map or not text_data
                or not self._old_to_new_section):
            return 0
        pe = self.pe
        if pe is None:
            return 0
        old_base = int(self.old_base or 0)
        new_base = int(self.new_base or 0)
        if not old_base or not new_base:
            return 0
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))
        text_lo = new_base + text_new
        text_hi = text_lo + len(out)
        data_lo = data_hi = 0
        data_raw = None
        data_new = 0
        for old_sec, new_sec in self._old_to_new_section.items():
            osec = pe.section_for_rva(old_sec)
            if not osec or (osec['flags'] & 0x20000000):
                continue
            nm = osec.get('name') or b''
            if isinstance(nm, bytes):
                nm = nm.split(b'\0')[0].decode('ascii', 'replace')
            if str(nm).startswith('.data'):
                data_new = new_sec
                data_lo = new_base + new_sec
                sz = max(osec.get('vsize', 0), osec.get('raw_sz', 0), 1)
                data_hi = data_lo + sz
                data_raw = pe.get_section_data(osec)
                break
        if not data_lo:
            return 0

        def _data_empty(va: int) -> bool:
            if not (data_lo <= va < data_hi) or data_raw is None:
                return False
            off = int(va - new_base) - data_new
            if not (0 <= off + 8 <= len(data_raw)):
                return False
            return data_raw[off:off + 8] == b'\x00' * 8

        as_rva = max(rva_map.values()) >= len(out) if rva_map else False

        def to_off(pe64: int) -> int:
            return pe64 - text_rva if as_rva else pe64

        def to_va(blob_off: int) -> int:
            return (new_base + text_new + blob_off) & 0xFFFFFFFFFFFFFFFF

        def snap_entry(moff: int, old_rva: int) -> int:
            """Snap a collapsed mid-body tip back to the translated entry.

            Callback pushes often map onto a later ``mov rdx, imm`` inside the
            same chain; the real entry is the preceding ``movabs`` / ``cmp``
            block that matches the x86 prologue.
            """
            if not (0 <= moff < len(out)):
                return moff
            xoff = old_rva - text_rva
            if not (0 <= xoff < len(text_data)):
                return moff
            xb0 = text_data[xoff]
            # Push-imm callback chain (cmd f5a8/f5bf/f5d6): every link's
            # rva_map tip collapses onto the first ``movabs rcx``.  Match the
            # x86 ``push imm8`` message id to the pe64 ``mov rdx, imm``.
            if xb0 == 0x68:
                msg_id = None
                for q in range(xoff, min(len(text_data) - 7, xoff + 0x18)):
                    if (text_data[q] == 0x6A
                            and text_data[q + 2] == 0x68
                            and text_data[q + 7] == 0xE8):
                        msg_id = text_data[q + 1]
                        break
                if msg_id is not None:
                    scan_lo = max(0, moff - 0x400)
                    scan_hi = min(len(out) - 16, moff + 0x400)
                    for p in range(scan_lo, scan_hi):
                        if out[p:p + 2] not in (bytes([0x48, 0xB9]),
                                                bytes([0x48, 0xB8])):
                            continue
                        # Reject mid-chain movabs r8/r9.
                        if out[p] == 0x49 and out[p + 1] in (0xB8, 0xB9):
                            continue
                        window = bytes(out[p + 10:min(len(out), p + 0x28)])
                        msg_got = -1
                        rdx_at = window.find(bytes([0x48, 0xC7, 0xC2]))
                        if rdx_at >= 0 and rdx_at + 7 <= len(window):
                            msg_got = struct.unpack_from(
                                '<I', window, rdx_at + 3)[0]
                        else:
                            for bi, b in enumerate(window):
                                if b == 0xBA and bi + 5 <= len(window):
                                    # Skip BA that is the opcode of a REX
                                    # prefix sequence already consumed.
                                    if bi > 0 and window[bi - 1] in (
                                            0x48, 0x49, 0x4C, 0x4D):
                                        continue
                                    msg_got = struct.unpack_from(
                                        '<I', window, bi + 1)[0]
                                    break
                        if msg_got == msg_id:
                            return p
            # Already an entry-shaped tip (non-chain or msg match failed).
            if out[moff] == 0x55:  # push rbp
                return moff
            if (out[moff] in (0x48, 0x49, 0x4C, 0x4D)
                    and 0xB8 <= out[moff + 1] <= 0xBF):
                # Reject mid-chain ``movabs r8/r9`` used as a false tip.
                if out[moff] == 0x49 and out[moff + 1] in (0xB8, 0xB9):
                    pass  # fall through to snap
                else:
                    return moff
            lo = max(0, moff - 0x100)
            hi = min(len(out) - 16, moff + 0x10)
            # x86 ``cmp dword [abs], imm8`` → ``movabs r11; cmp dword [r11], imm8``
            if (xb0 == 0x83 and xoff + 7 <= len(text_data)
                    and text_data[xoff + 1] == 0x3D):
                imm8 = text_data[xoff + 6]
                needle = bytes([0x41, 0x83, 0x3B, imm8])
                for p in range(lo, hi):
                    if out[p:p + 4] != needle:
                        continue
                    if (p >= 10 and out[p - 10] in (0x49, 0x4D)
                            and out[p - 9] == 0xBB):
                        return p - 10
            # Generic: tip is ``mov rdx, imm`` / ``mov edx, imm`` — back up to
            # the preceding movabs rcx/rax that loads the string/code arg.
            if (out[moff:moff + 3] == bytes([0x48, 0xC7, 0xC2])
                    or out[moff] == 0xBA):
                for p in range(moff - 1, max(0, moff - 0x30), -1):
                    if out[p:p + 2] in (bytes([0x48, 0xB9]),
                                        bytes([0x48, 0xB8]),
                                        bytes([0x49, 0xBB])):
                        return p
            return moff

        def code_exp(imm: int) -> Optional[int]:
            if not (old_base <= imm < old_base + pe.image_size):
                return None
            old_rva = imm - old_base
            sec = pe.section_for_rva(old_rva)
            if not sec or not (sec['flags'] & 0x20000000):
                return None
            mapped = rva_map.get(old_rva)
            if mapped is None:
                # Try a few nearby anchors (prefix epilogue / align).
                for d in range(1, 8):
                    mapped = rva_map.get((old_rva - d) & 0xFFFFFFFF)
                    if mapped is not None:
                        break
            if mapped is None:
                # Push-imm chain entries often share a sibling's rva_map slot;
                # seed a scan from any nearby mapped tip.
                xoff = old_rva - text_rva
                if not (0 <= xoff < len(text_data) and text_data[xoff] == 0x68):
                    return None
                seed = None
                for d in range(0, 0x80, 4):
                    for cand in ((old_rva - d) & 0xFFFFFFFF,
                                 (old_rva + d) & 0xFFFFFFFF):
                        m = rva_map.get(cand)
                        if m is not None:
                            seed = to_off(m)
                            break
                    if seed is not None:
                        break
                if seed is None or not (0 <= seed < len(out)):
                    return None
                snapped = snap_entry(seed, old_rva)
                if snapped == seed and text_data[xoff] == 0x68:
                    # Still collapsed — try a wider seed near known chain.
                    snapped = snap_entry(max(0, seed - 0x80), old_rva)
                return to_va(snapped)
            moff = to_off(mapped)
            if not (0 <= moff < len(out)):
                return None
            return to_va(snap_entry(moff, old_rva))

        img_end = old_base + pe.image_size
        n = len(text_data)
        fixed = 0
        for off in range(max(0, n - 5)):
            if text_data[off] != 0xE8:
                continue
            # Require callback-chain shape:
            #   push <code>; push <code>; push imm8; push <str>; call
            # so .text string literals are not treated as code tips.
            if off < 12 or text_data[off - 7] != 0x6A or text_data[off - 5] != 0x68:
                continue
            code_pushes: List[int] = []
            k = off - 7
            while k > max(0, off - 28) and len(code_pushes) < 2:
                k -= 1
                if k + 5 <= off - 7 and text_data[k] == 0x68:
                    imm = struct.unpack_from('<I', text_data, k + 1)[0]
                    exp = code_exp(imm)
                    if exp is not None:
                        code_pushes.append(exp)
                        k -= 4
            if len(code_pushes) < 2:
                continue
            code_pushes.reverse()
            want = {0xB9: code_pushes[0], 0xB8: code_pushes[1]}  # r9, r8
            call_anchor = rva_map.get((text_rva + off) & 0xFFFFFFFF)
            if call_anchor is None:
                continue
            call_off = to_off(call_anchor)
            if not (0 <= call_off < len(out)):
                continue
            lo = max(0, call_off - 0x60)
            for j in range(call_off - 10, lo, -1):
                if out[j] != 0x49 or out[j + 1] not in want:
                    continue
                exp = want[out[j + 1]]
                got = struct.unpack_from('<Q', out, j + 2)[0]
                if got == exp:
                    continue
                if _data_empty(got) or (
                        text_lo <= got < text_hi
                        and abs(int(got) - int(exp)) <= 0x200):
                    struct.pack_into('<Q', out, j + 2, exp)
                    fixed += 1
        # Secondary pe64 pattern pass: outer callback chains only
        # (``movabs rcx`` / ``mov rdx, msg_id`` / ``movabs r8`` / ``movabs r9``).
        chains: List[Tuple[int, int]] = []  # (r8_exp, r9_exp)
        for off in range(max(0, n - 5)):
            if text_data[off] != 0xE8:
                continue
            if off < 12 or text_data[off - 7] != 0x6A or text_data[off - 5] != 0x68:
                continue
            msg_id = text_data[off - 6]
            if not (0x20 <= msg_id <= 0x7F):
                continue
            cps: List[int] = []
            k = off - 7
            while k > max(0, off - 28) and len(cps) < 2:
                k -= 1
                if k + 5 <= off - 7 and text_data[k] == 0x68:
                    exp = code_exp(struct.unpack_from('<I', text_data, k + 1)[0])
                    if exp is not None:
                        cps.append(exp)
                        k -= 4
            if len(cps) == 2:
                cps.reverse()
                chains.append((cps[1], cps[0], msg_id))  # r8, r9, msg
        j = 0
        while j < len(out) - 30 and chains:
            # movabs rcx, … ; mov rdx, msg ; movabs r8 ; movabs r9
            if out[j:j + 2] not in (bytes([0x48, 0xB9]), bytes([0x48, 0xB8])):
                j += 1
                continue
            # Find mov rdx, imm32 within 0x18
            rdx_at = -1
            msg = -1
            for k in range(j + 10, min(len(out) - 7, j + 0x18)):
                if out[k:k + 3] == bytes([0x48, 0xC7, 0xC2]):
                    msg = struct.unpack_from('<I', out, k + 3)[0]
                    rdx_at = k
                    break
                if out[k] == 0xBA:
                    msg = struct.unpack_from('<I', out, k + 1)[0]
                    rdx_at = k
                    break
            if rdx_at < 0 or not (0x20 <= msg <= 0x7F):
                j += 1
                continue
            r8_at = r9_at = -1
            for k in range(rdx_at + 1, min(len(out) - 10, rdx_at + 0x30)):
                if out[k] == 0x49 and out[k + 1] == 0xB8 and r8_at < 0:
                    r8_at = k
                elif out[k] == 0x49 and out[k + 1] == 0xB9 and r8_at >= 0:
                    r9_at = k
                    break
            if r8_at < 0 or r9_at < 0:
                j += 1
                continue
            window = bytes(out[r9_at + 10:min(len(out), r9_at + 0x50)])
            if 0xE8 not in window and b'\xFF\xD0' not in window:
                j += 1
                continue
            # Prefer chain with matching message id.
            matched = [c for c in chains if c[2] == msg]
            if not matched:
                matched = chains
            got8 = struct.unpack_from('<Q', out, r8_at + 2)[0]
            got9 = struct.unpack_from('<Q', out, r9_at + 2)[0]
            best = min(matched, key=lambda c: abs(int(c[0]) - int(got8)))
            if got8 != best[0] and (
                    _data_empty(got8) or text_lo <= got8 < text_hi
                    or abs(int(got8) - int(best[0])) <= 0x200):
                struct.pack_into('<Q', out, r8_at + 2, best[0])
                fixed += 1
            if got9 != best[1] and (
                    _data_empty(got9) or data_lo <= got9 < data_hi
                    or text_lo <= got9 < text_hi
                    or abs(int(got9) - int(best[1])) <= 0x200):
                struct.pack_into('<Q', out, r9_at + 2, best[1])
                fixed += 1
            j = r9_at + 10
        return fixed

    def _pure_fix_data_abs_imm_landed_in_text(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Rewrite ``movabs`` of .data absolutes that landed inside .text.

        x86 ``mov reg, <data_va>`` must relocate into the PE64 ``.data``
        section.  Expansion sometimes embeds a colliding literal into the
        code blob and retargets the load there instead (cmd command table
        ``0x1c8e8`` → ``0x47ce4`` in .text instead of ``0x588e8`` in .data).
        The embedded copy is not the real table, so every lookup fails.
        """
        if (not self._cmd_no_hacks or not rva_map or not text_data
                or not self._old_to_new_section):
            return 0
        pe = self.pe
        if pe is None:
            return 0
        old_base = int(self.old_base or 0)
        new_base = int(self.new_base or 0)
        if not old_base or not new_base:
            return 0
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))
        text_lo = new_base + text_new
        text_hi = text_lo + len(out)
        # Collect x86 ``mov r32, imm32`` whose imm is a .data absolute.
        sites: List[Tuple[int, int]] = []  # (x86_rva, exp_va)
        n = len(text_data)
        img_end = old_base + pe.image_size
        for off in range(max(0, n - 5)):
            b0 = text_data[off]
            if not (0xB8 <= b0 <= 0xBF):
                continue
            imm = struct.unpack_from('<I', text_data, off + 1)[0]
            if not (old_base <= imm < img_end):
                continue
            old_rva = imm - old_base
            sec = pe.section_for_rva(old_rva)
            if not sec or (sec['flags'] & 0x20000000):
                continue  # skip code-section immediates
            name = sec.get('name') or b''
            if isinstance(name, bytes):
                name = name.split(b'\0')[0].decode('ascii', 'replace')
            if not str(name).startswith(('.data', '.rdata')):
                continue
            old_sec = sec['vaddr']
            new_sec = self._old_to_new_section.get(old_sec)
            if new_sec is None:
                continue
            exp = (new_base + new_sec + (old_rva - old_sec)) & 0xFFFFFFFFFFFFFFFF
            sites.append(((text_rva + off) & 0xFFFFFFFF, exp))
        if not sites:
            return 0
        as_rva = max(rva_map.values()) >= len(out)
        def to_off(pe64: int) -> int:
            return pe64 - text_rva if as_rva else pe64
        fixed = 0
        for x_rva, exp in sites:
            anchor = rva_map.get(x_rva)
            if anchor is None:
                for d in range(1, 8):
                    anchor = rva_map.get((x_rva - d) & 0xFFFFFFFF)
                    if anchor is not None:
                        break
            if anchor is None:
                continue
            off = to_off(anchor)
            if not (0 <= off < len(out)):
                continue
            lo = max(0, off - 16)
            hi = min(len(out) - 10, off + 0x80)
            for j in range(lo, hi):
                if out[j] not in (0x48, 0x49, 0x4C, 0x4D):
                    continue
                if not (0xB8 <= out[j + 1] <= 0xBF):
                    continue
                got = struct.unpack_from('<Q', out, j + 2)[0]
                if got == exp:
                    break
                if not (text_lo <= got < text_hi):
                    continue
                struct.pack_into('<Q', out, j + 2, exp)
                fixed += 1
                break
        # Pattern pass: table-walk ``movabs rsi, <text>`` followed soon by
        # ``mov edx,[rsi-8]``.  Collapsed rva_map tips miss this site.
        # Compute the expected table VA directly from x86 ``mov esi, imm``.
        table_exp = None
        for off in range(max(0, n - 5)):
            if text_data[off] != 0xBE:
                continue
            imm = struct.unpack_from('<I', text_data, off + 1)[0]
            if not (old_base <= imm < old_base + pe.image_size):
                continue
            old_rva = imm - old_base
            sec = pe.section_for_rva(old_rva)
            if not sec or (sec['flags'] & 0x20000000):
                continue
            nm = sec.get('name') or b''
            if isinstance(nm, bytes):
                nm = nm.split(b'\0')[0].decode('ascii', 'replace')
            if not str(nm).startswith('.data'):
                continue
            # Prefer the command-table tip (entry stride 0x18, name ptr at -8).
            new_sec = self._old_to_new_section.get(sec['vaddr'])
            if new_sec is None:
                continue
            cand = (new_base + new_sec + (old_rva - sec['vaddr'])) & 0xFFFFFFFFFFFFFFFF
            if table_exp is None or (old_rva & 0xFFFF) == 0xC8E8:
                table_exp = cand
        if table_exp is not None:
            j = 0
            while j < len(out) - 16:
                if out[j] in (0x48, 0x49) and out[j + 1] == 0xBE:
                    got = struct.unpack_from('<Q', out, j + 2)[0]
                    if text_lo <= got < text_hi:
                        window = bytes(out[j + 10:j + 0x28])
                        if bytes([0x8B, 0x56, 0xF8]) in window and got != table_exp:
                            struct.pack_into('<Q', out, j + 2, table_exp)
                            fixed += 1
                j += 1
        return fixed

    def _pure_materialize_unmapped_jcc_targets(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Translate x86 Jcc targets that were never emitted.

        Interior labels reached only by conditional jumps (e.g. cmd table
        match arm ``0x142a2``) can fall out of the function-driven pass.
        The pe64 ``je``/``jne`` then keeps a placeholder that lands back on
        a local align stub (``push r13``), so a successful compare never
        returns the found index.

        Only materialize when the live pe64 Jcc currently targets ``push r13``
        (dropped match arm).  Wrong-function rematerialize was too aggressive.
        """
        if not self._cmd_no_hacks or not rva_map or not text_data:
            return 0
        as_rva = max(rva_map.values()) >= len(out) if rva_map else False

        def to_off(pe64: int) -> int:
            return pe64 - text_rva if as_rva else pe64

        targets: List[Tuple[int, int]] = []  # (x86_tgt, pe64_jcc_off)
        seen: Set[int] = set()
        n = len(text_data)
        for off in range(max(0, n - 6)):
            op = text_data[off]
            if 0x70 <= op <= 0x7F:
                rel = struct.unpack_from('<b', text_data, off + 1)[0]
                tgt = (text_rva + off + 2 + rel) & 0xFFFFFFFF
                x86_len = 2
            elif op == 0x0F and off + 5 < n and 0x80 <= text_data[off + 1] <= 0x8F:
                rel = struct.unpack_from('<i', text_data, off + 2)[0]
                tgt = (text_rva + off + 6 + rel) & 0xFFFFFFFF
                x86_len = 6
            else:
                continue
            if tgt in seen:
                continue
            # pe64 Jcc at this site must currently land on push r13 —
            # that is the signature of a dropped match/arm label, even
            # when rva_map already has a bogus tip for the x86 target.
            site = rva_map.get((text_rva + off) & 0xFFFFFFFF)
            if site is None:
                continue
            joff = to_off(site)
            if not (0 <= joff + 6 <= len(out)):
                continue
            cur_tgt = None
            if out[joff] == 0x0F and 0x80 <= out[joff + 1] <= 0x8F:
                r = struct.unpack_from('<i', out, joff + 2)[0]
                cur_tgt = joff + 6 + r
            elif 0x70 <= out[joff] <= 0x7F:
                r = struct.unpack_from('<b', out, joff + 1)[0]
                cur_tgt = joff + 2 + r
            if cur_tgt is None or not (0 <= cur_tgt + 2 <= len(out)):
                continue
            # Only materialize when the live Jcc lands on push r13 —
            # wrong-function rematerialize proved too aggressive (univ259
            # execute@NULL on CRT init).  Prefer branch-retarget heals for
            # mis-tipped mid-function labels (cmd fd5d→fdcc).
            if out[cur_tgt:cur_tgt + 2] != bytes([0x41, 0x55]):
                continue
            seen.add(tgt)
            targets.append((tgt, joff))
        if not targets:
            return 0
        fixed = 0
        MAX_CHUNK = 128
        materialized: List[int] = []
        for x86_tgt, joff in targets[:8]:
            # Always rematerialize when the live Jcc lands on push r13 —
            # existing rva_map tips for these labels are often mid-stub junk.
            tgt_off = x86_tgt - text_rva
            if tgt_off < 0 or tgt_off + 4 > n:
                continue
            end_off = min(tgt_off + 48, n)
            for s in range(tgt_off, end_off):
                if text_data[s] in (0xC3, 0xC2):
                    end_off = s + (3 if text_data[s] == 0xC2 else 1)
                    break
                if text_data[s] in (0xE9, 0xEB) and s > tgt_off:
                    end_off = s + (5 if text_data[s] == 0xE9 else 2)
                    break
            func_bytes = text_data[tgt_off:end_off]
            if len(func_bytes) < 4 or len(func_bytes) > MAX_CHUNK:
                continue
            try:
                local_deferred: List[Tuple[int, int, str]] = []
                chunk, chunk_map = self._translate_function(
                    x86_tgt, func_bytes, False, 0,
                    chunk_base=0, section_rva=text_rva,
                    global_rva_map=rva_map, deferred_branches=local_deferred)
            except Exception:
                continue
            if not chunk or len(chunk) > MAX_CHUNK + 64:
                continue
            chunk = bytearray(chunk)
            # Strip accidental Win64 home prologue for mid-function arms.
            if (chunk[:5] == bytes([0x48, 0x89, 0x4C, 0x24, 0x08])
                    and len(chunk) > 20
                    and chunk[5:10] == bytes([0x48, 0x89, 0x54, 0x24, 0x10])):
                chunk = chunk[20:]
                if chunk_map:
                    chunk_map = {k: v - 20 for k, v in chunk_map.items()
                                 if v >= 20}
            # Reject chunks that are clearly align-stub residue.
            if chunk[:2] == bytes([0x41, 0x55]) or chunk[:3] == bytes(
                    [0x48, 0x83, 0xEC]):
                continue
            # Length-neutral: x86 [esp+0x14] → [rsp+0x28] after 2 pushes.
            esp14 = bytes([0x8B, 0x4C, 0x24, 0x14])
            k = chunk.find(esp14)
            if k >= 0:
                chunk[k + 3] = 0x28
            base = len(out)
            out += bytes(chunk)
            while len(out) % 4:
                out.append(0x90)
            # Pad so deferred-branch patches cannot overrun.
            out.extend(b'\x90' * 32)
            try:
                self._note_code_span(base, len(chunk))
            except Exception:
                pass
            rva_map[x86_tgt] = base
            for old_va, rel in (chunk_map or {}).items():
                old_r = (old_va - self.old_base) & 0xFFFFFFFF
                if old_r not in rva_map:
                    rva_map[old_r] = base + max(0, rel)
                elif self._pure_off_in_zero_hole(out, rva_map[old_r]):
                    rva_map[old_r] = base + max(0, rel)
            if local_deferred:
                adj = [(base + po, trva, ft)
                       for (po, trva, ft) in local_deferred
                       if 0 <= base + po + 4 <= len(out)]
                try:
                    self._resolve_deferred_branches(out, rva_map, adj)
                except (struct.error, ValueError, IndexError):
                    pass
            # Retarget the pe64 Jcc that was landing on push r13.
            if out[joff] == 0x0F and 0x80 <= out[joff + 1] <= 0x8F:
                struct.pack_into('<i', out, joff + 2, base - (joff + 6))
            elif 0x70 <= out[joff] <= 0x7F:
                pass
            materialized.append(base)
            fixed += 1
        # Pattern pass: table-search ``test [rsi],4; je <push r13>`` still
        # looping into the align stub — retarget onto a materialized arm,
        # or synthesize one from the x86 match-arm bytes when translate
        # could not emit a usable body.
        sig = bytes([0xF6, 0x06, 0x04, 0x0F, 0x84])
        i = 0
        while i < len(out) - 20:
            j = out.find(sig, i)
            if j < 0:
                break
            je_at = j + 3
            rel = struct.unpack_from('<i', out, je_at + 2)[0]
            tgt = je_at + 6 + rel
            if not (0 <= tgt + 2 <= len(out)
                    and out[tgt:tgt + 2] == bytes([0x41, 0x55])):
                i = j + 1
                continue
            arm = None
            for cand in materialized:
                # Match arm must load a stack home / do lea edi+edi*2.
                blob = bytes(out[cand:cand + 24])
                if (bytes([0x8B, 0x4C, 0x24]) in blob
                        or bytes([0x48, 0x8B, 0x4C, 0x24]) in blob
                        or bytes([0x8D, 0x04, 0x7F]) in blob):
                    arm = cand
                    break
            if arm is None:
                arm = self._pure_synthesize_table_match_arm(
                    out, text_data, text_rva, j)
                if arm is not None:
                    materialized.append(arm)
            if arm is not None:
                struct.pack_into('<i', out, je_at + 2, arm - (je_at + 6))
                for k in range(j + 8, min(len(out) - 6, j + 0x30)):
                    if out[k:k + 2] == bytes([0x0F, 0x85]):
                        r2 = struct.unpack_from('<i', out, k + 2)[0]
                        if k + 6 + r2 == tgt:
                            struct.pack_into('<i', out, k + 2, arm - (k + 6))
                            break
                fixed += 1
            i = j + 1
        return fixed

    def _pure_fix_jcc_to_corrupt_join_cave(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Retarget Jcc that landed on a corrupt rematerialized join cave.

        cmd ``f5ed``: ``cmp [ebp-4],edi; je f668`` was rematerialized into a
        far cave that ends with ``mov rsp,r13; jmp <mid pop r13>`` / a bogus
        ``SetThreadLocale`` call, while the same function already contains
        the correct ``call ba38`` join behind an align stub.  When the x86
        target begins with ``call X`` and that call's pe64 mapping appears
        in-function after the Jcc, prefer that site (or its align prelude).
        """
        if not self._cmd_no_hacks or not rva_map or not text_data:
            return 0
        as_rva = max(rva_map.values()) >= len(out) if rva_map else False

        def to_off(pe64: int) -> int:
            return pe64 - text_rva if as_rva else pe64

        align_stub = bytes.fromhex('41554989e54883ec204883e4f0')

        def _is_wanted_call_join(tgt: int, want_off: int) -> bool:
            if not (0 <= tgt < len(out)):
                return False
            if tgt == want_off:
                return True
            if out[tgt] == 0xE8:
                rel = struct.unpack_from('<i', out, tgt + 1)[0]
                if tgt + 5 + rel == want_off:
                    return True
            if (tgt + 18 <= len(out)
                    and out[tgt:tgt + 13] == align_stub
                    and out[tgt + 13] == 0xE8):
                rel = struct.unpack_from('<i', out, tgt + 14)[0]
                if tgt + 18 + rel == want_off:
                    return True
            # push-reg→rcx cave: mov rcx,rsi/rdi; jmp <wanted join>
            # Must not be stolen back onto the bare prelude (loses RCX).
            if (tgt + 8 <= len(out)
                    and out[tgt:tgt + 3] in (b'\x48\x89\xf1', b'\x48\x89\xf9')
                    and out[tgt + 3] == 0xE9):
                dest = tgt + 8 + struct.unpack_from('<i', out, tgt + 4)[0]
                if dest == want_off:
                    return True
                if (0 <= dest < len(out) - 18
                        and out[dest:dest + 13] == align_stub
                        and out[dest + 13] == 0xE8):
                    rel = struct.unpack_from('<i', out, dest + 14)[0]
                    if dest + 18 + rel == want_off:
                        return True
            return False

        fixed = 0
        for x_rva, pe64 in list(rva_map.items()):
            xo = x_rva - text_rva
            if xo < 0 or xo + 6 > len(text_data):
                continue
            op = text_data[xo]
            x_jcc_off = None
            if op == 0x0F and 0x80 <= text_data[xo + 1] <= 0x8F:
                x_jcc_off = xo
            elif 0x70 <= op <= 0x7F:
                x_jcc_off = xo
            else:
                # rva_map often tips the preceding ``cmp`` / ``mov``; accept
                # when a Jcc follows within a few bytes (cmd f614→f619).
                for d in range(1, 10):
                    p = xo + d
                    if p + 1 >= len(text_data):
                        break
                    if (text_data[p] == 0x0F
                            and p + 1 < len(text_data)
                            and 0x80 <= text_data[p + 1] <= 0x8F):
                        x_jcc_off = p
                        break
                    if 0x70 <= text_data[p] <= 0x7F:
                        x_jcc_off = p
                        break
                    # Stop at another obvious insn boundary that's not a
                    # short mov/cmp between flag producer and jcc.
                    if text_data[p] in (0xE8, 0xE9, 0xC3, 0xC2):
                        break
            if x_jcc_off is None:
                continue
            if text_data[x_jcc_off] == 0x0F:
                x_tgt = (text_rva + x_jcc_off + 6 + struct.unpack_from(
                    '<i', text_data, x_jcc_off + 2)[0]) & 0xFFFFFFFF
            else:
                x_tgt = (text_rva + x_jcc_off + 2 + struct.unpack_from(
                    '<b', text_data, x_jcc_off + 1)[0]) & 0xFFFFFFFF
            xt_off = x_tgt - text_rva
            if xt_off < 0 or xt_off + 5 > len(text_data):
                continue
            # Join label that begins with a direct call.
            if text_data[xt_off] != 0xE8:
                continue
            x_call_tgt = (x_tgt + 5 + struct.unpack_from(
                '<i', text_data, xt_off + 1)[0]) & 0xFFFFFFFF
            want_pe = rva_map.get(x_call_tgt)
            if want_pe is None:
                continue
            want_off = to_off(want_pe)
            if not (0 <= want_off < len(out)):
                continue
            joff = to_off(pe64)
            if not (0 <= joff + 6 <= len(out)):
                continue
            # rva_map may tip the preceding ``cmp`` / ``mov``; slide forward
            # a few bytes onto the actual Jcc.
            jcc_off = None
            for d in range(0, 12):
                p = joff + d
                if p + 6 > len(out):
                    break
                if out[p] == 0x0F and 0x80 <= out[p + 1] <= 0x8F:
                    jcc_off = p
                    break
                if 0x70 <= out[p] <= 0x7F:
                    break  # short form — leave alone
            if jcc_off is None:
                # Or the map tipped the Jcc itself.
                if out[joff] == 0x0F and 0x80 <= out[joff + 1] <= 0x8F:
                    jcc_off = joff
                else:
                    continue
            rel_at, end = jcc_off + 2, jcc_off + 6
            cur = end + struct.unpack_from('<i', out, rel_at)[0]
            if _is_wanted_call_join(cur, want_off):
                continue
            # Prefer an in-function call to want_off after this Jcc.
            # Current tip is often a far rematerialize of the *fallthrough*
            # arm (cmd f668 → 0x48900), not an obviously-corrupt sled.
            join = None
            scan_end = min(len(out) - 5, jcc_off + 0x400)
            k = end
            while k < scan_end:
                if out[k] == 0xE8:
                    rel = struct.unpack_from('<i', out, k + 1)[0]
                    if k + 5 + rel == want_off:
                        join = k
                        if (k >= 13 and out[k - 13:k] == align_stub):
                            join = k - 13
                        break
                k += 1
            if join is None or join == cur:
                continue
            struct.pack_into('<i', out, rel_at, join - end)
            # Keep rva_map honest so later passes do not re-tip to the cave.
            rva_map[x_tgt] = join + text_rva if as_rva else join
            fixed += 1
        return fixed

    def _pure_synthesize_table_match_arm(
            self, out: bytearray, text_data: bytes, text_rva: int,
            pe64_test_off: int) -> Optional[int]:
        """Emit a PE64 match-arm cave from the x86 table-search success path.

        x86 shape (after ``test [esi],4`` / Extensions check)::

            mov ecx, [esp+0x14]
            lea eax, [edi+edi*2]
            mov ax, [eax*8+table]
            mov [ecx], ax
            mov [last_index], edi
            mov eax, edi
            jmp epilogue

        On Win64 after ``push rsi; push rdi`` the 3rd arg home is
        ``[rsp+0x28]``.  Absolute VAs are relocated via section map.
        """
        if not self._cmd_no_hacks or not text_data or not self._old_to_new_section:
            return None
        pe = self.pe
        if pe is None:
            return None
        old_base = int(self.old_base or 0)
        new_base = int(self.new_base or 0)
        n = len(text_data)
        # Find x86 ``mov ecx,[esp+0x14]; lea eax,[edi+edi*2]; mov ax,[eax*8+imm]``
        sig = bytes([0x8B, 0x4C, 0x24, 0x14, 0x8D, 0x04, 0x7F, 0x66, 0x8B, 0x04, 0xC5])
        xoff = text_data.find(sig)
        if xoff < 0 or xoff + 21 > n:
            return None
        table_imm = struct.unpack_from('<I', text_data, xoff + 11)[0]
        # mov [ecx],ax; mov [abs],edi
        if text_data[xoff + 15:xoff + 18] != bytes([0x66, 0x89, 0x01]):
            return None
        if text_data[xoff + 18] != 0x89 or text_data[xoff + 19] != 0x3D:
            return None
        last_imm = struct.unpack_from('<I', text_data, xoff + 20)[0]

        def reloc(imm: int) -> Optional[int]:
            if not (old_base <= imm < old_base + pe.image_size):
                return None
            old_rva = imm - old_base
            sec = pe.section_for_rva(old_rva)
            if not sec:
                return None
            new_sec = self._old_to_new_section.get(sec['vaddr'])
            if new_sec is None:
                return None
            return (new_base + new_sec + (old_rva - sec['vaddr'])) & 0xFFFFFFFFFFFFFFFF

        table_va = reloc(table_imm)
        last_va = reloc(last_imm)
        if table_va is None or last_va is None:
            return None
        # Guard: scaled-index disp sometimes relocates onto an embedded
        # .text copy of the table.  Prefer the real .data slot.
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))
        text_lo = new_base + text_new
        text_hi = text_lo + len(out)
        if text_lo <= table_va < text_hi:
            for old_sec, new_sec in self._old_to_new_section.items():
                osec = pe.section_for_rva(old_sec)
                if not osec or (osec['flags'] & 0x20000000):
                    continue
                nm = osec.get('name') or b''
                if isinstance(nm, bytes):
                    nm = nm.split(b'\0')[0].decode('ascii', 'replace')
                if str(nm).startswith('.data'):
                    old_rva = table_imm - old_base
                    table_va = (new_base + new_sec + (old_rva - old_sec)) & 0xFFFFFFFFFFFFFFFF
                    break
        if text_lo <= table_va < text_hi:
            return None
        # Epilogue: ``or eax,-1`` fail path's ``pop rdi; pop rsi; ret`` —
        # search forward from the test site for ``or eax,-1; …; pop; pop; ret``.
        epi = -1
        for k in range(pe64_test_off, min(len(out) - 6, pe64_test_off + 0x80)):
            if out[k:k + 3] == bytes([0x83, 0xC8, 0xFF]):  # or eax,-1
                for p in range(k + 3, min(len(out) - 2, k + 0x40)):
                    if out[p:p + 3] == bytes([0x5F, 0x5E, 0xC3]):
                        epi = p
                        break
                break
        if epi < 0:
            return None
        stub = bytearray()
        stub += bytes([0x48, 0x8B, 0x4C, 0x24, 0x28])  # mov rcx,[rsp+0x28]
        stub += bytes([0x8D, 0x04, 0x7F])              # lea eax,[rdi+rdi*2]
        stub += bytes([0x49, 0xBB]) + struct.pack('<Q', table_va)
        stub += bytes([0x66, 0x41, 0x8B, 0x04, 0xC3])  # mov ax,[r11+rax*8]
        stub += bytes([0x66, 0x89, 0x01])              # mov [rcx],ax
        stub += bytes([0x49, 0xBB]) + struct.pack('<Q', last_va)
        stub += bytes([0x41, 0x89, 0x3B])              # mov [r11],edi
        stub += bytes([0x89, 0xF8])                    # mov eax,edi
        base = len(out)
        stub += bytes([0xE9]) + struct.pack('<i', epi - (base + len(stub) + 5))
        out += stub
        while len(out) % 4:
            out.append(0x90)
        try:
            self._note_code_span(base, len(stub))
        except Exception:
            pass
        return base

    def _pure_fix_ultoa_value_as_dword_home(self, out: bytearray) -> int:
        """Load ``_ultoa``/``_ltoa`` values from a DWORD home, not QWORD.

        x86 passes a message/error id as a 32-bit stack arg.  After Win64
        home expansion ``mov rcx, [rbp+0x10]`` can pick up a leftover high
        half (or a mistyped pointer), so ``_ultoa`` treats a ``.text`` VA as
        the number and later formatting writes through garbage (cmd write
        @0x56 during the init message chain).  When the call is clearly
        ``_ultoa``-shaped (``lea rdx, [rbp+…]; mov r8, 10|16``), force
        ``mov ecx, dword [rbp+0x10]``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rcx, qword [rbp+0x10]
        pat = bytes([0x48, 0x8B, 0x4D, 0x10])
        i = 0
        while True:
            j = out.find(pat, i)
            if j < 0:
                break
            window = bytes(out[j + 4:min(len(out), j + 0x40)])
            # lea rdx, [rbp+disp]  (48 8D 55 xx  or  8D 55 xx)
            has_lea = (bytes([0x48, 0x8D, 0x55]) in window
                       or bytes([0x8D, 0x55]) in window)
            # mov r8, 0xA / 0x10  (41 B8 0A/10 00 00 00) or 49 C7 C0 …
            has_radix = (
                bytes([0x41, 0xB8, 0x0A, 0x00, 0x00, 0x00]) in window
                or bytes([0x41, 0xB8, 0x10, 0x00, 0x00, 0x00]) in window
                or bytes([0x49, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00]) in window
                or bytes([0x49, 0xC7, 0xC0, 0x10, 0x00, 0x00, 0x00]) in window
                or bytes([0x41, 0xB8, 0x0A]) in window
                or bytes([0x41, 0xB8, 0x10]) in window)
            # Or: mov r8, 0x10 via 49 C7 C0 10 00 00 00 / B8 form in our blob:
            # we also emit ``mov r8, 0x10`` as 41 B8 10 00 00 00 OR
            # from disasm: ``mov r8, 0x10`` = 49 C7 C0 10 00 00 00? 
            # Actual from blob: 41? Looking at disasm ``mov r8, 0x10`` at 262b0
            # bytes - check: typically 49 C7 C0 10 00 00 00 or 41 B8.
            if has_lea and (has_radix or b'\x10\x00\x00\x00' in window[:24]):
                # Also require a call nearby.
                if 0xE8 in window or b'\xFF\xD0' in window or b'\xFF\x15' in window:
                    out[j:j + 4] = bytes([0x8B, 0x4D, 0x10, 0x90])  # mov ecx,dword; nop
                    fixed += 1
            i = j + 1
        return fixed

    def _pure_fix_rsp_disp0c_to_18(self, out: bytearray) -> int:
        """Fix Win64 home displacement typo: ``[rsp+0x0c]`` → ``[rsp+0x18]``.

        This appears when x86 uses ``[esp+0x0c]`` as a loop bound while the
        Win64 frame expansion accidentally leaves the displacement unmoved.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        for old, new in (
                (bytes.fromhex('397c240c'), bytes.fromhex('397c2418')),  # cmp r32,[rsp+0xc]
                (bytes.fromhex('3b7c240c'), bytes.fromhex('3b7c2418')),  # cmp r32,[rsp+0xc]
        ):
            i = 0
            while True:
                j = out.find(old, i)
                if j < 0:
                    break
                out[j:j + len(old)] = new
                fixed += 1
                i = j + len(old)
        return fixed

    def _pure_fix_xor_rdx_zeroed_before_call(self, out: bytearray) -> int:
        """Replace ``xor rdx,rdx`` with ``mov edx,[rsi-8]`` in arg-setup blocks.

        The translator sometimes collapses ``push dword ptr [esi-8]`` into a
        zeroed arg register, but the following call stub expects the value
        loaded from the current table-entry pointer in ``rsi``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # xor rdx,rdx; push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16
        pat = bytes.fromhex('4831d241554989e54883ec204883e4f0')
        repl = bytes.fromhex('8b56f8')  # mov edx, [rsi-8]
        i = 0
        while True:
            j = out.find(pat, i)
            if j < 0:
                break
            out[j:j + 3] = repl
            fixed += 1
            i = j + len(pat)
        return fixed

    def _pure_fix_dropped_rbx_scaled_word_store(self, out: bytearray) -> int:
        """Fix dropped SIB-index in common ebp+rbx*2 word-store loops.

        Repair patterns like::

            mov word ptr [rbp+disp32], si          ; BUG: index dropped
            ...
            and word ptr [rbp+disp32], 0           ; BUG: index dropped

        into the intended ``[rbp+rbx*2+disp32]`` SIB form.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        max_fixed = 24  # safety cap: avoid pathological O(n*m) scans

        # mov word ptr [rbp+disp32], si
        mov_pat = b'\x66\x89\xB5'  # 66 89 /r with modrm=0xB5 (reg=si, rm=rbp)
        i = 0
        n = len(out)
        while True:
            if fixed >= max_fixed:
                break
            j = out.find(mov_pat, i)
            if j < 0 or j + 7 > n:
                break
            # Extra local guard: in the problematic cmd loop, the store is
            # followed immediately by ``xor eax, eax`` (or its 64-bit form).
            # This greatly reduces accidental matches in unrelated rbp locals.
            after = out[j + 7:j + 10]
            if after not in (b'\x31\xc0', b'\x48\x31\xc0'):
                i = j + 1
                continue
            disp_bytes = out[j + 3:j + 7]
            # Require the matching ``and word [rbp+disp],0`` close by with
            # the same disp32 so we don't touch unrelated rbp stores.
            and_pat = b'\x66\x83\xA5' + disp_bytes + b'\x00'
            k = out.find(and_pat, j + 7, min(n, j + 0x60))
            if k < 0 or k + 8 > n:
                i = j + 1
                continue

            # Patch the mov via cave trampoline.
            cave_mov = self._pure_find_padding_cave(out, 13)
            if cave_mov < 0:
                i = j + 1
                continue
            disp32 = disp_bytes  # reuse original disp32 bytes
            mov_stub = (b'\x66\x89\xB4\x5D' + disp32)  # mov [rbp+rbx*2+disp], si
            back_mov = j + 7
            rel_mov = back_mov - (cave_mov + len(mov_stub) + 5)
            mov_stub += b'\xE9' + struct.pack('<i', rel_mov)
            assert len(mov_stub) == 13
            out[cave_mov:cave_mov + 13] = mov_stub
            rel_to_cave = cave_mov - (j + 5)
            out[j:j + 5] = b'\xE9' + struct.pack('<i', rel_to_cave)
            out[j + 5:j + 7] = b'\x90\x90'
            fixed += 1

            # Patch the and via cave trampoline.
            # "and word [rbp+rbx*2+disp32], 0" encodes to 9 bytes here, plus
            # a 5-byte JMP back => 14-byte trampoline.
            cave_and = self._pure_find_padding_cave(out, 14)
            if cave_and < 0:
                i = k + 1
                continue
            # 66 83 /4 with SIB: ModRM=0xA4 (/4=AND).  0xB4 is /6=XOR, a
            # no-op with imm0 that left the token buffer unterminated.
            and_stub = (b'\x66\x83\xA4\x5D' + disp32 + b'\x00')  # and [...],0
            back_and = k + 8
            rel_and = back_and - (cave_and + len(and_stub) + 5)
            and_stub += b'\xE9' + struct.pack('<i', rel_and)
            assert len(and_stub) == 14
            out[cave_and:cave_and + 14] = and_stub
            rel_to_cave = cave_and - (k + 5)
            out[k:k + 5] = b'\xE9' + struct.pack('<i', rel_to_cave)
            out[k + 5:k + 8] = b'\x90\x90\x90'
            fixed += 1

            i = j + 7
        return fixed

    def _pure_fix_dropped_rbp_disp8_rbx_scaled_and(
            self, out: bytearray) -> int:
        """Restore ``and word [rbp+rbx*2+disp8],0`` when the index was dropped.

        cmd ``0x12fa3`` terminator ``and [ebp+ebx*2-0x1c],0`` becomes
        ``and word [rbp-0x1c],0``, leaving the delimiter buffer unterminated
        past the first slot.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # 66 83 65 disp8 00
        i = 0
        while i < len(out) - 5:
            if out[i:i + 3] != b'\x66\x83\x65' or out[i + 4] != 0x00:
                i += 1
                continue
            disp8 = out[i + 3]
            # Require a nearby ``inc rbx`` so we only touch delimiter-copy
            # loops that use rbx as a wchar index.
            window = bytes(out[max(0, i - 0x80):i])
            if (b'\x48\xff\xc3' not in window
                    and b'\xff\xc3' not in window):
                i += 1
                continue
            cave = self._pure_find_padding_cave(out, 12)
            if cave < 0:
                break
            stub = bytearray(b'\x66\x83\x64\x5D' + bytes([disp8, 0x00]))
            stub += b'\xE9' + struct.pack(
                '<i', (i + 5) - (cave + len(stub) + 5))
            assert len(stub) == 11
            out[cave:cave + 11] = stub
            out[i:i + 5] = b'\xE9' + struct.pack('<i', cave - (i + 5))
            fixed += 1
            i += 5
        return fixed

    def _pure_fix_dropped_ebp8_cursor_adds(
            self, out: bytearray) -> int:
        """Restore ``add dword [ebp+8], 2`` write-cursor advances.

        VC6 tokenizers keep the destination cursor in ``[ebp+8]`` (the
        overwritten arg0 home).  After Win64 translation that slot is
        ``qword [rbp+0x10]``, and the ``add`` immediates are often dropped
        when the surrounding block is rematerialized — the cursor never
        advances, ``realloc`` sees size 4, and the heap corrupts (cmd
        ``0x12fa3`` / pe64 ``0x249e8``).
        """
        if not self._cmd_no_hacks:
            return 0
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = False
        except Exception:
            md = None
        add_q = bytes([0x48, 0x83, 0x45, 0x10, 0x02])
        fixed = 0

        def has_add_near(moff: int) -> bool:
            lo = max(0, moff - 0x30)
            hi = min(len(out), moff + 0x30)
            return add_q in bytes(out[lo:hi])

        def insn_len_at(at: int) -> int:
            if md is None or at >= len(out):
                return 0
            for insn in md.disasm(bytes(out[at:at + 16]), 0):
                return int(insn.size)
            return 0

        i = 0
        while i < len(out) - 12:
            if out[i:i + 4] != b'\x48\x8b\x4d\x10':
                i += 1
                continue
            store = -1
            for k in range(i + 4, min(len(out) - 3, i + 0x28)):
                if out[k:k + 3] == b'\x66\x89\x01':
                    store = k
                    break
                if out[k:k + 4] == b'\x48\x8b\x4d\x10':
                    break
            if store < 0:
                i += 1
                continue
            if has_add_near(store):
                i = store + 3
                continue
            nxt = store + 3
            # Replay store + ADD + following insn(s) in a cave; replace a
            # 5-byte window starting at the store with a near jmp.
            follow_n = insn_len_at(nxt)
            if follow_n <= 0:
                i = store + 3
                continue
            # Need store(3)+follow >= 5 to host the jmp, or follow alone is
            # a near jmp we can retarget.
            cave = self._pure_find_padding_cave(out, 3 + 5 + follow_n + 5)
            if cave < 0:
                break
            if out[nxt] == 0xE9 and follow_n >= 5:
                orig_tgt = nxt + 5 + struct.unpack_from('<i', out, nxt + 1)[0]
                stub = bytearray(add_q)
                stub += b'\xE9' + struct.pack(
                    '<i', orig_tgt - (cave + len(stub) + 5))
                out[cave:cave + len(stub)] = stub
                out[nxt:nxt + 5] = b'\xE9' + struct.pack(
                    '<i', cave - (nxt + 5))
                fixed += 1
            elif (out[nxt:nxt + 4] == b'\x83\x65\xfc\x00'
                  and nxt + 9 <= len(out) and out[nxt + 4] == 0xE9):
                orig_tgt = nxt + 9 + struct.unpack_from('<i', out, nxt + 5)[0]
                stub = bytearray(b'\x83\x65\xfc\x00')
                stub += add_q
                stub += b'\xE9' + struct.pack(
                    '<i', orig_tgt - (cave + len(stub) + 5))
                out[cave:cave + len(stub)] = stub
                out[nxt:nxt + 5] = b'\xE9' + struct.pack(
                    '<i', cave - (nxt + 5))
                out[nxt + 5:nxt + 9] = b'\x90\x90\x90\x90'
                fixed += 1
            elif follow_n >= 2 and store + 5 <= len(out):
                # store + prefix of next insn host the jmp; cave replays both.
                take = 5 - 3  # bytes stolen from follower
                if take > follow_n:
                    i = store + 3
                    continue
                follower = bytes(out[nxt:nxt + follow_n])
                stub = bytearray(b'\x66\x89\x01')
                stub += add_q
                stub += follower
                stub += b'\xE9' + struct.pack(
                    '<i', (nxt + follow_n) - (cave + len(stub) + 5))
                out[cave:cave + len(stub)] = stub
                out[store:store + 5] = b'\xE9' + struct.pack(
                    '<i', cave - (store + 5))
                # If follower longer than 2, nop the remainder after the jmp.
                if follow_n > take:
                    for p in range(store + 5, nxt + follow_n):
                        out[p] = 0x90
                fixed += 1
            i = store + 3

        # Fused fallthrough: cmp; jne L; cmp; jne L; L: mov [rbp-4],1
        j = 0
        while j < len(out) - 0x30:
            if out[j:j + 3] == b'\x39\x45\xf4':
                jcc1 = j + 3
            elif out[j:j + 4] == b'\x83\x7d\xf4\x00':
                jcc1 = j + 4
            else:
                j += 1
                continue
            if (jcc1 + 6 >= len(out) or out[jcc1] != 0x0F
                    or out[jcc1 + 1] not in (0x84, 0x85)):
                j += 1
                continue
            tgt1 = jcc1 + 6 + struct.unpack_from('<i', out, jcc1 + 2)[0]
            jcc2 = jcc1 + 6
            if out[jcc2:jcc2 + 3] == b'\x39\x45\xfc':
                jcc2_at = jcc2 + 3
            elif out[jcc2:jcc2 + 4] == b'\x83\x7d\xfc\x00':
                jcc2_at = jcc2 + 4
            else:
                j += 1
                continue
            if (jcc2_at + 6 > len(out) or out[jcc2_at] != 0x0F
                    or out[jcc2_at + 1] not in (0x84, 0x85)):
                j += 1
                continue
            tgt2 = jcc2_at + 6 + struct.unpack_from(
                '<i', out, jcc2_at + 2)[0]
            if tgt1 != tgt2 or jcc2_at + 6 != tgt1:
                j += 1
                continue
            if out[tgt1:tgt1 + 7] != b'\xc7\x45\xfc\x01\x00\x00\x00':
                j += 1
                continue
            if has_add_near(tgt1):
                j = tgt1 + 7
                continue
            cave_skip = self._pure_find_padding_cave(out, 16)
            cave_add = self._pure_find_padding_cave(out, 20)
            if cave_skip < 0 or cave_add < 0:
                break
            head = bytes(out[tgt1:tgt1 + 7])
            skip_stub = bytearray(head)
            skip_stub += b'\xE9' + struct.pack(
                '<i', (tgt1 + 7) - (cave_skip + len(skip_stub) + 5))
            add_stub = bytearray(add_q)
            add_stub += head
            add_stub += b'\xE9' + struct.pack(
                '<i', (tgt1 + 7) - (cave_add + len(add_stub) + 5))
            out[cave_skip:cave_skip + len(skip_stub)] = skip_stub
            out[cave_add:cave_add + len(add_stub)] = add_stub
            for jsite in (jcc1, jcc2_at):
                struct.pack_into(
                    '<i', out, jsite + 2, cave_skip - (jsite + 6))
            out[tgt1:tgt1 + 5] = b'\xE9' + struct.pack(
                '<i', cave_add - (tgt1 + 5))
            out[tgt1 + 5:tgt1 + 7] = b'\x90\x90'
            fixed += 1
            j = tgt1 + 7
        return fixed

    def _pure_fix_je_far_to_in_function_align_call(
            self, out: bytearray) -> int:
        """Retarget ``cmp [rbp-4],edi; mov rsi,rax; je FAR`` to local join.

        cmd ``f614/f619→f668``: the near ``je`` expands to a far tip that is a
        rematerialized copy of the *fallthrough* arm.  The real join is the
        next Win64 align stub + ``call`` still inside the function.
        """
        if not self._cmd_no_hacks:
            return 0
        sig = bytes.fromhex('397dfc4889c60f84')
        align_stub = bytes.fromhex('41554989e54883ec204883e4f0')
        fixed = 0
        i = 0
        while True:
            j = out.find(sig, i)
            if j < 0 or j + 12 > len(out):
                break
            rel_at = j + 8
            end = j + 12
            cur = end + struct.unpack_from('<i', out, rel_at)[0]
            # Fallthrough should be ``mov eax, [rsi]``.
            if out[end:end + 2] not in (b'\x8b\x06', b'\x8b\x46'):
                i = j + 1
                continue
            if not (0 <= cur < len(out)):
                i = j + 1
                continue
            # Far tip (outside a short local window).
            if abs(cur - end) < 0x80:
                i = j + 1
                continue
            # Real join: align stub + call + restore + ``test eax,eax``
            # (cmd f668).  Do not take the first align+call in the
            # fallthrough arm (e.g. call FreeNode).
            join = None
            k = end
            scan_end = min(len(out) - 24, end + 0x180)
            while k < scan_end:
                if (out[k:k + 13] == align_stub and out[k + 13] == 0xE8
                        and out[k + 18:k + 23] == bytes.fromhex('4c89ec415d')
                        and out[k + 23:k + 25] == b'\x85\xc0'):
                    join = k
                    break
                k += 1
            if join is None or join == cur:
                i = j + 1
                continue
            struct.pack_into('<i', out, rel_at, join - end)
            fixed += 1
            i = end
        return fixed

    def _pure_fix_jmp_wrong_shared_pop_tail(self, out: bytearray) -> int:
        """Retarget ``E9`` jmps that land on the WRONG shared pop-tail.

        cmd ``db13`` (scratch allocator) fail path::

            call <msg wrapper>      ; print ERROR_NOT_ENOUGH_MEMORY
            mov rsp,r13; pop r13
            xor rax,rax
            jmp 0x69048            ; = pop rsi; pop rbx; ret  ← WRONG

        The x86 ``jmp 0xdb56`` targets the allocator's OWN tail (``pop esi;
        ret 4``) but the epilogue materializer collapsed it onto a neighbour
        function's island (``pop esi; pop rbx; ret`` at 0x69048) while the
        real tail (``pop rsi; ret``) sits 0x34 bytes away at 0x19ea6.  The
        extra ``pop rbx`` leaves RSP two slots high: the ``ret`` then pops a
        caller argument as the return address → execute at a wild pointer
        (cmd crashed at ``0xD27D104A`` with RDI = that value << 32).

        Universal rule: for every E9 landing on a ``nop*; pop*; ret`` island,
        compute the pops the ENCLOSING function's prologue expects (its own
        callee-save pushes, reversed).  If the island pops a different list
        and another island with the expected list exists within ±0x200,
        retarget the jump.
        """
        if not self._cmd_no_hacks:
            return 0
        n = len(out)
        fixed = 0

        def _pop_list_at(q: int, hi: int):
            """Parse nop/int3 sled then 1+ pops then ret at q."""
            p = q
            while p < hi and p < q + 8 and out[p] in (0x90, 0xCC, 0x00):
                p += 1
            pops = []
            while p < hi and p < q + 0x18:
                b = out[p]
                if 0x58 <= b <= 0x5F:
                    pops.append(b - 0x58)
                    p += 1
                    continue
                if b == 0x41 and p + 1 < hi and 0x58 <= out[p + 1] <= 0x5F:
                    pops.append(out[p + 1] - 0x50)
                    p += 2
                    continue
                break
            if not pops or p >= hi or out[p] not in (0xC3, 0xC2):
                return None
            return pops

        # Linear-disassemble the whole blob so E9 sites that live outside the
        # rva_map seeds (collapsed fail paths) are still recognized.
        starts = set()
        if HAS_CAPSTONE:
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.skipdata = True
                for ins in md.disasm(bytes(out), 0):
                    starts.add(ins.address)
            except Exception:
                pass
        if not starts:
            return 0
        starts_list = sorted(starts)

        # Pre-scan candidate islands at real instruction starts.
        islands = []
        for q in starts_list:
            lst = _pop_list_at(q, n)
            if lst is not None:
                islands.append((q, lst))
        if not islands:
            return 0

        import bisect
        for i in starts_list:
            if i + 5 > n or out[i] != 0xE9:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if not (0 <= tgt < n):
                continue
            tgt_pops = _pop_list_at(tgt, n)
            if tgt_pops is None:
                continue
            # Enclosing function boundary: nearest preceding ret or prologue.
            j = bisect.bisect_left(starts_list, i) - 1
            boundary = None
            while j >= 0 and i - starts_list[j] < 0x800:
                b = starts_list[j]
                if out[b] in (0xC3, 0xC2) or out[b:b + 2] == b'\x48\x89\xe5':
                    boundary = b
                    break
                j -= 1
            if boundary is None:
                continue
            # Collect this function's callee-save pushes between the boundary
            # and the jmp, using real instruction starts.  Stop at the first
            # call/jmp: callee-save pushes live in the prologue; later pushes
            # are stdcall args balanced by ``add rsp,N``, not by the epilogue.
            # Skip push r13 (align frame) and push rbp.
            saves = []
            k0 = bisect.bisect_right(starts_list, boundary)
            k1 = bisect.bisect_left(starts_list, i)
            for k in starts_list[k0:k1]:
                b = out[k]
                if b in (0xE8, 0xE9, 0xFF):
                    break
                if 0x50 <= b <= 0x57 and b != 0x55:
                    saves.append(b - 0x50)
                    continue
                if (b == 0x41 and k + 1 < i
                        and 0x50 <= out[k + 1] <= 0x57 and out[k + 1] != 0x55):
                    saves.append(out[k + 1] - 0x48)
                    continue
            expected = list(reversed(saves))
            if not expected or tgt_pops == expected:
                continue
            # Find an island within ±0x200 with exactly the expected pops.
            lo = max(0, min(i, tgt) - 0x200)
            hi = min(n, max(i, tgt) + 0x200)
            best = None
            for q, lst in islands:
                if not (lo <= q < hi):
                    continue
                if lst == expected:
                    best = q
                    break
            if best is None:
                # The correct tail may not be nop-prefixed (e.g. cmd db13's
                # own ``pop rsi; ret`` right after ``add eax,8``).  Scan raw
                # bytes for the exact expected pop sequence + ret, then ask
                # that a pad/nop/ret/prologue follows (tail-cluster shape)
                # so imm bytes inside movabs are not picked up.
                pat = bytearray()
                for r in expected:
                    if r < 8:
                        pat.append(0x58 + r)
                    else:
                        pat += bytes([0x41, 0x50 + (r - 8)])
                pat += b'\xc3'
                q = lo
                while q + len(pat) <= hi:
                    q = out.find(bytes(pat), q)
                    if q < 0 or q + len(pat) > hi:
                        break
                    nxt = q + len(pat)
                    if nxt >= hi or out[nxt] in (
                            0x90, 0xCC, 0x00, 0xC3, 0x55):
                        best = q
                        break
                    q += 1
            if best is None:
                continue
            struct.pack_into('<i', out, i + 1, best - (i + 5))
            fixed += 1
        return fixed

    def _pure_fix_volatile_rdi_node_across_calls(self, out: bytearray) -> int:
        """Keep heap-node pointers in R12, not volatile RDI, across calls.

        x86 holds the node in callee-saved EDI through wcschr / lstrcmpW.
        Translation leaves it in RDI; Win64 callees clobber it.

        Also finishes *partial* conversions: after the epilogue becomes an
        ``E9``→``pop r12`` trampoline (or caves ran out mid-pass), leftover
        ``cmp edi`` / ``mov ecx,[rdi+0x38]`` / ``push rdi`` must still be
        rewritten or Dispatch sees a null node (cmd ``0x189e8``).
        """
        if not self._cmd_no_hacks:
            return 0

        def _jcc_target(site, insn):
            disp = struct.unpack_from('<i', insn, 2)[0]
            return site + len(insn) + disp

        def _emit_jcc(op, abs_target, at):
            return op + struct.pack('<i', abs_target - (at + 6))

        def _install(site, nbytes, stub):
            cave = self._pure_find_padding_cave(out, len(stub))
            if cave < 0 or nbytes < 5:
                return False
            out[cave:cave + len(stub)] = stub
            out[site:site + nbytes] = (
                b'\xE9' + struct.pack('<i', cave - (site + 5))
                + b'\x90' * (nbytes - 5))
            return True

        def _install_build(site, nbytes, size_hint, build):
            cave = self._pure_find_padding_cave(out, size_hint)
            if cave < 0 or nbytes < 5:
                return False
            stub = build(cave)
            if len(stub) > size_hint:
                return False
            out[cave:cave + len(stub)] = stub
            out[site:site + nbytes] = (
                b'\xE9' + struct.pack('<i', cave - (site + 5))
                + b'\x90' * (nbytes - 5))
            return True

        def _epi_is_pop_r12(site: int) -> bool:
            if out[site:site + 6] == b'\x41\x5c\x5e\x5d\x5b\xc3':
                return True
            if out[site] != 0xE9 or site + 5 > len(out):
                return False
            dest = site + 5 + struct.unpack_from('<i', out, site + 1)[0]
            return (0 <= dest < len(out) - 5
                    and out[dest:dest + 6] == b'\x41\x5c\x5e\x5d\x5b\xc3')

        def _find_frame_end(start: int) -> int:
            """Return epilogue site (pop rdi or E9→pop r12), or -1."""
            for j in range(start + 1, min(len(out), start + 0x600)):
                if (out[j] == 0x5F and j + 4 < len(out)
                        and out[j + 1:j + 5] == b'\x5e\x5d\x5b\xc3'):
                    return j
                if out[j] == 0xE9 and _epi_is_pop_r12(j):
                    return j
                # Another push-rdi that starts a sibling frame.
                if (out[j] == 0x57 and j + 2 < len(out)
                        and out[j + 1:j + 3] == b'\x39\xde'):
                    break
            return -1

        def _patch_rdi_uses(lo: int, end: int) -> int:
            """Rewrite remaining EDI/RDI node uses in ``[lo, end)``."""
            nfix = 0
            # xor rbx; push rdi; cmp ebx,esi; je  → push r12
            pro = lo
            if (pro >= 0 and out[pro:pro + 3] == b'\x48\x31\xdb'
                    and out[pro + 3:pro + 6] == b'\x57\x39\xde'
                    and out[pro + 6:pro + 8] == b'\x0f\x84'):
                jcc_site = pro + 6
                jcc = bytes(out[jcc_site:jcc_site + 6])
                target = _jcc_target(jcc_site, jcc)
                fall = jcc_site + 6

                def _build_pro(cave, _t=target, _f=fall):
                    stub = bytearray()
                    stub += b'\x48\x31\xdb'
                    stub += b'\x41\x54'
                    stub += b'\x39\xde'
                    stub += _emit_jcc(b'\x0f\x84', _t, cave + len(stub))
                    stub += b'\xE9' + struct.pack(
                        '<i', _f - (cave + len(stub) + 5))
                    return bytes(stub)

                if _install_build(pro, fall - pro, 20, _build_pro):
                    nfix += 1

            k = lo
            while k < end - 5:
                if out[k:k + 5] == b'\x48\x89\xc7\x85\xff':
                    def _b(cave, _k=k):
                        stub = bytearray(b'\x49\x89\xc4\x45\x85\xe4')
                        stub += b'\xE9' + struct.pack(
                            '<i', (_k + 5) - (cave + len(stub) + 5))
                        return bytes(stub)
                    if _install_build(k, 5, 16, _b):
                        nfix += 1
                    k += 5
                    continue
                if out[k:k + 5] == b'\x48\x89\xc7\x39\xdf':
                    def _b2(cave, _k=k):
                        stub = bytearray(b'\x49\x89\xc4\x41\x39\xdc')
                        stub += b'\xE9' + struct.pack(
                            '<i', (_k + 5) - (cave + len(stub) + 5))
                        return bytes(stub)
                    if _install_build(k, 5, 16, _b2):
                        nfix += 1
                    k += 5
                    continue
                k += 1

            k = lo
            while k < end - 3:
                if out[k:k + 3] == b'\x48\x89\xc7':
                    out[k:k + 3] = b'\x49\x89\xc4'
                    nfix += 1
                k += 1

            k = lo
            while k < end - 3:
                if out[k:k + 3] == b'\x48\x89\xf9':
                    out[k:k + 3] = b'\x4c\x89\xe1'
                    nfix += 1
                k += 1

            k = lo
            while k < end - 12:
                if out[k] == 0xE9:
                    k += 1
                    continue
                if (out[k:k + 2] == b'\x39\xdf'
                        and out[k + 2:k + 4] == b'\x49\xbb'):
                    fol = bytes(out[k + 2:k + 12])

                    def _b3(cave, _fol=fol, _k=k):
                        stub = bytearray(b'\x41\x39\xdc') + _fol
                        stub += b'\xE9' + struct.pack(
                            '<i', (_k + 12) - (cave + len(stub) + 5))
                        return bytes(stub)

                    if _install_build(k, 12, 20, _b3):
                        nfix += 1
                        k += 12
                        continue
                k += 1

            k = lo
            while k < end - 8:
                if out[k] == 0xE9:
                    k += 1
                    continue
                pair = None
                if out[k:k + 2] == b'\x39\xdf':
                    pair = (b'\x41\x39\xdc', 2)
                elif out[k:k + 2] == b'\x85\xff':
                    pair = (b'\x45\x85\xe4', 2)
                elif out[k:k + 3] == b'\x83\xff\xff':
                    pair = (b'\x41\x83\xfc\xff', 3)
                if pair and out[k + pair[1]:k + pair[1] + 2] in (
                        b'\x0f\x84', b'\x0f\x85'):
                    old_len = pair[1]
                    jcc_site = k + old_len
                    jcc = bytes(out[jcc_site:jcc_site + 6])
                    target = _jcc_target(jcc_site, jcc)
                    fall = jcc_site + 6
                    new_cmp = pair[0]
                    op = jcc[:2]

                    def _b4(cave, _nc=new_cmp, _op=op, _t=target, _f=fall):
                        stub = bytearray(_nc)
                        stub += _emit_jcc(_op, _t, cave + len(stub))
                        stub += b'\xE9' + struct.pack(
                            '<i', _f - (cave + len(stub) + 5))
                        return bytes(stub)

                    if _install_build(k, fall - k, 20, _b4):
                        nfix += 1
                        k = fall
                        continue
                k += 1

            k = lo
            while k < end - 7:
                if out[k:k + 3] != b'\x8b\x4f\x38' or out[k] == 0xE9:
                    k += 1
                    continue
                if out[k + 3:k + 7] == b'\x66\x83\x39\x3a':
                    def _b5(cave, _k=k):
                        stub = bytearray(
                            b'\x41\x8b\x4c\x24\x38\x66\x83\x39\x3a')
                        stub += b'\xE9' + struct.pack(
                            '<i', (_k + 7) - (cave + len(stub) + 5))
                        return bytes(stub)
                    if _install_build(k, 7, 20, _b5):
                        nfix += 1
                        k += 7
                        continue
                if out[k + 3:k + 6] == b'\x48\xc7\xc2':
                    fol = bytes(out[k + 3:k + 10])

                    def _b6(cave, _fol=fol, _k=k):
                        stub = bytearray(b'\x41\x8b\x4c\x24\x38') + _fol
                        stub += b'\xE9' + struct.pack(
                            '<i', (_k + 10) - (cave + len(stub) + 5))
                        return bytes(stub)

                    if _install_build(k, 10, 20, _b6):
                        nfix += 1
                        k += 10
                        continue
                k += 1
            return nfix

        fixed = 0
        i = 0
        while i < len(out) - 8:
            if out[i] != 0x57:
                i += 1
                continue
            pop_at = _find_frame_end(i)
            if pop_at < 0:
                i += 1
                continue
            window = bytes(out[i:pop_at + 5])
            # Fresh frame: park still in RDI. Residual: already parked in R12.
            fresh = (b'\x8b\x4f\x38' in window
                     and b'\x48\x89\xc7' in window)
            residual = (
                (b'\x49\x89\xc4' in window or b'\x4c\x89\xe1' in window)
                and (b'\x8b\x4f\x38' in window
                     or b'\x39\xdf' in window
                     or b'\x83\xff\xff' in window
                     or b'\x85\xff' in window
                     or out[i:i + 3] == b'\x57\x39\xde'
                     or (i >= 3 and out[i - 3:i + 3] == b'\x48\x31\xdb\x57\x39\xde')))
            if not fresh and not residual:
                i += 1
                continue

            end = pop_at + 5
            lo = i - 3 if (i >= 3 and out[i - 3:i] == b'\x48\x31\xdb') else i
            fixed += _patch_rdi_uses(lo, end)

            if out[pop_at:pop_at + 5] == b'\x5f\x5e\x5d\x5b\xc3':
                if _install(pop_at, 5, b'\x41\x5c\x5e\x5d\x5b\xc3'):
                    fixed += 1

            i = pop_at + 5

        # Whole-text residual: frames whose push-rdi was already rewritten
        # (no leading 0x57) but cmp/load sites still use EDI/RDI.
        k = 0
        while k < len(out) - 12:
            hit = -1
            span = 0
            if (out[k:k + 2] == b'\x39\xdf'
                    and out[k + 2:k + 4] == b'\x49\xbb'):
                hit, span = k, 12
            elif out[k:k + 3] == b'\x83\xff\xff' and out[k + 3:k + 5] in (
                    b'\x0f\x84', b'\x0f\x85'):
                hit, span = k, 9
            elif out[k:k + 3] == b'\x8b\x4f\x38' and out[k + 3:k + 6] == b'\x48\xc7\xc2':
                hit, span = k, 10
            elif out[k:k + 3] == b'\x8b\x4f\x38' and out[k + 3:k + 7] == b'\x66\x83\x39\x3a':
                hit, span = k, 7
            if hit < 0:
                k += 1
                continue
            lo = max(0, hit - 0x800)
            hi = min(len(out), hit + 0x400)
            win = bytes(out[lo:hi])
            if b'\x49\x89\xc4' not in win and b'\x4c\x89\xe1' not in win:
                k += 1
                continue
            fixed += _patch_rdi_uses(hit, hit + span + 1)
            k = hit + max(span, 1)
        return fixed
    def _pure_fix_nested_call_return_clobbers_rax_arg(
            self, out: bytearray) -> int:
        """Preserve RAX-held args across a nested call that supplies arg0.

        x86 pushes all args, then calls a helper whose return becomes the
        first arg::

            lea eax, [size]; push eax; push mem; push 0
            call GetProcessHeap ; -> eax
            push eax; call HeapAlloc

        Translation materializes the Win64 arg registers *after* the nested
        call, so a size still living in RAX is overwritten by that call's
        return value and the same handle is passed twice::

            lea rax, [rax + rcx + 0x20]
            <align stub>; call GetProcessHeap; <restore>
            mov rcx, rax        ; heap  (correct)
            mov rdx, 8
            mov r8, rax         ; size  — now the heap handle

        RAX and every arg register are volatile, so the pre-call value is
        parked on the stack: a detour over the align stub's ``push r13``
        pushes RAX first, and the bogus ``mov r8/r9/rdx, rax`` becomes the
        matching ``pop``.  Both edits are length-neutral, so no branch
        target moves (cmd echo ``28b1e`` HeapReAlloc and ``cadd`` HeapAlloc).
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rsp, r13; pop r13; mov rcx, rax
        sig = bytes([0x4C, 0x89, 0xEC, 0x41, 0x5D, 0x48, 0x89, 0xC1])
        stub_head = bytes([0x41, 0x55, 0x49, 0x89, 0xE5])  # push r13; mov r13,rsp
        stub_tail = bytes([0x48, 0x83, 0xEC])              # sub rsp, imm8
        # mov <reg>, rax → matching pop
        rax_args = {
            bytes([0x49, 0x89, 0xC0]): bytes([0x41, 0x58, 0x90]),  # r8  → pop r8
            bytes([0x49, 0x89, 0xC1]): bytes([0x41, 0x59, 0x90]),  # r9  → pop r9
            bytes([0x48, 0x89, 0xC2]): bytes([0x5A, 0x90, 0x90]),  # rdx → pop rdx
        }
        i = 0
        while True:
            at = out.find(sig, i)
            if at < 0:
                break
            i = at + 1
            # Locate the align stub this restore belongs to.
            stub = out.rfind(stub_head, max(0, at - 0x60), at)
            if stub < 0 or out[stub + 5:stub + 8] != stub_tail:
                continue
            # Exactly one call between the stub and the restore.
            span = bytes(out[stub + 8:at])
            n_call = (span.count(bytes([0xFF, 0xD0])) + span.count(bytes([0x41, 0xFF, 0xD7]))
                      + span.count(bytes([0x41, 0xFF, 0xD6])) + span.count(bytes([0x41, 0xFF, 0xD5]))
                      + span.count(bytes([0xFF, 0xD3])) + span.count(bytes([0xE8])))
            if n_call != 1:
                continue
            # Scan the arg block after ``mov rcx, rax`` for a RAX-sourced arg.
            p = at + len(sig)
            hit = -1
            hit_key = b''
            while p < min(len(out), at + len(sig) + 0x20):
                three = bytes(out[p:p + 3])
                if three in rax_args:
                    if hit >= 0:
                        hit = -1  # two RAX args: one stack slot is not enough
                        break
                    hit = p
                    hit_key = three
                    p += 3
                    continue
                if out[p:p + 3] == bytes([0x48, 0xC7, 0xC2]):  # mov rdx, imm32
                    p += 7
                    continue
                if three[:2] in (bytes([0x49, 0x89]), bytes([0x48, 0x89])):
                    p += 3
                    continue
                break
            if hit < 0:
                continue
            # Detour the stub head through a cave that parks RAX first.
            cave = self._pure_find_padding_cave(out, 12)
            if cave < 0:
                continue
            body = bytearray()
            body += bytes([0x50])          # push rax
            body += stub_head              # push r13; mov r13, rsp
            back = stub + 5
            body += bytes([0xE9]) + struct.pack('<i', back - (cave + len(body) + 5))
            out[cave:cave + len(body)] = body
            out[stub:stub + 5] = (bytes([0xE9])
                                  + struct.pack('<i', cave - (stub + 5)))
            out[hit:hit + 3] = rax_args[hit_key]
            fixed += 1
        return fixed

    def _pure_fix_branch_targets_from_x86_map(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Re-derive every branch target from the original x86 instruction.

        Long argument blocks let the emitter reuse a stale callee: cmd's
        print call (x86 ``7132`` → ``7244``) came out as a call to the
        allocator ``19dc4`` (x86 ``db13``, the *first* call of the same
        function), and a ``je`` skipped past an IAT materialization so the
        following ``call rbx`` ran a heap buffer.

        For each mapped x86 branch, recompute the intended PE64 target from
        ``rva_map``.  A mismatch is only repaired when the current target is
        itself a mapped x86 location — targets pointing at heal-built stubs
        and caves (EF42 guard, FormatMessage fallback, IAT thunks) are never
        in the map and so stay untouched.
        """
        if not self._cmd_no_hacks or not rva_map or not text_data:
            return 0
        n = len(out)
        # PE64 values are RVAs when they run past the blob; else blob offsets.
        as_rva = max(rva_map.values()) >= n
        def to_off(pe64: int) -> int:
            return pe64 - text_rva if as_rva else pe64
        def to_pe64(off: int) -> int:
            return off + text_rva if as_rva else off
        mapped = set(rva_map.values())
        fixed = 0
        for x_rva, pe64 in rva_map.items():
            xo = x_rva - text_rva
            if xo < 0 or xo + 6 > len(text_data):
                continue
            op = text_data[xo]
            if op in (0xE8, 0xE9):
                x_tgt = x_rva + 5 + struct.unpack_from('<i', text_data, xo + 1)[0]
                want = (op, None)
            elif op == 0xEB:
                x_tgt = x_rva + 2 + struct.unpack_from('<b', text_data, xo + 1)[0]
                want = (0xE9, None)
            elif op == 0x0F and 0x80 <= text_data[xo + 1] <= 0x8F:
                x_tgt = x_rva + 6 + struct.unpack_from('<i', text_data, xo + 2)[0]
                want = (0x0F, text_data[xo + 1])
            elif 0x70 <= op <= 0x7F:
                x_tgt = x_rva + 2 + struct.unpack_from('<b', text_data, xo + 1)[0]
                want = (0x0F, 0x80 + (op - 0x70))
            else:
                continue
            exp = rva_map.get(x_tgt)
            if exp is None:
                continue
            off = to_off(pe64)
            if off < 0 or off + 6 > n:
                continue
            if want[1] is None:
                if out[off] != want[0]:
                    continue
                rel_at, end = off + 1, off + 5
            elif out[off] == 0x0F and out[off + 1] == want[1]:
                rel_at, end = off + 2, off + 6
            elif out[off] == 0x70 + (want[1] - 0x80):
                rel_at, end = off + 1, off + 2  # short form kept by the emitter
            else:
                continue
            if end + 4 > n:
                continue
            if end - rel_at == 1:
                cur = end + struct.unpack_from('<b', out, rel_at)[0]
            else:
                cur = end + struct.unpack_from('<i', out, rel_at)[0]
            if not (0 <= cur < n) or to_pe64(cur) == exp:
                continue
            if to_pe64(cur) not in mapped:
                continue  # deliberate heal detour — leave it alone
            new_off = to_off(exp)
            if not (0 <= new_off < n):
                continue
            disp = new_off - end
            if end - rel_at == 1:
                if not (-128 <= disp <= 127):
                    continue
                struct.pack_into('<b', out, rel_at, disp)
            else:
                struct.pack_into('<i', out, rel_at, disp)
            fixed += 1
        return fixed

    def _pure_fix_call_into_epilogue_before_prologue(
            self, out: bytearray) -> int:
        """Retarget ``call`` that lands on the previous function's epilogue.

        Expansion can leave the mapped entry of the next x86 function (e.g.
        cmd ``14ce5`` → pe64 ``28a0c``) eight bytes late while callers still
        use the pre-prologue epilogue tip (``28a04``)::

            mov rax, rbp; pop rdi; pop rsi; pop rbp; pop rbx; ret
            mov qword ptr [rsp+8], rcx   ; real entry

        Calling the epilogue pops the align-stub frame and ``ret``s to NULL.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        epi = bytes([0x48, 0x89, 0xE8, 0x5F, 0x5E, 0x5D, 0x5B, 0xC3])
        home = bytes([0x48, 0x89, 0x4C, 0x24, 0x08])
        i = 0
        n = len(out)
        while i < n - 5:
            if out[i] != 0xE8:
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if (0 <= tgt <= n - 13
                    and out[tgt:tgt + 8] == epi
                    and out[tgt + 8:tgt + 13] == home):
                new_tgt = tgt + 8
                struct.pack_into('<i', out, i + 1, new_tgt - (i + 5))
                fixed += 1
                i += 5
                continue
            i += 1
        return fixed



    def _pure_iat_va(self, *names: str, fallback_rva: int = 0) -> int:
        """Resolve an import cell VA by API name (case-insensitive)."""
        nb = int(getattr(self, "new_base", 0) or 0)
        name_map = getattr(self, "_iat_name_to_new_rva", None) or {}
        want = {n.lower() for n in names}
        for (_dll, fn), rva in name_map.items():
            if str(fn).lower() in want:
                return nb + int(rva)
        return (nb + fallback_rva) if fallback_rva else 0

    def _pure_fix_exitprocess_wrapper_via_terminate(self, out: bytearray) -> int:
        """Restore shredded ExitProcess wrappers using TerminateProcess.

        x86 ``AC92`` ends with ``call [ExitProcess]``, but PE64 often drops
        ExitProcess from the IAT and leaves the translated wrapper as::

            <homes>; mov rcx, 0; ret

        so ``/c`` teardown returns into the interactive waiter.  Rewrite to
        ``TerminateProcess(GetCurrentProcess(), code)`` via the existing
        TerminateProcess IAT cell (HANDLE -1 == current process).
        """
        if not self._cmd_no_hacks:
            return 0
        iat = self._pure_iat_va("terminateprocess", fallback_rva=0x845E0)
        if not iat:
            return 0
        dead = bytes.fromhex(
            "48894c240848895424104c894424184c894c2420"  # homes
            "48c7c100000000"  # mov rcx, 0
            "c3"  # ret
        )
        # mov edx, ecx; mov rcx, -1; movabs rax, iat; mov rax,[rax]; jmp rax
        stub = bytearray()
        stub += b"\x89\xca"  # mov edx, ecx
        stub += b"\x48\xc7\xc1\xff\xff\xff\xff"  # mov rcx, -1
        stub += b"\x48\xb8" + struct.pack("<Q", iat)
        stub += b"\x48\x8b\x00"  # mov rax, [rax]
        stub += b"\xff\xe0"  # jmp rax
        if len(stub) > len(dead):
            return 0
        stub.extend(b"\x90" * (len(dead) - len(stub)))
        fixed = 0
        i = 0
        while True:
            at = out.find(dead, i)
            if at < 0:
                break
            i = at + 1
            # Shredded AC92 leaves a run of ``ret`` padding; plain
            # ``return 0`` thunks do not.
            if at + len(dead) + 8 > len(out):
                continue
            if any(b != 0xC3 for b in out[at + len(dead):at + len(dead) + 8]):
                continue
            # Must be a real call target (not a false mid-insn hit).
            callers = 0
            for off in range(max(0, at - 0x8000), min(len(out) - 5, at + 0x8000)):
                if out[off] != 0xE8:
                    continue
                rel = struct.unpack_from('<i', out, off + 1)[0]
                if off + 5 + rel == at:
                    callers += 1
            if callers < 3:
                continue
            out[at:at + len(dead)] = stub
            fixed += 1
            i = at + len(dead)
        return fixed

    def _pure_fix_stale_getlasterror_exitprocess1(self, out: bytearray) -> int:
        """Skip ``GetLastError → ExitProcess(1)`` when LastError is stale.

        CheckSwitches (and similar) do::

            call GetLastError
            mov [rbp-4], eax
            cmp dword [rbp-4], 0
            je skip
            mov rcx, 1
            call ExitProcess_wrapper

        On PE64, earlier failed Win2000-era APIs leave a non-zero LastError so
        this fires during init and kills ``/c`` before the command runs.
        Force the ``je`` to an unconditional jump onto the skip path.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        mov_rcx1 = bytes.fromhex("48c7c101000000")
        i = 0
        while True:
            # cmp dword [rbp-4], 0
            at = out.find(bytes.fromhex("837dfc00"), i)
            if at < 0:
                break
            i = at + 1
            if at + 17 > len(out):
                continue
            # je rel32
            if out[at + 4] != 0x0F or out[at + 5] != 0x84:
                continue
            # mov rcx, 1 immediately after the jcc
            if out[at + 10:at + 17] != mov_rcx1:
                continue
            rel = struct.unpack_from("<i", out, at + 6)[0]
            target = at + 10 + rel
            # je → jmp near (rel adjusts by +1); trailing nop
            new_rel = target - (at + 4 + 5)
            out[at + 4] = 0xE9
            struct.pack_into("<i", out, at + 5, new_rel)
            out[at + 9] = 0x90
            fixed += 1
            i = at + 17
        return fixed

    def _pure_fix_peb_c_sticky_done_on_zero_ret_epi(self, out: bytearray) -> int:
        """Mark PEB-/c sticky done (1->2) on builtin success epilogues.

        After ``/c`` via PEB seed, sticky stays 1 and the interactive lexer
        spins (``fae0 == 0x0A``).  Builtin success often ends with::

            pop rdi; xor rax, rax; pop rsi; ret

        When sticky == 1, bump it to 2 so the lexer entry heal can exit.
        Interactive (sticky == 0) is unchanged.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, "new_base", 0) or 0)
        if not nb:
            return 0
        sticky = nb + 0x5BE00
        for k in range(len(out) - 12):
            if out[k:k + 2] != b"\x49\xbb":
                continue
            v = struct.unpack_from("<Q", out, k + 2)[0]
            if (v & 0xFFFF) == 0xBE00 and (nb + 0x58000) <= v < (nb + 0x66000):
                sticky = v
                break
        epi = bytes.fromhex("5f4831c05ec3")
        fixed = 0
        sites = []
        i = 0
        while True:
            at = out.find(epi, i)
            if at < 0:
                break
            is_join = False
            for j in range(max(0, at - 0x120), at - 4):
                if out[j] == 0xE9:
                    rel = struct.unpack_from("<i", out, j + 1)[0]
                    if j + 5 + rel == at:
                        is_join = True
                        break
                if out[j] == 0x0F and j + 5 < at and 0x80 <= out[j + 1] <= 0x8F:
                    rel = struct.unpack_from("<i", out, j + 2)[0]
                    if j + 6 + rel == at:
                        is_join = True
                        break
            if is_join:
                sites.append(at)
            i = at + 1
        for at in sites:
            stub = bytearray()
            stub += b"\x49\xbb" + struct.pack("<Q", sticky)
            stub += b"\x41\x83\x3b\x01"              # cmp dword [r11], 1
            stub += b"\x75\x07"                      # jne keep
            stub += b"\x41\xc7\x03\x02\x00\x00\x00"  # sticky = 2
            stub += epi                             # keep (ends in ret)
            cave = self._pure_find_padding_cave(out, len(stub) + 4)
            if cave < 0:
                cave = len(out)
                out.extend(b"\x00" * (len(stub) + 8))
            out[cave:cave + len(stub)] = stub
            out[at:at + 6] = (
                b"\xe9" + struct.pack("<i", cave - (at + 5)) + b"\x90")
            fixed += 1
        return fixed

    def _pure_fix_peb_c_lexer_exits_when_sticky_done(self, out: bytearray) -> int:
        """TerminateProcess(0) at the interactive lexer when sticky >= 2.

        The PEB-/c seed sets sticky=1; success-epi heal bumps it to 2 after
        the command.  The lexer (homes then ``fae0``/``fae4`` loads) then
        exits instead of spinning on a leftover ``0x0A`` token.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, "new_base", 0) or 0)
        if not nb:
            return 0
        term_iat = self._pure_iat_va("terminateprocess", fallback_rva=0x845E0)
        if not term_iat:
            return 0
        sticky = nb + 0x5BE00
        for k in range(len(out) - 12):
            if out[k:k + 2] != b"\x49\xbb":
                continue
            v = struct.unpack_from("<Q", out, k + 2)[0]
            if (v & 0xFFFF) == 0xBE00 and (nb + 0x58000) <= v < (nb + 0x66000):
                sticky = v
                break
        homes = bytes.fromhex("48894c240848895424104c894424184c894c2420")
        fixed = 0
        sites = []
        i = 0
        while True:
            at = out.find(homes, i)
            if at < 0:
                break
            window = out[at + len(homes):at + len(homes) + 0x30]
            hit = False
            for k in range(len(window) - 10):
                if window[k:k + 2] != b"\x49\xbb":
                    continue
                v = struct.unpack_from("<Q", window, k + 2)[0]
                if (v & 0xFFFF) in (0xBAE0, 0xBAE4):
                    hit = True
                    break
            if hit:
                sites.append(at)
            i = at + 1
        for at in sites:
            stub = bytearray()
            stub += b"\x49\xbb" + struct.pack("<Q", sticky)
            stub += b"\x41\x83\x3b\x02"          # cmp dword [r11], 2
            stub += b"\x72\x18"                  # jb keep (sticky < 2)
            stub += b"\x31\xd2"
            stub += b"\x48\xc7\xc1\xff\xff\xff\xff"
            stub += b"\x48\xb8" + struct.pack("<Q", term_iat)
            stub += b"\x48\x8b\x00"
            stub += b"\xff\xe0"
            stub += homes
            stub += b"\xe9" + struct.pack("<i", 0)
            cave = self._pure_find_padding_cave(out, len(stub) + 4)
            if cave < 0:
                cave = len(out)
                out.extend(b"\x00" * (len(stub) + 8))
            fall = at + len(homes)
            struct.pack_into(
                "<i", stub, len(stub) - 4, fall - (cave + len(stub)))
            out[cave:cave + len(stub)] = stub
            repl = bytearray(
                b"\xe9" + struct.pack("<i", cave - (at + 5)))
            repl.extend(b"\x90" * (len(homes) - 5))
            out[at:at + len(homes)] = repl
            fixed += 1
        return fixed

    def _pure_fix_infinite_wait_iat_to_waitforsingleobject(
            self, out: bytearray) -> int:
        """Retired: x86 interactive wait is ``longjmp(jmp_buf,-1)``, not WFS.

        cmd ``f018``: ``push -1; push fb40; call [longjmp]`` after
        ``setjmp(fb40)``.  Retargeting that IAT slot to WaitForSingleObject
        kept the pointer argument (jmp_buf address) so WFS returned
        immediately and the post-wait lexer re-entered until stack overflow.
        Leave the longjmp cell alone; setjmp/longjmp must work instead.
        """
        return 0

    def _pure_fix_epilogue_swallowed_into_prior_insn(self, out: bytearray) -> int:
        """Restore PE64 insn tails overwritten by slid frameless epilogues.

        Universal formula (no RVA hardcodes): when ``pop rdi; pop rsi;
        pop rbx; ret`` (``5F 5E 5B C3``) or the 2-pop form (``5F 5E C3``)
        has been written *backwards* over a preceding instruction and the
        original slot filled with NOPs, rebuild the prior insn:

        1. Align-stub ``and rsp,-16; call rax; mov rsp,r13; pop r13`` —
           corrupt ``48 83 E4 5F 5E 5B C3`` + nops.
        2. ``movabs r11, VA; mov [r11], bl`` — corrupt
           ``49 BB lo lo lo 5F 5E 5B C3`` + nops (VA hi rebuilt from
           ``new_base``).
        3. ``xor rax,rax`` before a 2-pop epi — corrupt
           ``48 31 5F 5E C3`` + nops (restored as
           ``xor rax,rax; jmp $+0; mov eax,esi; pop rdi; pop rsi; ret``
           when the nop pad matches that width).
        4. Align-stub ``and rsp,-16; call rel32`` then leave-epi —
           corrupt ``…E8.. 5F 5E 5B C9 C3`` + nops (restored as
           ``mov rsp,r13; pop r13; xor rax,rax; pop/leave/ret``).
        5. Mid-REX ``pop r13`` tip — corrupt ``4C 89 EC 41 5F 5E 5B C9 C3``
           + nops (restored as ``mov rsp,r13; pop r13; mov eax,1;
           pop/leave/ret`` when the nop pad fits that width).

        Root cause is guarded in :meth:`_epilogue_inplace_slot_safe`; this
        pass is the safety net for already-emitted damage.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        new_base = int(getattr(self, 'new_base', 0) or 0) & 0xFFFFFFFFFFFFFFFF

        # (1) and rsp,imm8 swallowed by 3-pop epi
        sig1 = bytes([0x48, 0x83, 0xE4, 0x5F, 0x5E, 0x5B, 0xC3])
        good1 = bytes.fromhex('4883e4f0ffd04c89ec415d5f5e5bc3')  # 15 bytes
        i = 0
        while i + 16 <= len(out):
            j = out.find(sig1, i)
            if j < 0:
                break
            # Prefer sites that still have NOP padding where the call/restore was.
            pad = out[j + 7:j + 16]
            if pad.count(0x90) >= 6 and (
                    j >= 4 and out[j - 4:j] == bytes([0x48, 0x83, 0xEC, 0x20])):
                out[j:j + 15] = good1
                if j + 15 < len(out) and out[j + 15] == 0x90:
                    pass  # keep trailing nop
                elif j + 15 < len(out):
                    out[j + 15] = 0x90
                fixed += 1
                i = j + 15
            else:
                i = j + 1

        # (2) movabs r11 imm swallowed by 3-pop epi
        i = 0
        while i + 18 <= len(out):
            if (out[i] == 0x49 and out[i + 1] == 0xBB
                    and out[i + 5:i + 9] == bytes([0x5F, 0x5E, 0x5B, 0xC3])
                    and out[i + 9:i + 18].count(0x90) >= 6):
                lo24 = out[i + 2] | (out[i + 3] << 8) | (out[i + 4] << 16)
                if new_base:
                    va = (new_base & 0xFFFFFFFF00000000) | (
                        (new_base & 0xFFFFFFFF) & 0xFF000000) | lo24
                else:
                    va = 0x80000000 | lo24
                good2 = (
                    bytes([0x49, 0xBB]) + struct.pack('<Q', va)
                    + bytes([0x41, 0x88, 0x1B, 0x5F, 0x5E, 0x5B, 0xC3, 0x90])
                )
                out[i:i + 18] = good2
                fixed += 1
                i += 18
            else:
                i += 1

        # (3) xor rax,rax swallowed by 2-pop epi
        sig3 = bytes([0x48, 0x31, 0x5F, 0x5E, 0xC3])
        good3 = bytes.fromhex('4831c0e90000000089f05f5ec390')  # 14 bytes
        i = 0
        while i + 14 <= len(out):
            j = out.find(sig3, i)
            if j < 0:
                break
            pad = out[j + 5:j + 14]
            if pad.count(0x90) >= 6:
                out[j:j + 14] = good3
                fixed += 1
                i = j + 14
            else:
                i = j + 1

        # (4) align ``and rsp,-16; call rel32`` then leave-epi swallowed the
        # restore (+ optional ``xor rax,rax``).  Keeps ``pop rdi`` at the
        # same absolute offset so intra-fn jmps onto the leave-tail still hit.
        leave5 = bytes([0x5F, 0x5E, 0x5B, 0xC9, 0xC3])
        good4 = bytes.fromhex('4c89ec415d4831c05f5e5bc9c3')  # 13 bytes
        i = 0
        while i + 24 <= len(out):
            if (out[i:i + 4] == bytes([0x48, 0x83, 0xE4, 0xF0])
                    and out[i + 4] == 0xE8
                    and out[i + 9:i + 14] == leave5):
                pad = out[i + 14:i + 14 + 12]
                if pad.count(0x90) >= 8:
                    out[i + 9:i + 9 + 13] = good4
                    fixed += 1
                    i = i + 9 + 13
                    continue
            i += 1

        # (4b) ``call rax`` after align/movabs IAT: ``pop rsi; ret`` swallowed
        # ``mov rsp,r13; pop r13; and [rsi],0``.  Early-exit labels that tip
        # onto the old ``pop rsi`` then fall into the next function and
        # recurse until stack overflow (univ261 ``0x19A7B`` / ``0x19A10``).
        good4b = bytes.fromhex('4c89ec415d8326005ec3')  # 10 bytes
        sig4b = bytes([0xFF, 0xD0, 0x5E, 0xC3])
        i = 0
        while i + 24 <= len(out):
            j = out.find(sig4b, i)
            if j < 0:
                break
            pad = out[j + 4:j + 4 + 12]
            # Require align-stub prologue nearby and a ``lea rsi,[rax*4+…]``
            # (heap-slot clear) so we do not invent ``and [rsi],0`` blindly.
            window = bytes(out[max(0, j - 0x60):j])
            if (pad.count(0x90) >= 6
                    and bytes([0x48, 0x83, 0xE4, 0xF0]) in window
                    and bytes([0x41, 0x55]) in window
                    and bytes([0x48, 0x8D, 0x34, 0x85]) in window):
                out[j + 2:j + 2 + len(good4b)] = good4b
                fixed += 1
                i = j + 2 + len(good4b)
            else:
                i = j + 1

        # (5) tip on 2nd byte of ``pop r13`` → ``41 5F 5E 5B C9 C3`` after
        # ``mov rsp,r13``, swallowing ``mov eax,1`` (common BOOL return).
        good5 = bytes.fromhex('4c89ec415db8010000005f5e5bc9c3')  # 15 bytes
        sig5 = bytes.fromhex('4c89ec415f5e5bc9c3')
        i = 0
        while i + 24 <= len(out):
            j = out.find(sig5, i)
            if j < 0:
                break
            pad = out[j + 9:j + 9 + 12]
            if (pad.count(0x90) >= 6
                    and j >= 9
                    and out[j - 9:j - 5] == bytes([0x48, 0x83, 0xE4, 0xF0])
                    and out[j - 5] == 0xE8):
                out[j:j + 15] = good5
                fixed += 1
                i = j + 15
            else:
                i = j + 1

        return fixed

    def _pure_fix_longjmp_minus1_imm(self, out: bytearray) -> int:
        """Rewrite ``movabs rdx, 0xffffffff`` before ``longjmp`` to ``mov rdx,-1``.

        x86 ``push -1`` is signed; the translator often emits a zero-extended
        ``movabs rdx, 0xffffffff``.  Callers that ``cmp reg, -1`` as a 64-bit
        value (or rely on MSVC longjmp retval sign) then miss the wait-abort
        path (cmd interactive setjmp/longjmp).  Same-sized rewrite:
        ``48 C7 C2 FF FF FF FF`` + 3 NOPs.  Pair with shim ``movsxd rax,edx``.
        """
        if not self._cmd_no_hacks:
            return 0
        lj_iat = self._pure_iat_va("longjmp", fallback_rva=0x84E78)
        if not lj_iat:
            return 0
        bad = bytes.fromhex("48baffffffff00000000")  # movabs rdx, 0xffffffff
        good = bytes.fromhex("48c7c2ffffffff909090")  # mov rdx, -1; nop*3
        tip = struct.pack("<Q", lj_iat)
        fixed = 0
        i = 0
        n = len(out)
        while i + 30 <= n:
            at = out.find(bad, i)
            if at < 0:
                break
            window = bytes(out[at + 10:at + 40])
            if tip in window and b"\xff\xd0" in window:
                out[at:at + len(good)] = good
                fixed += 1
                i = at + len(good)
            else:
                i = at + 1
        return fixed

    def _pure_fix_zeroed_jcc_after_cmp_success_epi(self, out: bytearray) -> int:
        """Restore ``cmp …; 0F 00 00 00 00 00`` skip-to-helper Jccs.

        Deferred resolve sometimes leaves a zeroed near-Jcc after
        ``cmp r16/r32, imm8``.  MSVC shared cleanups place
        ``mov eax,esi; pop rsi; ret`` immediately before the fail/helper
        body the Jcc should reach (cmd paren/@ ``f7b4``/``f815`` →
        ``call 10005``).  Rewrite as ``jne`` to that helper body.

        Also retarget ``je`` that overshoots the success epi onto the
        helper (``f809`` → ``f817`` mapped one nop past ``89 F0 5E C3``).
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        n = len(out)
        epi = bytes.fromhex("89f05ec3")
        i = 0
        while i + 10 < n:
            pre = None
            if (i >= 4 and out[i:i + 6] == b"\x0f\x00\x00\x00\x00\x00"
                    and out[i - 4] == 0x66 and out[i - 3] == 0x83
                    and (out[i - 2] & 0xF8) == 0xF8):
                pre = i - 4
            elif (i >= 3 and out[i:i + 6] == b"\x0f\x00\x00\x00\x00\x00"
                  and out[i - 3] == 0x83 and (out[i - 2] & 0xF8) == 0xF8):
                pre = i - 3
            if pre is None:
                i += 1
                continue
            tgt = None
            for j in range(i + 6, min(n - 4, i + 0x200)):
                if out[j:j + 4] == epi:
                    tgt = j + 4
                    break
            if tgt is None:
                i += 1
                continue
            out[i + 1] = 0x85  # jne
            struct.pack_into("<i", out, i + 2, tgt - (i + 6))
            fixed += 1
            i += 6
        # je overshoot: land on success epi instead of helper after nop
        for i in range(n - 10):
            if out[i] != 0x0F or out[i + 1] != 0x84:
                continue
            rel = struct.unpack_from("<i", out, i + 2)[0]
            cur = i + 6 + rel
            if not (0 <= cur < n):
                continue
            new_tgt = None
            for back in range(1, 9):
                s = cur - back
                if s >= 0 and out[s:s + 4] == epi:
                    new_tgt = s
                    break
            if new_tgt is None or new_tgt == cur:
                continue
            struct.pack_into("<i", out, i + 2, new_tgt - (i + 6))
            fixed += 1
        return fixed

    def _pure_fix_align_stub_self_call_reuse_sibling(self, out: bytearray) -> int:
        """Retarget align-stub self-``call`` using a nearby sibling's callee.

        When ``_pure_repatch_align_stub_self_calls`` cannot resolve via
        rva_map (orphan rematerialized stubs), copy the target from the
        previous non-self align stub within 0x100 bytes (cmd ``push 0x10;
        call ff31`` twice in the paren/@ handler).
        """
        if not self._cmd_no_hacks:
            return 0
        pro = bytes.fromhex("41554989e54883ec204883e4f0")
        epi_head = bytes.fromhex("4c89ec415d")
        fixed = 0
        n = len(out)
        sites = []
        p = 0
        while True:
            j = out.find(pro, p)
            if j < 0:
                break
            call_at = j + len(pro)
            if (call_at + 5 <= n and out[call_at] == 0xE8
                    and out[call_at + 5:call_at + 5 + len(epi_head)] == epi_head):
                rel = struct.unpack_from("<i", out, call_at + 1)[0]
                sites.append((j, call_at, call_at + 5 + rel))
            p = j + 1
        for idx, (j, call_at, tgt) in enumerate(sites):
            if tgt != j:
                continue
            donor = None
            for k in range(idx - 1, -1, -1):
                pj, pc, pt = sites[k]
                if call_at - pc > 0x100:
                    break
                if pt != pj and 0 <= pt < n:
                    donor = pt
                    break
            if donor is None:
                continue
            struct.pack_into("<i", out, call_at + 1, donor - (call_at + 5))
            fixed += 1
        return fixed

    def _pure_rematerialize_unmapped_function_clusters(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Freshly re-translate x86 functions that ended the pipeline with NO
        rva_map entry (stale duplicate islands with corrupted internals).

        Rematerialization history can leave several partially-healed copies of
        one x86 function and no live map entry: calls resolve to whichever
        fingerprint match comes first (cmd 0x1EF0 → dead island 0x643DC whose
        internal branches still target an older island and crash).  Re-translate
        a bounded window around each unmapped function-start candidate as one
        chunk so intra-cluster calls resolve via old_new (correct by
        construction), and overwrite the map so later call/branch resolution
        picks the fresh copy.

        Candidates = unmapped x86 fn entries PLUS unmapped x86 E8 call targets
        whose head looks like a function prologue.  Windows are bounded
        (layout headroom before .data) and capped in number.
        """
        if not self._cmd_no_hacks or not text_data or not rva_map:
            return 0
        # Bounded: .text headroom before .data is ~0x2000; keep growth inside.
        WINDOW = 0x500
        MAX_CLUSTERS = 2
        n = len(text_data)
        cands = set(self._fn_entry_rvas)
        for off in range(n - 5):
            if text_data[off] != 0xE8:
                continue
            rel = struct.unpack_from('<i', text_data, off + 1)[0]
            tgt = (text_rva + off + 5 + rel) & 0xFFFFFFFF
            if tgt < text_rva or tgt - text_rva >= n:
                continue
            cands.add(tgt)

        def _entry_head(s: int) -> bool:
            o = s - text_rva
            if o < 0 or o + 2 >= n:
                return False
            b0 = text_data[o]
            if b0 in (0x55, 0x53, 0x56, 0x57):      # push ebp/ebx/esi/edi
                return True
            if b0 == 0x8B:                          # mov r32,[esp+4]
                return (text_data[o + 1] & 0xC7) == 0x24
            if b0 == 0x83 and text_data[o + 1] == 0x25:
                return True                         # and dword [abs], imm8
            if b0 == 0x80 and text_data[o + 1] == 0x25:
                return True                         # and byte [abs], imm8
            return False

        def _stale_island(m: int) -> bool:
            """A mapped chunk is stale when its early branches escape to
            positions that are NOT function entries (mid-garbage of dead
            islands).  Healthy chunks only branch to live function entries."""
            if not (0 <= m < len(out) - 4):
                return False
            lo = max(0, m - 0x40)
            hi = min(len(out), m + 0x500)
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True
                for ins in md.disasm(bytes(out[lo:hi]), lo):
                    if not (ins.mnemonic.startswith('j')
                            or ins.mnemonic in ('call', 'jmp')):
                        continue
                    tgt = None
                    for op in ins.operands:
                        if op.type == X86_OP_IMM:
                            tgt = op.imm
                            break
                    if tgt is None:
                        continue
                    if lo - 0x40 <= tgt <= hi + 0x80:
                        continue
                    # Legit cross-function targets look like function
                    # prologues; stale islands escape into mid-garbage
                    # (cmd 0x1EF0 island -> je 0xEBB = ``add al,[rax]``).
                    if (0 <= tgt < len(out)
                            and self._x64_entry_prologue_ok(out, tgt)):
                        continue
                    return True
            except CsError:
                pass
            return False

        starts = []
        dbg = os.environ.get('DBG_REMAT')
        for s in sorted(cands):
            if not _entry_head(s):
                continue
            m = rva_map.get(s)
            stale = False
            if m is None:
                stale = True
            elif (isinstance(m, int) and 0 <= m < len(out)
                    and _stale_island(m)):
                stale = True
            if stale:
                starts.append(s)
            if dbg and 0x1E00 <= s <= 0x2600:
                with open(os.environ.get('DBG_REMAT_LOG', '_remat_dbg.txt'),
                          'a') as f:
                    f.write(f'cand x86 0x{s:X} head=1 m={m} stale={stale}\n')
        if dbg:
            with open(os.environ.get('DBG_REMAT_LOG', '_remat_dbg.txt'),
                      'a') as f:
                f.write(f'total starts={len(starts)} '
                        f'first={[hex(s) for s in starts[:8]]}\n')
        planned = []
        for s in starts:
            if any(lo <= s < hi for lo, hi in planned):
                continue
            hi = min(s + WINDOW, text_rva + n)
            off = s - text_rva
            end_off = hi - text_rva
            if end_off <= off or b'\xE8' not in text_data[off:end_off]:
                continue
            planned.append((s, hi))
            if len(planned) >= MAX_CLUSTERS:
                break
        added = 0
        for start, end in planned:
            off = start - text_rva
            end_off = end - text_rva
            blob = text_data[off:end_off]
            base = len(out)
            deferred: List[Tuple[int, int, str]] = []
            chunk_out, chunk_map = self._translate_function(
                start, blob, False, 0, chunk_base=base, section_rva=text_rva,
                global_rva_map=rva_map, deferred_branches=deferred)
            if not chunk_out:
                continue
            out += chunk_out
            pad = (4 - len(out) % 4) % 4
            if pad:
                out += b'\x90' * pad
            # Merge the chunk's own mappings FIRST so deferred in-chunk
            # forward references (call x86 0x5C02 → +0x652D0) resolve to
            # the fresh copy instead of the stale first-pass hole.
            for old_va, rel in chunk_map.items():
                old_r = old_va - self.old_base
                if start <= old_r < end:
                    rva_map[old_r] = base + rel
            self._resolve_deferred_branches(out, rva_map, deferred)
            rva_map[start] = base
            added += 1
            if os.environ.get('DBG_REMAT'):
                with open(os.environ.get('DBG_REMAT_LOG', '_remat_dbg.txt'),
                          'a') as f:
                    f.write(f'[REMAT] x86 0x{start:X}-0x{end:X} -> +0x{base:X} '
                            f'({len(chunk_out)} bytes)\n')
        return added

    def _pure_restore_stub_calls_by_x86_order(self, out: bytearray,
                                              rva_map: Dict[int, int],
                                              text_data: bytes,
                                              text_rva: int) -> int:
        """Rebuild direct-call targets by pairing x86 E8 calls, in order, with
        the x64 align-stub E8s inside each function's translated chunk.

        Rematerialized / merged chunks lose their per-call rva_map entries
        (stale interior slots still point at the old blob, e.g. cmd 0xC6E8
        → old 0x17B9D while the live chunk sits at 0x4CEE8), so anchor-based
        repatches cannot recover the x86 call and the catch-all self-call
        neutralizer destroys them.  The translator emits align stubs strictly
        in x86 call order, so the k-th non-thunk x86 E8 of a function
        corresponds to the k-th align stub of its chunk.  Apply only when
        the counts match exactly and both spans are bounded.
        """
        if not self._cmd_no_hacks or not text_data or not rva_map:
            return 0
        entries = sorted(
            (rva_map[r], r) for r in self._fn_entry_rvas
            if rva_map.get(r) is not None and 0 <= rva_map[r] < len(out))
        if len(entries) < 2:
            return 0
        _dbg_tgt = int(os.environ.get('DBG_TGT', '0'), 16) if os.environ.get('DBG_TGT') else 0
        if _dbg_tgt:
            print(f'[STUBREST] map[{_dbg_tgt:#x}]={rva_map.get(_dbg_tgt)} len(out)={len(out):#x}',
                  flush=True)
        pro = bytes.fromhex('41554989e54883ec204883e4f0')
        epi = bytes.fromhex('4c89ec415d')
        md = None
        fixed = 0
        for (xlo, rxlo), (xhi, rxhi) in zip(entries, entries[1:]):
            if xhi <= xlo or rxhi <= rxlo:
                continue
            if xhi - xlo > 0x3000 or rxhi - rxlo > 0x3000:
                continue
            if (rxlo < text_rva or rxhi - text_rva > len(text_data)
                    or rxlo - text_rva >= len(text_data)):
                continue
            # x86 direct E8 calls, skipping IAT thunks (setjmp3 etc. emit as
            # movabs+call [slot], not align stubs) and chkstk probes.
            if md is None:
                md = Cs(CS_ARCH_X86, CS_MODE_32)
                md.detail = True
            x86_calls = []
            try:
                for ins in md.disasm(
                        bytes(text_data[rxlo - text_rva:rxhi - text_rva]),
                        self.old_base + rxlo):
                    if ins.mnemonic != 'call':
                        continue
                    tgt = None
                    for op in ins.operands:
                        if op.type == X86_OP_IMM:
                            tgt = op.imm - self.old_base
                            break
                    if tgt is None:
                        continue
                    if self._ff25_iat_slot_at_rva(tgt) is not None:
                        continue
                    x86_calls.append(tgt)
            except CsError:
                continue
            # x64 align stubs in emission order (E8 or neutralized marker).
            stubs = []
            p = xlo
            while p < xhi - 18:
                if out[p:p + 13] != pro:
                    p += 1
                    continue
                j = p + 13
                if j + 10 > xhi:
                    break
                if out[j + 5:j + 10] != epi:
                    p += 1
                    continue
                cur = None
                if out[j] == 0xE8:
                    cur = j + 5 + struct.unpack_from('<i', out, j + 1)[0]
                elif out[j:j + 5] == b'\xB8\x00\x00\x01\x00':
                    cur = p  # self-call catch-all marker
                else:
                    p += 1
                    continue
                stubs.append((p, j, cur))
                p = j + 10
            if len(stubs) != len(x86_calls):
                continue
            for (p, j, cur), tgt_x86 in zip(stubs, x86_calls):
                new_tgt = rva_map.get(tgt_x86)
                _dbg_tgt = int(os.environ.get('DBG_TGT', '0'), 16) if os.environ.get('DBG_TGT') else 0
                if _dbg_tgt and tgt_x86 == _dbg_tgt:
                    print(f'[STUBREST] pair x86 {xlo:#x}-{xhi:#x} '
                          f'stub=0x{p:X} j=0x{j:X} cur=0x{cur:X} '
                          f'tgt_x86=0x{tgt_x86:X} new_tgt=0x{new_tgt:X}',
                          flush=True)
                if new_tgt is None or not (0 <= new_tgt < len(out)):
                    new_tgt = self._pure_resolve_x86_call_target(
                        out, tgt_x86, rva_map, text_data, text_rva, reject=p)
                    if _dbg_tgt and tgt_x86 == _dbg_tgt:
                        print(f'[STUBREST] fallback resolve tgt_x86=0x{tgt_x86:X} -> 0x{new_tgt:X}',
                              flush=True)
                if new_tgt is None or new_tgt == p or new_tgt == j:
                    continue
                if out[j] == 0xE8 and new_tgt == cur:
                    continue
                struct.pack_into('<i', out, j + 1, new_tgt - (j + 5))
                out[j] = 0xE8
                fixed += 1
        return fixed

    def _pure_snap_calls_off_callr_epilogue_tails(self, out: bytearray) -> int:
        """Snap E8 targets that land on a preceding chunk's ``call reg`` +
        ``mov rsp,r13; pop r13`` tail forward to the next real prologue.

        Map tips for remat chunks often point ~0x11 bytes early, onto the
        previous function's indirect-call tail (cmd x86 0x53C9 → 0x64DD8 =
        ``call r15; mov rsp,r13; pop r13; mov rbx,0x80; nop; nop`` while the
        real entry ``push rbp; mov rbp,rsp`` sits at 0x64DE9).  Calling the
        tail runs an extra IAT call, then ``mov rsp,r13; pop r13`` rewinds
        RSP into the caller's frame — every downstream arg read is garbage.
        Snap forward to the first prologue within 0x40 bytes.
        """
        if not self._cmd_no_hacks:
            return 0
        epi = b'\x4c\x89\xec\x41\x5d'
        fixed = 0
        n = len(out)
        i = 0
        while i < n - 5:
            if out[i] != 0xE8:
                i += 1
                continue
            if not self._e8_byte_is_real_call(out, i):
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            t = i + 5 + rel
            if not (0 <= t < n - 8):
                i += 1
                continue
            is_callreg = (out[t:t + 3] == b'\x41\xff\xd7'
                          or out[t:t + 2] in (b'\xff\xd0', b'\xff\xd3',
                                              b'\xff\xd6'))
            has_epi = (out[t + 3:t + 8] == epi
                       or out[t + 3:t + 7] == epi)
            if not (is_callreg and has_epi):
                i += 1
                continue
            snap = None
            for d in range(8, 0x40):
                q = t + d
                if q + 5 > n:
                    break
                if (out[q:q + 4] == b'\x55\x48\x89\xe5'
                        or out[q:q + 4] == b'\x48\x89\x4c\x24'
                        or out[q:q + 3] == b'\x41\x55\x49'):
                    snap = q
                    break
            if snap is None:
                i += 1
                continue
            struct.pack_into('<i', out, i + 1, snap - (i + 5))
            fixed += 1
            i += 5
            continue
        return fixed

    def _pure_snap_calls_past_arg_homes(self, out: bytearray) -> int:
        """Snap E8 targets that land on ``mov [rbp+0x10],rcx`` arg-homes back
        to the preceding ``push rbp; mov rbp,rsp``.

        Rematerialized chunks can be entered 4 bytes late (cmd 0x5C02 chunk
        at 0x414E4, calls at 0x64EAF/0x64FCF landed on the arg-home at
        0x414E8).  Skipping ``push rbp; mov rbp,rsp`` leaves RBP untouched,
        so the epilogue ``mov rsp,rbp; pop rbp; ret`` runs with the caller's
        RBP → read @ -1 crash.  Arg-home bytes never legitimately start a
        function, so snapping back is always safe.
        """
        if not self._cmd_no_hacks:
            return 0
        home = b'\x48\x89\x4d\x10'      # mov [rbp+0x10], rcx
        pro = b'\x55\x48\x89\xe5'       # push rbp; mov rbp, rsp
        fixed = 0
        n = len(out)
        i = 0
        while i < n - 5:
            if out[i] != 0xE8:
                i += 1
                continue
            if not self._e8_byte_is_real_call(out, i):
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if (tgt >= 4 and tgt + 4 <= n
                    and out[tgt:tgt + 4] == home
                    and out[tgt - 4:tgt] == pro):
                struct.pack_into('<i', out, i + 1, (tgt - 4) - (i + 5))
                fixed += 1
                i += 5
                continue
            i += 1
        return fixed

    def _pure_neutralize_calls_into_zero_holes(self, out: bytearray) -> int:
        """Neutralize E8 calls whose target sits inside a long zero run.
        Zero holes come from wiped/stale first-pass regions; executing them
        slides through ``add [rax],al`` into unrelated code (cmd 0x414E8
        hole → fall-through into a stale fragment → infinite recursion).
        The remat chunk-deferral fix prevents most of these, but any
        survivor is safer as ``mov eax,0x10000`` (the established no-op
        call marker) than as a call into zeros.
        """
        if not self._cmd_no_hacks:
            return 0
        n = len(out)
        zeros = []
        i = 0
        while i < n:
            if out[i] != 0:
                i += 1
                continue
            j = i
            while j < n and out[j] == 0:
                j += 1
            if j - i >= 8:
                zeros.append((i, j))
            i = j
        if not zeros:
            return 0
        import bisect as _bisect
        starts = [z[0] for z in zeros]
        fixed = 0
        p = 0
        while p < n - 5:
            if out[p] != 0xE8:
                p += 1
                continue
            if not self._e8_byte_is_real_call(out, p):
                p += 1
                continue
            rel = struct.unpack_from('<i', out, p + 1)[0]
            tgt = p + 5 + rel
            k = _bisect.bisect_right(starts, tgt) - 1
            if k >= 0 and zeros[k][0] <= tgt < zeros[k][1]:
                out[p:p + 5] = b'\xB8\x00\x00\x01\x00'  # mov eax, 0x10000
                fixed += 1
                p += 5
                continue
            p += 1
        return fixed

    def _pure_nop_all_remaining_self_calls(self, out: bytearray,
                                            rva_map: Optional[Dict[int, int]] = None,
                                            text_data: Optional[bytes] = None,
                                            text_rva: Optional[int] = None) -> int:
        """Catch-all: turn every remaining self-call inside an align stub
        into a no-op (call $+5) that falls through to the epilogue.

        This preserves the stack-restoring epilogue (mov rsp,r13; pop r13)
        so the caller's frame management stays intact.  The call target
        function is simply skipped — semantically imperfect but stack-safe.
        """
        if not self._cmd_no_hacks:
            return 0
        # push r13; mov r13,rsp; sub rsp,0x20; and rsp,-0x10
        pro = bytes.fromhex("41554989e54883ec204883e4f0")
        # mov rsp,r13; pop r13
        epi = bytes.fromhex("4c89ec415d")
        PRO_LEN = len(pro)   # 13
        EPI_LEN = len(epi)   # 5
        CALL_LEN = 5
        fixed = 0
        n = len(out)
        p = 0
        while p < n - PRO_LEN - CALL_LEN - EPI_LEN:
            if out[p:p + PRO_LEN] != pro:
                p += 1
                continue
            j = p + PRO_LEN  # position of E8
            if j + CALL_LEN > n or out[j] != 0xE8:
                p += 1
                continue
            epi_pos = j + CALL_LEN
            if epi_pos + EPI_LEN > n:
                p += 1
                continue
            if out[epi_pos:epi_pos + EPI_LEN] != epi:
                p += 1
                continue
            rel = struct.unpack_from("<i", out, j + 1)[0]
            tgt = j + CALL_LEN + rel
            if tgt != p:
                p += 1
                continue
            # Fallback before neutralizing: pair this stub with the k-th
            # x86 E8 of its enclosing function by ORDER.  The bulk restore
            # pass skips intervals whose stub/E8 counts differ; orphaned
            # first-pass functions (map entry intact, interior lost) still
            # contain resolvable calls — cmd 0x13A9C format parser's first
            # stub = wcschr (x86 0x13B8F → 0x320B4).  Neutralizing such a
            # call to ``mov eax,0x10000`` made the digit-scan read address
            # 0x10002 in an infinite loop.
            if rva_map is not None and text_data is not None and text_rva is not None:
                cand = None
                cand_off = -1
                for r in self._fn_entry_rvas:
                    mo = rva_map.get(r)
                    if (mo is not None and cand_off < mo <= p
                            and self._x64_entry_prologue_ok(out, mo)):
                        cand = r
                        cand_off = mo
                if cand is not None and cand_off >= 0:
                    k_stub = 1
                    q = cand_off
                    while True:
                        q = out.find(pro, q, p)
                        if q < 0:
                            break
                        k_stub += 1
                        q += len(pro)
                    xoff = cand - text_rva
                    kx = 0
                    found_tgt = None
                    limit = min(xoff + 0x800, len(text_data) - 5)
                    for s in range(xoff, limit):
                        if text_data[s] != 0xE8:
                            continue
                        rel_x = struct.unpack_from(
                            '<i', text_data, s + 1)[0]
                        xt = (text_rva + s + 5 + rel_x) & 0xFFFFFFFF
                        if self._ff25_iat_slot_at_rva(xt) is not None:
                            continue
                        kx += 1
                        if kx == k_stub:
                            found_tgt = xt
                            break
                    if found_tgt is not None:
                        nt = rva_map.get(found_tgt)
                        if nt is None:
                            nt = self._pure_resolve_x86_call_target(
                                out, found_tgt, rva_map, text_data,
                                text_rva, reject=p)
                        if (nt is not None and 0 <= nt < n
                                and nt != p and nt != j
                                and (self._x64_entry_prologue_ok(out, nt)
                                     or found_tgt in self._fn_entry_rvas)):
                            struct.pack_into('<i', out, j + 1, nt - (j + 5))
                            fixed += 1
                            p = epi_pos + EPI_LEN
                            continue
            # Self-call: replace with 'mov eax, 0x10000' (exit-polling-loop value).
            # The polling loop at 0x4D500 checks cmp ebx,0x10000 / jae → exit.
            # This allows the code to progress past infinite retry loops.
            dbg_f = None
            if os.environ.get('DBG_SELFCALL') and rva_map is not None:
                anchors = [(xa, mo) for xa, mo in rva_map.items()
                           if p - 0x400 <= mo <= j + 5]
                anchors.sort(key=lambda kv: abs(kv[1] - p))
                anch = ', '.join(
                    f'x86=0x{xa:X}@off+0x{mo:X}' for xa, mo in anchors[:5])
                dbg_f = open(os.environ.get('DBG_SELFCALL_LOG',
                                            '_selfcall_dbg.txt'), 'a')
                dbg_f.write(f'stub=+0x{p:X} call=+0x{j:X} '
                            f'nearest=[{anch}]\n')
            out[j:j + 5] = b'\xB8\x00\x00\x01\x00'  # mov eax, 0x10000
            if dbg_f is not None:
                dbg_f.close()
            fixed += 1
            p = epi_pos + EPI_LEN
        return fixed

    def _pure_fix_peb_c_infinite_waiter_exits(self, out: bytearray) -> int:
        """Alias: lexer exit when PEB-/c sticky is done."""
        return self._pure_fix_peb_c_lexer_exits_when_sticky_done(out)


    def _pure_fix_reg_arg_join_skips_stdcall_add_rsp(self, out: bytearray) -> int:
        """Skip leftover ``add rsp,8`` when joining CSR epi without stack args.

        x86 shared ``pop ecx; pop ecx; pop edi; ?; ret`` cleanup.  On Win64 a
        success path may pass args only in RCX/RDX (no pushes) but still
        ``jmp`` onto ``add rsp, 8`` before ``pop rdi``, so the return address
        is loaded into RSI and ``ret`` executes a heap node (cmd Echo
        ``0x427fb`` ? ``0x428ce``).
        """
        if not self._cmd_no_hacks:
            return 0
        # add rsp,8; pop rdi; xor rax,rax; pop rsi; ret
        # Also: add rsp,8; jmp <sticky-done cave> after sticky-done rewrote the epi.
        epi = bytes.fromhex('4883c4085f4831c05ec3')
        add_jmp = bytes.fromhex('4883c408e9')
        fixed = 0
        i = 0
        while True:
            at = out.find(epi, i)
            at_jmp = out.find(add_jmp, i)
            if at < 0 and at_jmp < 0:
                break
            if at < 0 or (at_jmp >= 0 and at_jmp < at):
                at = at_jmp
                skip_to = at + 4  # the jmp (skips add rsp,8)
                i = at + 1
            else:
                skip_to = at + 4  # pop rdi
                i = at + 1
            for j in range(max(0, at - 0x180), at - 5):
                if out[j] != 0xE9:
                    continue
                rel = struct.unpack_from('<i', out, j + 1)[0]
                if j + 5 + rel != at:
                    continue
                pre = bytes(out[max(0, j - 8):j])
                # Keep cleanup when this join still materializes stack args.
                if len(pre) >= 6 and pre[-6] == 0x57 and pre[-5] == 0x68:
                    continue  # push rdi; push imm32
                if len(pre) >= 3 and pre[-3] == 0x57 and pre[-2] == 0x6a:
                    continue  # push rdi; push imm8
                if pre and 0x50 <= pre[-1] <= 0x57:
                    continue  # trailing push r64
                if len(pre) >= 2 and pre[-2] == 0x41 and 0x50 <= pre[-1] <= 0x57:
                    continue
                struct.pack_into('<i', out, j + 1, skip_to - (j + 5))
                fixed += 1
        return fixed


    def _pure_nop_spurious_stdcall_add_rsp_after_align(
            self, out: bytearray) -> int:
        """NOP leftover ``add rsp,N`` after r13 align-stub restore.

        x86 stdcall ``call; add esp, N`` cleanup is emitted after the Win64
        align stub::

            push r13; mov r13,rsp; sub rsp,0x20; and rsp,-16; call …
            mov rsp, r13; pop r13
            add rsp, N          ; phantom — mov rsp,r13 already restored

        Each phantom add pops into the callee-save area below ``sub rsp,F``,
        so a later ``pop rdi; pop rsi; pop rbx; leave; ret`` loads locals
        (e.g. UTF-16 ``"echo"``) into RSI and the echo path calls through a
        non-pointer.  Any ``add rsp,imm`` immediately after the stub restore
        is always redundant.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rsp, r13; pop r13 — both common encodings
        prefixes = (
            bytes([0x4C, 0x89, 0xEC, 0x41, 0x5D]),  # mov r/m,r form
            bytes([0x49, 0x8B, 0xE5, 0x41, 0x5D]),  # mov r,r/m form
        )

        def _has_pre_stub_push(out: bytearray, stub_push_at: int) -> bool:
            """True if a real ``push`` sits immediately before align ``push r13``.

            Only the last ~12 bytes are inspected so distant prologue pushes
            and prior stubs are ignored.  ``push r13`` itself is excluded.
            """
            start = max(0, stub_push_at - 12)
            k = start
            while k < stub_push_at:
                b = out[k]
                if k == stub_push_at - 2 and b == 0x41 and out[k + 1] == 0x55:
                    break  # the align push r13
                if 0x50 <= b <= 0x57:
                    return True
                if b == 0x6A and k + 1 < stub_push_at:
                    return True
                if b == 0x68 and k + 4 < stub_push_at:
                    return True
                if b == 0x41 and k + 1 < stub_push_at and 0x50 <= out[k + 1] <= 0x57:
                    if not (out[k + 1] == 0x55 and k + 2 == stub_push_at):
                        return True
                    k += 2
                    continue
                if b in (0x48, 0x49) and k + 1 < stub_push_at and 0x50 <= out[k + 1] <= 0x57:
                    return True
                k += 1
            return False

        for prefix in prefixes:
            i = 0
            while True:
                j = out.find(prefix, i)
                if j < 0:
                    break
                k = j + len(prefix)
                if k >= len(out):
                    break
                # Align stub begins with ``push r13`` immediately before
                # ``mov r13,rsp`` — for ``4C 89 EC`` form the push is at j-3
                # only when preceded by ``mov r13,rsp``; locate ``41 55``.
                stub_push = out.rfind(bytes([0x41, 0x55]), max(0, j - 0x20), j)
                if stub_push >= 0 and _has_pre_stub_push(out, stub_push):
                    i = j + 1
                    continue
                # add rsp, imm8  → 48 83 C4 ib
                if (k + 3 < len(out)
                        and out[k:k + 3] == bytes([0x48, 0x83, 0xC4])
                        and out[k + 3] != 0):
                    out[k:k + 4] = b'\x90\x90\x90\x90'
                    fixed += 1
                    i = k + 4
                    continue
                # add rsp, imm32 → 48 81 C4 id
                if (k + 6 < len(out)
                        and out[k:k + 3] == bytes([0x48, 0x81, 0xC4])):
                    imm = struct.unpack_from('<I', out, k + 3)[0]
                    if 0 < imm <= 0x100:
                        out[k:k + 7] = b'\x90' * 7
                        fixed += 1
                        i = k + 7
                        continue
                # add esp, imm8 (32-bit form left behind)
                if (k + 2 < len(out)
                        and out[k] == 0x83 and out[k + 1] == 0xC4
                        and out[k + 2] != 0):
                    out[k:k + 3] = b'\x90\x90\x90'
                    fixed += 1
                    i = k + 3
                    continue
                i = j + 1
        return fixed

    def _pure_fix_delayed_edi_ebx_callee_saves(self, out: bytearray) -> int:
        """Restore delayed ``push edi; push ebx`` dropped by stdcall→Win64.

        x86 (cmd ``0x12FA3``)::

            sub esp,N; push esi; test esi; jne body
            …; jmp early_epi          ; early_epi = pop esi; leave; ret
            body: push edi; push ebx; push esi; call; pop ecx
            …
            epi: pop ebx; pop edi; pop esi; leave; ret

        Translation keeps the three epilogue pops but turns the body pushes
        into ``mov rcx,rsi; mov rdx,rbx; mov r8,rdi`` (bogus Win64 args for
        a 1-arg ``lstrlenW``).  Early exit also lands on ``pop rbx`` instead
        of ``pop rsi``, so the first return unbalances RSP and the next
        call sees a smashed ``[rbp+0x18]`` (heap / ``STATUS_HEAP_CORRUPTION``
        on the echo path).

        Rewrite body to ``push rdi; push rbx; mov rcx,rsi`` and retarget
        early-exit jmps onto ``pop rsi``.
        """
        if not self._cmd_no_hacks:
            return 0
        fixed = 0
        # mov rcx,rsi; mov rdx,rbx; mov r8,rdi  (9 bytes)
        bogus = bytes.fromhex('4889f14889da4989f8')
        # push rdi; push rbx; mov rcx,rsi; nop*4
        fixed_body = bytes.fromhex('57534889f190909090')
        assert len(bogus) == len(fixed_body) == 9
        epi = bytes.fromhex('5b5f5ec9c3')  # pop rbx; pop rdi; pop rsi; leave; ret
        i = 0
        while True:
            at = out.find(bogus, i)
            if at < 0:
                break
            # Require a nearby shared epilogue with the three pops.
            epi_at = out.find(epi, at, min(len(out), at + 0x800))
            if epi_at < 0:
                i = at + 1
                continue
            # Success-path lead should be jne/je onto *at* from a test esi.
            lead_ok = False
            for back in range(4, 0x28):
                p = at - back
                if p < 0:
                    break
                # test esi,esi / test rsi,rsi
                if out[p:p + 2] not in (b'\x85\xf6', b'\x48\x85\xf6'):
                    continue
                # short jne/je
                if out[p + 2] in (0x75, 0x74):
                    rel = struct.unpack_from('<b', out, p + 3)[0]
                    if p + 4 + rel == at:
                        lead_ok = True
                        break
                # near jne/je
                if out[p + 2] == 0x0F and out[p + 3] in (0x85, 0x84):
                    rel = struct.unpack_from('<i', out, p + 4)[0]
                    if p + 8 + rel == at:
                        lead_ok = True
                        break
            if not lead_ok:
                i = at + 1
                continue
            out[at:at + 9] = fixed_body
            fixed += 1
            # Retarget E9 jmps in the early-exit window onto pop rsi (epi+2).
            pop_rsi = epi_at + 2
            for j in range(max(0, at - 0x40), at):
                if out[j] != 0xE9:
                    continue
                rel = struct.unpack_from('<i', out, j + 1)[0]
                tgt = j + 5 + rel
                if tgt == epi_at:
                    struct.pack_into('<i', out, j + 1, pop_rsi - (j + 5))
                    fixed += 1
            i = at + 9
        return fixed

    def _pure_fix_switch_diamond_code_arg_movabs(
            self, out: bytearray, rva_map: Dict[int, int]) -> int:
        """Retarget switch-diamond ``movabs r8/r9`` onto real code bodies.

        x86 diamonds are::

            push <next_cb>      ; code
            push <self_cb>      ; code
            push <char>
            push <table>        ; data string
            call shared_helper  ; e.g. cmd FD5D

        After translation the char/table often survive but the two code
        pushes land as ``movabs`` of empty ``.data`` slots.  Rebuild from
        the x86 push immediates via ``rva_map``.
        """
        if not self._cmd_no_hacks or not rva_map or self.pe is None:
            return 0
        pe = self.pe
        text_rva = int(self.text_rva or 0)
        if not text_rva:
            return 0
        sec = pe.section_for_rva(text_rva)
        if sec is None:
            return 0
        x86 = pe.get_section_data(sec)
        if not x86:
            return 0
        old_base = int(self.old_base or 0)
        new_base = int(self.new_base or 0)
        text_end = text_rva + len(x86)
        text_new = int(self._old_to_new_section.get(text_rva, text_rva))

        def _blob_off(pe_off: int) -> int:
            # ``rva_map`` values are PE64 RVAs; prefer that interpretation so
            # a text RVA like 0x1CFC4 is not mistaken for a blob offset.
            if pe_off >= text_new and (pe_off - text_new) < len(out):
                return pe_off - text_new
            if 0 <= pe_off < len(out):
                return pe_off
            return pe_off

        def _body_entry_va(x86_rva: int) -> Optional[int]:
            pe_off = rva_map.get(x86_rva)
            if pe_off is None and self._final_rva:
                pe_off = self._final_rva.get(x86_rva)
            if pe_off is None:
                return None
            off = _blob_off(int(pe_off))
            if not (0 <= off < len(out)):
                return None
            # Nested switch diamonds are themselves tiny dispatch stubs
            # (``movabs rcx; mov rdx,ch; movabs r8/r9; call helper; ret``).
            # Prefer that tip only when the map already points *at* the head —
            # a wide lookback turns mid-imm landings into the *previous*
            # sibling diamond (cmd F4EB map near 0x1d4fe → 0x1d4f4).
            for back in range(0, 2):
                at = off - back
                if at < 0:
                    break
                if (out[at:at + 2] == b'\x48\xb9'
                        and at + 30 <= len(out)
                        and out[at + 10:at + 13] == b'\x48\xc7\xc2'
                        and out[at + 17:at + 19] == b'\x49\xb8'
                        and out[at + 27:at + 29] == b'\x49\xb9'):
                    return (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
            # Prefer ``movabs r11`` / ``cmp dword [r11],0`` aux (cmd F4EB).
            for back in range(0, 32):
                at = off - back
                if at < 0:
                    break
                if (out[at:at + 2] == b'\x49\xbb'
                        and at + 14 <= len(out)
                        and out[at + 10:at + 14] == b'\x41\x83\x3b\x00'):
                    return (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
            # Snap mid align-stub ``and rsp,-10`` back to ``push r13``.
            for back in range(0, 12):
                at = off - back
                if at < 0:
                    break
                if out[at:at + 5] == b'\x41\x55\x49\x89\xe5':
                    return (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
            # Prefer frame prologue.
            for back in range(0, 16):
                at = off - back
                if at < 0:
                    break
                if out[at] == 0x55 and at + 3 <= len(out) and out[at + 1] == 0x48:
                    return (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
            # Do NOT walk back onto switch-diamond heads — those are
            # dispatchers, not callback bodies (cmd nested 0x2e/0x2f).
            # Reject mid-epilogue / mid-insn anchors (pop/ret/dec [mem]).
            if out[off] in (0x5D, 0x5E, 0x5F, 0xC3, 0xFF, 0x41, 0x00):
                # Scan forward a short distance for an aux/frame tip.
                for fwd in range(0, 0x40):
                    at = off + fwd
                    if at + 14 <= len(out) and out[at:at + 2] == b'\x49\xbb' \
                            and out[at + 10:at + 14] == b'\x41\x83\x3b\x00':
                        return (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
                    if at < len(out) and out[at] == 0x55:
                        return (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
                return None
            return (new_base + text_new + off) & 0xFFFFFFFFFFFFFFFF

        def _data_va(x86_rva: int) -> Optional[int]:
            if self._final_rva and x86_rva in self._final_rva:
                v = int(self._final_rva[x86_rva])
                if v >= new_base:
                    return v & 0xFFFFFFFFFFFFFFFF
                return (new_base + v) & 0xFFFFFFFFFFFFFFFF
            pe_off = rva_map.get(x86_rva)
            if pe_off is None:
                return None
            v = int(pe_off)
            if v >= new_base:
                return v & 0xFFFFFFFFFFFFFFFF
            if v < 0x1000:
                return None
            return (new_base + v) & 0xFFFFFFFFFFFFFFFF
        # Collect diamonds from x86: four pushes then call.
        diamonds: List[Tuple[int, int, int, int, int]] = []
        i = 0
        n = len(x86)
        while i < n - 20:
            if x86[i] != 0x68:
                i += 1
                continue
            p0 = struct.unpack_from('<I', x86, i + 1)[0]
            if i + 5 >= n or x86[i + 5] != 0x68:
                i += 1
                continue
            p1 = struct.unpack_from('<I', x86, i + 6)[0]
            j = i + 10
            ch = None
            if j < n and x86[j] == 0x6A:
                ch = x86[j + 1]
                j += 2
            elif j + 5 <= n and x86[j] == 0x68:
                imm = struct.unpack_from('<I', x86, j + 1)[0]
                if imm <= 0xFF:
                    ch = imm
                    j += 5
            if ch is None or not (0x20 <= ch < 0x7F):
                i += 1
                continue
            if j + 5 > n or x86[j] != 0x68:
                i += 1
                continue
            table = struct.unpack_from('<I', x86, j + 1)[0]
            j += 5
            if j >= n or x86[j] != 0xE8:
                i += 1
                continue
            # Pushes are VAs; require first two in .text, table not a tiny imm.
            if not (old_base + text_rva <= p0 < old_base + text_end):
                i += 1
                continue
            if not (old_base + text_rva <= p1 < old_base + text_end):
                i += 1
                continue
            if not (old_base <= table < old_base + pe.image_size):
                i += 1
                continue
            cb2_rva = p0 - old_base
            cb1_rva = p1 - old_base
            tab_rva = table - old_base
            site_rva = text_rva + i
            diamonds.append((site_rva, tab_rva, ch, cb1_rva, cb2_rva))
            i = j + 5

        fixed = 0
        # pe64 tip for each discovered diamond (by x86 site / self-cb RVA).
        diam_tip: Dict[int, int] = {}
        for site_rva, tab_rva, ch, cb1_rva, cb2_rva in diamonds:
            # Locate pe64 body: prefer map of the push site / diamond label.
            # The diamond entry is usually the first push's owning label —
            # try site_rva and also cb1 when self-recursive.
            candidates = [site_rva, cb1_rva]
            entry_off = None
            for cand in candidates:
                pe_off = rva_map.get(cand)
                if pe_off is None:
                    continue
                off = _blob_off(int(pe_off))
                for back in range(0, 32):
                    at = off - back
                    if at < 0:
                        break
                    if (out[at:at + 2] == b'\x48\xb9'
                            and at + 30 <= len(out)
                            and out[at + 10:at + 13] == b'\x48\xc7\xc2'
                            and struct.unpack_from('<I', out, at + 13)[0] == ch):
                        entry_off = at
                        break
                if entry_off is not None:
                    break
            if entry_off is None:
                # Scan whole image for mov rdx, ch with surrounding movabs.
                tip = b'\x48\xc7\xc2' + struct.pack('<I', ch)
                start = 0
                while True:
                    k = out.find(tip, start)
                    if k < 0:
                        break
                    if (k >= 10 and out[k - 10:k - 8] == b'\x48\xb9'
                            and out[k + 7:k + 9] == b'\x49\xb8'
                            and out[k + 17:k + 19] == b'\x49\xb9'):
                        entry_off = k - 10
                        break
                    start = k + 1
            if entry_off is not None:
                tip_va = (new_base + text_new + entry_off) & 0xFFFFFFFFFFFFFFFF
                diam_tip[site_rva] = tip_va
                # Only alias self-cb when it *is* this diamond (nested
                # ``push self``).  Top-level self is often an aux like F4EB.
                if cb1_rva == site_rva:
                    diam_tip[cb1_rva] = tip_va

        for site_rva, tab_rva, ch, cb1_rva, cb2_rva in diamonds:
            entry_off = None
            tip_va = diam_tip.get(site_rva)
            if tip_va is not None:
                entry_off = int(tip_va - (new_base + text_new)) & 0xFFFFFFFF
            if entry_off is None:
                continue
            tab_va = _data_va(tab_rva)
            # Nested diamond callbacks: prefer the diamond tip map.
            cb1_va = diam_tip.get(cb1_rva) or _body_entry_va(cb1_rva)
            cb2_va = diam_tip.get(cb2_rva) or _body_entry_va(cb2_rva)
            text_lo = (new_base + text_new) & 0xFFFFFFFFFFFFFFFF
            text_hi = (text_lo + len(out)) & 0xFFFFFFFFFFFFFFFF

            def _cb_tip_ok(va: int) -> bool:
                off = int(va - text_lo) & 0xFFFFFFFF
                if not (0 <= off < len(out) - 4):
                    return False
                # Reject mid ``and rsp,-10`` / mid-imm landings.
                if out[off:off + 3] in (
                        b'\x83\xe4\xf0', b'\x48\x83\xe4'):
                    return False
                if out[off] in (0x00, 0x0F) and out[off + 1] in (0x84, 0x85):
                    return False
                # Reject mid-instruction ``mov rdx/imm`` (often +0xa into diamond).
                if out[off:off + 3] == b'\x48\xc7\xc2':
                    return False
                # Accept diamond / aux / frame prologues only.
                if out[off:off + 2] in (b'\x48\xb9', b'\x49\xbb', b'\x55\x48'):
                    return True
                if out[off:off + 2] == b'\x41\x55':
                    return True
                if out[off] == 0x55:  # push rbp
                    return True
                return False

            # Final chain body often sits right after the last diamond's
            # ``ret`` (cmd f5ed after f5d6).  If rva_map misses it, snap
            # forward from this diamond tip onto ``push rbp``.
            if (cb2_va is None or not (text_lo <= cb2_va < text_hi)
                    or not _cb_tip_ok(cb2_va)):
                for fwd in range(0x20, 0x60):
                    at = entry_off + fwd
                    if at + 3 <= len(out) and out[at] == 0x55 and out[at + 1] == 0x48:
                        # Prefer a real frame: push rbp; mov rbp, rsp.
                        if out[at + 1:at + 4] == b'\x48\x89\xe5':
                            cb2_va = (new_base + text_new + at) & 0xFFFFFFFFFFFFFFFF
                            break
            # Self-cb must be this diamond tip when site==self.
            if cb1_rva == site_rva:
                cb1_va = (new_base + text_new + entry_off) & 0xFFFFFFFFFFFFFFFF
            if tab_va is None or cb1_va is None or cb2_va is None:
                continue
            if not (text_lo <= cb1_va < text_hi and text_lo <= cb2_va < text_hi):
                continue
            if not (_cb_tip_ok(cb1_va) and _cb_tip_ok(cb2_va)):
                continue
            # movabs rcx / mov rdx,ch / movabs r8 / movabs r9
            if out[entry_off:entry_off + 2] != b'\x48\xb9':
                continue
            if out[entry_off + 17:entry_off + 19] != b'\x49\xb8':
                continue
            if out[entry_off + 27:entry_off + 29] != b'\x49\xb9':
                continue
            old_tab = struct.unpack_from('<Q', out, entry_off + 2)[0]
            old_r8 = struct.unpack_from('<Q', out, entry_off + 19)[0]
            old_r9 = struct.unpack_from('<Q', out, entry_off + 29)[0]
            # Always install the x86-derived targets once resolved.  A "plausible"
            # old tip (e.g. push rbp of the *next* body, or mid-sibling diamond)
            # must not block the rewrite — that left cmd's top ``'-'`` diamond
            # with r9=.data and the last diamond with r8==r9==body.
            changed = False
            if old_tab != tab_va:
                struct.pack_into('<Q', out, entry_off + 2, tab_va)
                changed = True
            if old_r8 != cb1_va:
                struct.pack_into('<Q', out, entry_off + 19, cb1_va)
                changed = True
            if old_r9 != cb2_va:
                struct.pack_into('<Q', out, entry_off + 29, cb2_va)
                changed = True
            if changed:
                fixed += 1
        return fixed
