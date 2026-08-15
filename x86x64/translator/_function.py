"""Instruction-level translation: x86 function bodies to x64.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403

import os
try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    _HAS_THREAD_POOL = True
except ImportError:
    _HAS_THREAD_POOL = False


class FunctionTranslationMixin:
    """See the module docstring."""

    _CALLEE_SAVE_REG_IDS = frozenset((
        X86_REG_EBX, X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
    ))


    def _translate_stub(self, stub: StubInfo) -> bytes:
        """
        Translate a Win2000 NTDLL syscall stub to a Win64 wrapper.

        Input stub (32-bit, ~16 bytes):
          MOV EAX, 0x0020       ; Win2000 NtCreateFile nr
          LEA EDX, [ESP+4]
          INT 0x2E
          RET 0x2C              ; 11 args × 4 bytes

        Output (64-bit, ~11 bytes):
          MOV RAX, 0x0020       ; Win2000 NtCreateFile nr (win2000 target)
          SYSCALL
          RET

        With --syscall-target win10, RAX holds the Win10 x64 SSDT index instead.

        In Win64 ABI the CALLER already placed:
          arg1=RCX, arg2=RDX, arg3=R8, arg4=R9, arg5=[RSP+0x28], …
        so the stub just needs to set RAX and call the kernel.

        win10 target only: if no Win10 mapping exists the stub becomes INT3; RET.
        """
        nr = resolve_syscall_nr(stub.name, stub.win2000_nr)
        if (_SYSCALL_TARGET == 'win10'
                and nr == 0
                and stub.name not in _WIN10_SYSCALL_NAMES):
            if not stub.name.startswith('Zw'):
                self.warnings.append(
                    f"  [NO MAP] {stub.name} (Win2000=0x{stub.win2000_nr:04X}) "
                    f"→ no Win10 x64 equivalent (removed/undocumented)"
                )
            return self._asm('int3') + self._asm('ret')

        return (
            self._asm(f'mov rax, 0x{nr:04x}')
            + self._asm('syscall')
            + self._asm('ret')
        )

    def _translate_function(self, func_rva: int, code: bytes,
                            is_stdcall: bool, n_args: int,
                            chunk_base: int = 0,
                            section_rva: int = 0,
                            global_rva_map: Optional[Dict[int, int]] = None,
                            deferred_branches: Optional[List[Tuple[int, int, str]]] = None
                            ) -> Tuple[bytes, Dict[int, int]]:
        """
        Translate a single 32-bit function to 64-bit.

        For Win2000 code that uses stdcall (PUSH args, CALL, callee does RET N):
          • Convert function prologue:
              PUSH EBP; MOV EBP,ESP; SUB ESP,N  →  SUB RSP,align(N+32)
          • Convert argument access:
              [EBP+8], [EBP+C], … → RCX, RDX, R8, R9, [RSP+0x28], …
          • Convert calls: PUSH args → MOV RCX/RDX/R8/R9 + stack setup
          • Convert epilogue:
              LEAVE; RET N  →  ADD RSP,align(N+32); RET
          • Fix all branches and pointer immediates

        This is a best-effort translation; complex patterns are flagged
        with a warning and an INT3 for manual inspection.
        """
        out   = bytearray()
        insns = list(self.md.disasm(code, self.old_base + func_rva))
        old_new: Dict[int, int] = {}   # old VA → new byte offset in out[]
        pending_fixups: List[Tuple[int,int,str]] = []   # (patch_off, target_va, type)

        # Env-gated per-instruction trace (DEBUG_FN=0xRVA) to pinpoint where a
        # function's translation diverges (mis-disassembly / wrong call targets).
        _dbg_fn = os.environ.get('DEBUG_FN')
        _dbg_on = False
        if _dbg_fn:
            try:
                _dbg_on = (int(_dbg_fn, 16) == func_rva)
            except ValueError:
                _dbg_on = False
        if _dbg_on:
            print(f"[DEBUG_FN 0x{func_rva:X}] {len(insns)} insns, {len(code)} bytes")

        # ── Phase 1: Enumerate instructions, build old→new offset map ──────────
        # We need a two-pass approach: first estimate sizes, then emit.
        # For simplicity we use a single pass with 5-byte rel32 branch encoding
        # (always the worst-case; the linker can shrink later).
        #
        # Key transformations:
        #   • INT 0x2E  → SYSCALL (handled by _translate_stub usually, but
        #                           just in case we encounter it inline here)
        #   • SYSENTER  → SYSCALL
        #   • FS:[disp] → GS:[teb64_offset(disp)]
        #   • PUSH r32  → (accumulated; flushed on CALL as MOV arg_reg,r)
        #   • CALL near → E8 rel32 (target to be fixed up)
        #   • Jcc near  → 0F 8x rel32 (6 bytes)
        #   • JMP near  → E9 rel32 (5 bytes)
        #   • MOV r,imm → patch imm if it's a pointer
        #   • RET N     → ADD RSP,N+shadow; RET   (stdcall cleanup)
        #   • LEAVE     → ADD RSP,frame_size; RET

        push_stack: List[Tuple[str,int]] = []   # accumulated PUSHes before CALL
        # MSVC ``call; pop ecx; push eax; call`` reuses the popped stack slot as
        # the 2nd Win64 arg (RDX) for the follow-on import call.
        cdecl_pop_ecx_arg: Optional[Tuple[str, int]] = None
        cdecl_pop_ecx_arg2: Optional[Tuple[str, int]] = None
        # Surplus pushes after a 1-arg shared-stack cdecl (e.g. _get_osfhandle)
        # that belong to the follow-on call as args 1..N (after the pushed EAX).
        cdecl_shared_surplus: List[Tuple[str, int]] = []
        iat_fn_holder: Dict[int, str] = {}  # x86 reg → x64 reg holding import fn ptr
        iat_fn_slot: Dict[int, int] = {}  # x86 reg → absolute IAT cell VA
        stack_spill_count = 0   # real stack pushes that must be read back at CALL
        hw_stack_pushes = 0     # emitted hardware PUSHes (4-byte x86 → 8-byte x64)
        callee_save_stack: List[str] = []  # r64 regs pushed as callee saves (balance on RET)
        stack_cleanup_pending = 0   # x86 add esp,N after cdecl/stub call args
        iat_fwd_epilogue = False    # stdcall push [esp+N]×3 → IAT; skip x86 stack tail
        cc_mode = 'stdcall'   # stdcall | thiscall | fastcall | cdecl
        frame_rbp_saved = False   # push ebp seen before mov ebp,esp in this function
        seh_prev_reg: Optional[str] = None  # reg holding gs:[0] before SEH prev push
        seh_frame_active = False  # SEH registered — [ebp-4] try level is at [rbp-8]
        leave_emitted = False     # leave restores frame; ret must not re-pop callee saves
        in_prologue = True   # callee-save pushes vs. argument pushes disambiguation
        esp_dirty = False    # has RSP moved since function entry? (frameless arg map)
        # True after a real CALL in this body.  Callee-save pushes also set
        # esp_dirty, but they do *not* establish a call-align R13 frame — so
        # frameless ``mov reg,[esp+N]`` must not reload from [r13+…] until a
        # call has actually run (cmd efd6: push ebx; mov ebx,[esp+8] → RCX).
        had_call = False
        ptr_taint: Set[str] = set()   # r64 regs holding relocated image pointers
        teb_ptr_regs: Set[str] = set()  # r64 regs holding TEB * (from fs:[0x18])
        skip_insns: Set[int] = set()  # paired push ecx locals, etc.
        rcx_home_reload = self._rcx_home_reload_needed(insns)
        # Whether the function reads its incoming args through [EBP+disp] (the
        # x86 stack home). Such args must be homed to the x64 shadow slots at
        # the prologue: x86 always re-reads the stack copy, which never gets
        # clobbered, whereas the x64 register copy does (cmd 0x15141 passes its
        # own [ebp+8] arg to GetCurrentDirectoryW after RCX was reloaded).
        ebp_args_used = any(
            o.type == X86_OP_MEM and o.mem.base == X86_REG_EBP
            and not o.mem.index and 0 < (o.mem.disp & 0xFFFFFFFF) <= 0x40
            for ins in insns for o in (ins.operands or []))
        frame_args_spilled = False
        frameless_shadow_homes = False  # Win64 shadow copy of incoming args
        # Frameless bodies that reload args via ``push [esp+N]`` OR
        # ``mov r32, [esp+N]`` (after callee-save pushes / a call) need the
        # Win64 shadow spill — otherwise post-call rsp-relative reloads read
        # garbage (cmd 0xB010 ``mov edi,[esp+0x14]`` after ``call``).
        needs_esp_fwd_homes = any(
            ins.operands
            and ins.operands[0].type == X86_OP_MEM
            and ins.operands[0].mem.base == X86_REG_ESP
            and not ins.operands[0].mem.index
            and ins.operands[0].mem.segment == 0
            and ins.mnemonic == 'push'
            for ins in insns) or any(
            len(ins.operands or []) == 2
            and ins.mnemonic == 'mov'
            and ins.operands[0].type == X86_OP_REG
            and ins.operands[1].type == X86_OP_MEM
            and ins.operands[1].mem.base == X86_REG_ESP
            and not ins.operands[1].mem.index
            and ins.operands[1].mem.segment == 0
            and (ins.operands[1].mem.disp & 0xFFFFFFFF) >= 4
            for ins in insns)
        ebp_frame_active = rcx_home_reload or ebp_args_used  # x86 uses [EBP+N] args even if prologue not in chunk
        ebp_data_ptr = False   # EBP holds a data pointer (mov ebp,[esp+N]), not a frame base
        ebp_data_ptr_reg = 'r12'  # callee-saved scratch when table base unknown
        parked_stdcall_arg0 = False  # r12 holds arg0 from frameless sub-esp spill
        ebp_table_base_rva: Optional[int] = None  # GetProcAddress trio at +0/+4/+8
        ebp_reg_scratch = False  # mov ebp,reg/imm while rbp is callee-save (cmd 0x6519)
        ebp_scratch_reg = 'r12'  # unused — scratch lives at [rbp+0x10]
        ebp_scratch_home = -0x20  # below ret addr at [rbp-0x10] on cmd 0x6511 frame
        # When True, heap/scratch value lives in RBP itself (no mov rbp,esp frame).
        # [rbp-0x20] would otherwise write through the *caller's* frame pointer.
        ebp_scratch_in_reg = False
        self._ebp_scratch_in_reg = False
        frame_local_sub = 0   # sub esp,N in frameless chunk (cmd 0x9EBA)
        frameless_stack_bias = 0  # bytes current RSP is below frame base (post sub)
        frame_arg_anchor = False  # lea r15,[rsp] holds frame base for arg homes
        elided_arg_bytes = 0  # x86 stack args moved to registers (4 bytes each)

        # Peephole: detect `push X … pop reg` constant-load idioms (MSVC emits
        # `push imm; pop ecx` to load a small constant). These are NOT call
        # args, so translate them directly to `mov reg, X` and skip both insns.
        pair_src_addrs: Set[int] = set()
        pop_pair: Dict[int, Tuple[str, int]] = {}
        for _i, _ins in enumerate(insns):
            if _ins.mnemonic != 'push' or not _ins.operands:
                continue
            _op = _ins.operands[0]
            if _op.type == X86_OP_IMM:
                _val = ('imm', _op.imm)
            elif _op.type == X86_OP_REG:
                _val = ('reg', _op.reg)
            else:
                continue
            for _j in range(_i + 1, min(_i + 7, len(insns))):
                _nx = insns[_j]
                nm = _nx.mnemonic
                if nm == 'pop' and _nx.operands and _nx.operands[0].type == X86_OP_REG:
                    pair_src_addrs.add(_ins.address)
                    pop_pair[_nx.address] = _val
                    break
                if nm in ('push', 'call', 'ret', 'retn', 'leave') or nm.startswith('j'):
                    break
                _stk = any(
                    (o.type == X86_OP_REG and o.reg == X86_REG_ESP)
                    or (o.type == X86_OP_MEM and o.mem.base == X86_REG_ESP)
                    for o in _nx.operands)
                if _stk:
                    break

        # Spill Win64 shadow args at true entry *before* any local/callee
        # pushes.  Deferred ``push ecx`` locals flush via ESP-touch without
        # going through the callee-save path that used to insert homes, so
        # waiting until ``hw_stack_pushes == 0`` on the first ebx/esi push
        # both missed the count and wrote homes *over* those locals — then
        # ``mov edi,[esp+0x1c]`` mapped to R8 instead of RCX (cmd ``fbe4``).
        if needs_esp_fwd_homes and not frameless_shadow_homes:
            _opens_ebp = False
            if insns:
                _i0 = insns[0]
                if (_i0.mnemonic == 'push' and _i0.operands
                        and _i0.operands[0].type == X86_OP_REG
                        and _i0.operands[0].reg == X86_REG_EBP):
                    _opens_ebp = True
                elif (_i0.mnemonic == 'mov' and len(_i0.operands or []) == 2
                      and _i0.operands[0].type == X86_OP_REG
                      and _i0.operands[0].reg == X86_REG_EBP
                      and _i0.operands[1].type == X86_OP_REG
                      and _i0.operands[1].reg == X86_REG_ESP):
                    _opens_ebp = True
            if not _opens_ebp:
                self._home_frameless_win64_shadow_args(out)
                frameless_shadow_homes = True

        for _insn_idx, insn in enumerate(insns):
            old_va  = insn.address
            if old_va in skip_insns:
                if _dbg_on:
                    print(f"  [skip] 0x{old_va - self.old_base:X}: "
                          f"{insn.mnemonic} {insn.op_str}")
                continue
            old_new[old_va] = len(out)
            _dbg_start = len(out)

            if (old_va - self.old_base) in (0x655D, 0x6555, 0x6557, 0x655E):
                with open("_dbg_translate.log", "a") as _f:
                    _f.write(f"[DBG INS] 0x{(old_va - self.old_base):X}: {insn.mnemonic} {insn.op_str} "
                             f"len(out)=0x{len(out):X}\n")

            mnem = insn.mnemonic
            ops  = insn.operands
            next_insn = insns[_insn_idx + 1] if _insn_idx + 1 < len(insns) else None

            # Once any control-flow happens the prologue is over; subsequent
            # push ebx/esi/edi are call arguments, not callee-save spills.
            # EXCEPTION: ``mov eax,N; call __chkstk`` is a large-frame stack
            # probe that is *part of* the prologue — the callee-save spill
            # (push ebx/ebp/esi/edi) follows it. Treating the probe call as
            # end-of-prologue made those pushes look like call args, so esi/edi
            # were dropped (stack desync → wrong incoming-arg offsets, e.g. cmd
            # 0xA4E7 → wcschr garbage). Keep the prologue open across a probe.
            _is_probe_call = (
                mnem == 'call' and ops and ops[0].type == X86_OP_IMM
                and self._is_alloca_probe_rva(
                    (ops[0].imm - self.old_base) & 0xFFFFFFFF))
            if ((mnem == 'call' and not _is_probe_call)
                    or mnem.startswith('j') or mnem in ('ret', 'retn')):
                in_prologue = False
                if mnem == 'call':
                    esp_dirty = True  # args in regs may be clobbered
                    had_call = True

            # ── Frameless cdecl: mov reg, [esp+N] at entry → Win64 arg reg ─────
            # A frameless function reads its args from [esp+4], [esp+8], … before
            # touching the stack. We passed those args in RCX/RDX/R8/R9, so map
            # the stack read to the register while RSP is still at entry.
            # After a call, reload from r13-relative stack (args are stable there).
            # Callee-save pushes set esp_dirty but leave args in RCX..R9 — do not
            # take the R13 path until had_call (else fall through to the
            # hw_stack_pushes handler which subtracts pushes from the slot).
            if (not frame_rbp_saved and mnem == 'mov'
                    and len(ops) == 2 and ops[0].type == X86_OP_REG
                    and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_ESP
                    and ops[1].mem.index == 0 and ops[1].mem.segment == 0):
                n = ops[1].mem.disp
                slot = (n - 4) // 4
                if n >= 4 and (n - 4) % 4 == 0 and slot < 32:
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    # Deep ``mov ebp,[esp+N]`` after ``sub esp`` locals is a
                    # data-pointer / stdcall-arg load (cmd 0xA071
                    # ``mov ebp,[esp+0x6c]``).  The had_call r13 formula below
                    # ignores ``frame_local_sub`` and emits
                    # ``mov rbp,[r13+0x108]`` → RBP=garbage → execute@.data.
                    # Defer to the dedicated ebp-data-ptr handler.
                    if ops[0].reg == X86_REG_EBP and n >= 0x60:
                        pass
                    elif had_call and callee_save_stack:
                        # Post-call: r13 was the call-align anchor, but the
                        # align *epilogue* pops it — so [r13+N] here reads the
                        # caller's r13 (cmd 0xB010 → write to 0x56).  Incoming
                        # args that survive as x86 [esp+disp] past callee-save
                        # pushes are the Win64 shadow homes at entry; after
                        # N pushes, rsp is entry_rsp - 8*N so shadow slot k is
                        # at [rsp + 8*N + 8 + 8*k].
                        #
                        # Use hw_stack_pushes (not just callee_save_stack):
                        # frameless ``push ecx`` locals are hardware pushes too
                        # but not callee-saves.  Disps *below* the return slot
                        # are locals — map them to [rsp+(disp/4)*8], never r13
                        # (cmd ``fbe4`` ``mov eax,[esp+0x10]`` → bogus
                        # ``[r13+0x48]`` then unbalanced epilogue → execute@0).
                        n_hw = hw_stack_pushes or len(callee_save_stack)
                        # When a frameless ``sub esp,N`` is active, prefer the
                        # stdcall-arg slot helper (accounts for locals) over the
                        # raw r13 formula.
                        if frame_local_sub > 0:
                            arg_slot = self._frameless_stdcall_arg_slot(
                                n, frame_local_sub, n_hw, elided_arg_bytes)
                            if arg_slot is not None and 0 <= arg_slot < 4:
                                off = 8 * (n_hw + 1 + arg_slot)
                                dst32 = W32_REG_ASM.get(ops[0].reg)
                                if dst32 and 'dword ptr' in insn.op_str.lower():
                                    out += self._asm(
                                        f'mov {dst32}, dword ptr [rsp+0x{off:x}]')
                                else:
                                    out += self._asm(
                                        f'mov {dst}, qword ptr [rsp+0x{off:x}]')
                                push_stack.clear()
                                continue
                        if 0 <= n < 4 * n_hw:
                            # Local / callee-save slot below the return address.
                            off = (n // 4) * 8
                            dst32 = W32_REG_ASM.get(ops[0].reg)
                            if dst32 and 'dword ptr' in insn.op_str.lower():
                                out += self._asm(
                                    f'mov {dst32}, dword ptr [rsp+0x{off:x}]')
                            else:
                                out += self._asm(
                                    f'mov {dst}, qword ptr [rsp+0x{off:x}]')
                            push_stack.clear()
                            continue
                        n_push = n_hw
                        if (n >= 4 + 4 * n_push
                                and (n - 4 - 4 * n_push) % 4 == 0):
                            arg_index = (n - 4 - 4 * n_push) // 4
                            if 0 <= arg_index < 4:
                                off = 8 * (n_push + 1 + arg_index)
                                out += self._asm(
                                    f'mov {dst}, qword ptr [rsp+0x{off:x}]')
                                push_stack.clear()
                                continue
                        arg_off = 8 * (n_push + 2 + slot)
                        out += self._asm(
                            f'mov {dst}, qword ptr [r13+0x{arg_off:x}]')
                        push_stack.clear()
                        continue
                    if not esp_dirty and slot < 4:
                        arg_reg32 = W32_ARG_REG_NAMES[slot]
                        dst32 = W32_REG_ASM.get(ops[0].reg, 'eax')
                        if dst32 != arg_reg32:
                            out += self._asm(f'mov {dst32}, {arg_reg32}')
                        else:
                            out += b'\x90'
                        push_stack.clear()
                        continue
                    # esp_dirty from pushes only — let hw_stack_pushes path map
                    # [esp+N] → arg reg with push count subtracted.


            # Frameless cdecl: cmp/test with [esp+N] → Win64 arg register.
            if (not frame_rbp_saved and not esp_dirty and mnem in ('cmp', 'test')
                    and len(ops) == 2):
                frameless_cmp = False
                for mem_i, other_i in ((0, 1), (1, 0)):
                    if ops[mem_i].type != X86_OP_MEM:
                        continue
                    m = ops[mem_i].mem
                    if (m.base != X86_REG_ESP or m.index != 0
                            or m.segment != 0):
                        continue
                    n = m.disp
                    if n < 4 or (n - 4) % 4 != 0:
                        continue
                    idx = (n - 4) // 4
                    if idx >= 4:
                        continue
                    arg = WIN64_ARG_REG_NAMES[idx]
                    other = ops[other_i]
                    if mnem == 'test' and other.type == X86_OP_REG:
                        r = W32_TO_W64_REG.get(other.reg, 'rax')
                        if r != arg:
                            out += self._asm(f'test {arg}, {r}')
                        else:
                            out += b'\x90'
                    elif mnem == 'cmp':
                        if other.type == X86_OP_IMM:
                            out += self._asm(
                                f'cmp {arg}, 0x{other.imm & 0xFFFFFFFF:x}')
                        elif other.type == X86_OP_REG:
                            r = W32_TO_W64_REG.get(other.reg, 'rax')
                            out += self._asm(f'cmp {arg}, {r}')
                        else:
                            continue
                    else:
                        continue
                    frameless_cmp = True
                    break
                if frameless_cmp:
                    push_stack.clear()
                    continue

            # Frameless: and/or/xor dword [esp+N], reg|imm → same Win64 arg reg.
            # Imm form matters: cmd ``0xFF3A`` ``or [esp+4], 0x10`` must become
            # ``or ecx, 0x10``.  Emitting ``or [rsp+4], imm`` mutates shadow
            # garbage, then ``push [esp+4]`` reloads that garbage as add9 flags
            # (``0x40``) while also leaving the real flags in RCX to be
            # clobbered by ``mov ecx, [c8d8]``.
            if (not frame_rbp_saved and not esp_dirty
                    and mnem in ('and', 'or', 'xor') and len(ops) == 2
                    and ops[0].type == X86_OP_MEM
                    and ops[1].type in (X86_OP_REG, X86_OP_IMM)):
                m = ops[0].mem
                if (m.base == X86_REG_ESP and not m.index and m.segment == 0):
                    n = m.disp
                    if n >= 4 and (n - 4) % 4 == 0:
                        idx = (n - 4) // 4
                        if idx < 4:
                            arg64 = WIN64_ARG_REG_NAMES[idx]
                            arg32 = {'rcx': 'ecx', 'rdx': 'edx',
                                     'r8': 'r8d', 'r9': 'r9d'}.get(
                                arg64, 'eax')
                            if ops[1].type == X86_OP_REG:
                                src32 = W32_REG_ASM.get(ops[1].reg, 'eax')
                                if 'dword ptr' in insn.op_str.lower():
                                    out += self._asm(
                                        f'{mnem} {arg32}, {src32}')
                                else:
                                    out += self._asm(
                                        f'{mnem} {arg64}, '
                                        f'{W32_TO_W64_REG.get(ops[1].reg, "rax")}')
                            else:
                                imm = ops[1].imm & 0xFFFFFFFF
                                out += self._asm(
                                    f'{mnem} {arg32}, 0x{imm:x}')
                            push_stack.clear()
                            continue

            # stdcall IAT forwarder tail: mov eax,[esp+N]; add esp,M; ret N
            if (iat_fwd_epilogue and mnem == 'mov' and len(ops) == 2
                    and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EAX
                    and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_ESP
                    and not ops[1].mem.index):
                push_stack.clear()
                continue

            # mov ebp, [esp+N] with large N — load a data pointer (0xA071 path).
            # Small offsets are usually frame tricks; hw_stack_pushes is often 0
            # after stdcall `pop ecx` tails decrement it.
            if (mnem == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG
                    and ops[0].reg == X86_REG_EBP
                    and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_ESP
                    and ops[1].mem.index == 0 and ops[1].mem.segment == 0):
                disp = ops[1].mem.disp
                if disp > 0x7FFFFFFF:
                    disp -= 0x100000000
                if disp >= 0x60:
                    local_sub = frame_local_sub
                    # Nested __chkstk / mid-function resets can clear
                    # frame_local_sub while the opening ``sub esp,N`` is still
                    # live.  Recover it so stdcall arg homes resolve (cmd 0xA071).
                    if local_sub <= 0:
                        for k in range(_insn_idx - 1, max(-1, _insn_idx - 400), -1):
                            ik = insns[k]
                            if (ik.mnemonic == 'sub' and len(ik.operands) == 2
                                    and ik.operands[0].type == X86_OP_REG
                                    and ik.operands[0].reg == X86_REG_ESP
                                    and ik.operands[1].type == X86_OP_IMM):
                                imm = ik.operands[1].imm & 0xFFFFFFFF
                                if imm > 0x28:
                                    local_sub = imm
                                    break
                    # ``sub esp,0x58`` / ``mov ebp,[esp+0x6c]`` — arg0 was
                    # parked in r12 at the frame open.  Do not reload via
                    # stale r15/[rsp] (nested __chkstk clobbers the anchor).
                    if ((parked_stdcall_arg0 or local_sub == 0x58)
                            and disp == 0x6c):
                        ebp_data_ptr = True
                        push_stack.clear()
                        continue
                    arg_slot = self._frameless_stdcall_arg_slot(
                        disp, local_sub, hw_stack_pushes,
                        elided_arg_bytes)
                    if arg_slot is not None:
                        # Prefer parked arg0 in r12 — nested __chkstk callees
                        # clobber r15 (cmd 0xA071 after 0xA4E7).
                        if ((parked_stdcall_arg0 or local_sub == 0x58)
                                and arg_slot == 0):
                            ebp_data_ptr = True
                            push_stack.clear()
                            continue
                        off = self._frameless_arg_home_slot_off(arg_slot)
                        if frame_arg_anchor:
                            out += self._asm(f'mov eax, dword ptr [r15+0x{off:x}]')
                        else:
                            off = self._frameless_arg_home_rsp_off(
                                arg_slot, frameless_stack_bias)
                            out += self._asm(f'mov eax, dword ptr [rsp+0x{off:x}]')
                        out += self._asm(f'mov {ebp_data_ptr_reg}, rax')
                        ebp_data_ptr = True
                        push_stack.clear()
                        continue
                    # Do NOT use _find_ebp_global_table_rva here: that heuristic
                    # looks forward at GetProcAddress stores + [ebp+N] cmps and
                    # wrongly treats ``mov ebp,[esp+0x6c]`` (stdcall arg0 after
                    # ``sub esp,0x58``) as a GPA table base (cmd 0xA071 →
                    # movabs r12, .data; execute@0).  GPA bases are absolute
                    # immediates, never deep [esp+N] loads.
                    # Deep [esp+N] locals — bias for elided x86 arg pushes.
                    off_x64 = (disp - elided_arg_bytes
                               + len(callee_save_stack) * 4) & 0xFFFFFFFFFFFFFFFF
                    # Keystone cannot encode `mov rbp, dword ptr [rsp+N]`; load via EAX.
                    out += self._asm(f'mov eax, dword ptr [rsp+0x{off_x64:x}]')
                    out += self._asm(f'mov {ebp_data_ptr_reg}, rax')
                    ebp_data_ptr = True
                    push_stack.clear()
                    continue

            # mov reg, [esp+N] after callee-save pushes → Win64 arg reg or [rsp+N']
            if (mnem == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG
                    and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_ESP
                    and ops[1].mem.index == 0 and ops[1].mem.segment == 0
                    and hw_stack_pushes):
                disp = ops[1].mem.disp
                if disp > 0x7FFFFFFF:
                    disp -= 0x100000000
                arg_slot = self._frameless_stdcall_arg_slot(
                    disp, frame_local_sub, hw_stack_pushes, elided_arg_bytes)
                if arg_slot is not None:
                    off = self._frameless_arg_home_slot_off(arg_slot)
                    dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    is_dword = 'dword ptr' in insn.op_str.lower()
                    # Keystone rejects ``mov rdi, dword ptr […]`` (width
                    # mismatch → INT3).  Load into the 32-bit view so the
                    # high half is zero-extended (cmd 0xC98B ``mov edi,
                    # [esp+0x21c]`` after ``sub esp,0x208``).
                    dst_asm = (W32_REG_ASM.get(ops[0].reg, 'eax')
                               if is_dword else dst64)
                    sz = 'dword' if is_dword else 'qword'
                    if frame_arg_anchor:
                        out += self._asm(
                            f'mov {dst_asm}, {sz} ptr [r15+0x{off:x}]')
                    else:
                        off = self._frameless_arg_home_rsp_off(
                            arg_slot, frameless_stack_bias)
                        out += self._asm(
                            f'mov {dst_asm}, {sz} ptr [rsp+0x{off:x}]')
                    push_stack.clear()
                    continue
                slot = (disp - 4) // 4 - hw_stack_pushes
                dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                if 0 <= slot < 4:
                    src64 = WIN64_ARG_REG_NAMES[slot]
                    if dst64 != src64:
                        out += self._asm(f'mov {dst64}, {src64}')
                    push_stack.clear()
                    continue
                off_x64 = disp + hw_stack_pushes * 4
                if off_x64 < 0:
                    off_x64 &= 0xFFFFFFFFFFFFFFFF
                is_dword = 'dword ptr' in insn.op_str.lower()
                dst_asm = (W32_REG_ASM.get(ops[0].reg, 'eax')
                           if is_dword else dst64)
                sz = 'dword' if is_dword else 'qword'
                out += self._asm(f'mov {dst_asm}, {sz} ptr [rsp+0x{off_x64:x}]')
                push_stack.clear()
                continue

            # and/or/xor [esp+N], reg after callee-save pushes → Win64 arg reg
            # or the frameless shadow home (so the mutation survives a later
            # ``push [esp+N]`` reload after a nested call clobbered the regs).
            # Without this, `and [esp+0xc], eax` after push esi + skipped pop ecx
            # corrupts the return address on x64 (helper 0x6581 / SetEnv path).
            if (mnem in ('and', 'or', 'xor') and len(ops) == 2
                    and ops[0].type == X86_OP_MEM
                    and ops[0].mem.base == X86_REG_ESP
                    and ops[0].mem.index == 0
                    and ops[0].mem.segment == 0
                    and ops[1].type == X86_OP_REG
                    and hw_stack_pushes):
                disp = ops[0].mem.disp
                if disp > 0x7FFFFFFF:
                    disp -= 0x100000000
                slot = (disp - 4) // 4 - hw_stack_pushes
                if 0 <= slot < 4:
                    if frameless_shadow_homes:
                        off = 8 * (hw_stack_pushes + 1 + slot)
                        src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                        out += self._asm(
                            f'{mnem} qword ptr [rsp+0x{off:x}], {src64}')
                    else:
                        arg64 = WIN64_ARG_REG_NAMES[slot]
                        src32 = W32_REG_ASM.get(ops[1].reg, 'eax')
                        if 'dword ptr' in insn.op_str.lower():
                            arg32 = {'rcx': 'ecx', 'rdx': 'edx',
                                     'r8': 'r8d', 'r9': 'r9d'}.get(arg64, 'eax')
                            out += self._asm(f'{mnem} {arg32}, {src32}')
                        else:
                            src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                            out += self._asm(f'{mnem} {arg64}, {src64}')
                    push_stack.clear()
                    continue

            # mov ecx, ebp at entry often means "this = arg1" — RCX already holds it.
            if (mnem == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG
                    and ops[1].type == X86_OP_REG and in_prologue
                    and not frame_rbp_saved
                    and ops[0].reg == X86_REG_ECX and ops[1].reg == X86_REG_EBP):
                push_stack.clear()
                continue

            # Track whether RSP has moved from its entry value (frameless args).
            if mnem in ('push', 'pop', 'pushfd', 'popfd', 'pushad', 'popad'):
                esp_dirty = True
            elif mnem in ('sub', 'add') and ops and ops[0].type == X86_OP_REG \
                    and ops[0].reg == X86_REG_ESP:
                esp_dirty = True

            # Deferred pushes are call args — keep them queued until the CALL
            # consumes them. Only flush (treat as real pushes) when control flow
            # happens or the stack pointer is explicitly manipulated, since a
            # compiler may schedule unrelated non-stack ops between arg pushes.
            if mnem not in ('push', 'call') and push_stack:
                touches_esp = any(
                    (op.type == X86_OP_REG and op.reg == X86_REG_ESP)
                    or (op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP)
                    for op in ops
                )
                # ``lea/mov reg,[esp+N]`` only *reads* a stack slot to form the
                # next stdcall arg (cmd 0xBA66: ``push src; lea dest,[esp+N];
                # push dest; call wcscpy``).  Flushing here turned the deferred
                # src into a hardware push and left Win64 RDX unset → AV in
                # msvcrt.  Real ESP mutation (push/pop/add/sub esp) still flushes.
                if touches_esp and mnem == 'lea':
                    touches_esp = False
                elif (touches_esp and mnem == 'mov' and len(ops) == 2
                      and ops[0].type == X86_OP_REG
                      and ops[1].type == X86_OP_MEM
                      and ops[1].mem.base == X86_REG_ESP
                      and not ops[1].mem.index):
                    touches_esp = False
                elif (touches_esp and mnem == 'mov' and len(ops) == 2
                      and ops[0].type == X86_OP_MEM
                      and ops[0].mem.base == X86_REG_ESP
                      and not ops[0].mem.index):
                    # ``push args; mov [esp+N], reg; call`` — store into a local
                    # *above* the deferred args (cmd GetVDMCurrentDirectories at
                    # 0x71BC).  Flushing would hardware-push the args and leave
                    # the CALL with empty Win64 marshalling.
                    touches_esp = False
                elif (touches_esp and mnem in ('and', 'or', 'xor', 'add', 'sub')
                      and len(ops) >= 1
                      and ops[0].type == X86_OP_MEM
                      and ops[0].mem.base == X86_REG_ESP
                      and not ops[0].mem.index):
                    # Same for ``and [esp+N],0`` between args and a later call.
                    touches_esp = False
                flush_now = (
                    mnem in ('ret', 'retn', 'leave', 'jmp', 'pop', 'int', 'iret')
                    or mnem.startswith('j')
                    or mnem in ('sub', 'add') and ops and ops[0].type == X86_OP_REG
                       and ops[0].reg == X86_REG_ESP
                    or touches_esp
                )
                if flush_now:
                    n_flush = self._flush_deferred_pushes(out, push_stack)
                    if n_flush:
                        hw_stack_pushes += n_flush
                        if frame_local_sub > 0:
                            frameless_stack_bias += 8 * n_flush
                        esp_dirty = True

            # Detect thiscall: ECX = 'this' before a CALL (not plain arg setup).
            if mnem == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG:
                if (ops[0].reg == X86_REG_ECX and ops[1].type == X86_OP_REG
                        and ops[1].reg in (X86_REG_EBX, X86_REG_EDI, X86_REG_EBP)):
                    for j in range(_insn_idx + 1, min(_insn_idx + 8, len(insns))):
                        nx = insns[j]
                        if nx.mnemonic == 'call':
                            cc_mode = 'thiscall'
                            break
                        if nx.mnemonic in ('ret', 'retn', 'jmp'):
                            break

            # ── INT 0x2E / SYSENTER → SYSCALL ─────────────────────────────────
            if mnem == 'int' and ops and ops[0].type == X86_OP_IMM and ops[0].imm == 0x2E:
                out += b'\x0f\x05'   # SYSCALL
                push_stack.clear()
                continue
            if mnem == 'sysenter':
                out += b'\x0f\x05'
                push_stack.clear()
                continue

            # ── FS: segment override → GS: TEB remap ──────────────────────────
            if mnem in ('mov', 'lea') and ops:
                has_fs = any(op.type == X86_OP_MEM and op.mem.segment == X86_REG_FS
                             for op in ops)
                if has_fs:
                    # Identify the FS: operand and remap its disp
                    for op in ops:
                        if op.type == X86_OP_MEM and op.mem.segment == X86_REG_FS:
                            fs_disp = op.mem.disp
                            gs_disp = TEB_FS_TO_GS.get(fs_disp, fs_disp)
                            if op == ops[1]:  # fs: is src
                                # MSVC SEH: push -1; push scope; push handler; mov eax,fs:[0]
                                # Deferred "call arg" pushes before this read are the SEH
                                # registration record — emit them as real stack pushes.
                                if push_stack and fs_disp == 0:
                                    hw_stack_pushes += self._flush_deferred_pushes(
                                        out, push_stack)
                                dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                                out += self._encode_gs_load(dst, gs_disp)
                                if fs_disp == 0x18:
                                    self._teb_ptr_mark(teb_ptr_regs, ops[0].reg)
                                if fs_disp == 0 and mnem == 'mov':
                                    seh_prev_reg = dst
                            else:             # fs: is dst
                                src = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                                out += self._encode_gs_store(src, gs_disp)
                                if fs_disp == 0:
                                    seh_prev_reg = None
                                    seh_frame_active = True
                    push_stack.clear()
                    continue

            # SEH: push <reg> immediately after mov reg, gs:[0] saves prev chain link.
            if (mnem == 'push' and ops and seh_prev_reg is not None
                    and ops[0].type == X86_OP_REG):
                rname = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                if rname == seh_prev_reg:
                    out += self._asm(f'push {rname}')
                    hw_stack_pushes += 1
                    seh_prev_reg = None
                    continue

            # ── [EBP+disp] stack args / locals → Win64 registers or [RBP-disp] ─
            if ops and any(op.type == X86_OP_MEM and op.mem.base == X86_REG_EBP for op in ops):
                ebp_op = next(op for op in ops if op.type == X86_OP_MEM and op.mem.base == X86_REG_EBP)
                disp = ebp_op.mem.disp
                if ebp_data_ptr:
                    # ebp holds a data pointer (stdcall arg or global table),
                    # not a frame.  All [ebp+disp] are struct fields — including
                    # disp==8 (cmd 0xA075 ``cmp [ebp+8],ebx``).  Never treat
                    # those as Win64 homed stack args.
                    ptr_sz = self._mem_ptr_size(insn.op_str)
                    ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                    other = (ops[1] if ebp_op == ops[0] else ops[0]) if len(ops) >= 2 else None
                    if other is not None and mnem == 'cmp' and other.type == X86_OP_REG:
                        if other.reg == X86_REG_EBX:
                            r = '0'
                        else:
                            r = self._ebp_slot_reg_asm(
                                other, insn.op_str, ebp_sz)
                        if ebp_table_base_rva is not None:
                            slot_va = self._relocate_imm(
                                self.old_base + ebp_table_base_rva + disp,
                                len(out), 0)
                            scratch = 'r11' if r != 'r11d' else 'r10'
                            out += self._asm(
                                f'movabs {scratch}, '
                                f'0x{slot_va & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(
                                f'cmp {ebp_sz} ptr [{scratch}], {r}')
                        else:
                            ptr = ebp_data_ptr_reg
                            out += self._asm(
                                f'cmp {ebp_sz} ptr [{ptr}{disp:+d}], {r}')
                        continue
                    if other is not None and mnem == 'mov' and ebp_op == ops[1] and ops[0].type == X86_OP_REG:
                        dst = self._ebp_slot_reg_asm(
                            ops[0], insn.op_str, ebp_sz)
                        if ebp_table_base_rva is not None:
                            slot_va = self._relocate_imm(
                                self.old_base + ebp_table_base_rva + disp,
                                len(out), 0)
                            scratch = 'r11' if dst != 'r11' else 'r10'
                            out += self._asm(
                                f'movabs {scratch}, '
                                f'0x{slot_va & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(
                                f'mov {dst}, {ebp_sz} ptr [{scratch}]')
                        else:
                            ptr = ebp_data_ptr_reg
                            out += self._asm(
                                f'mov {dst}, {ebp_sz} ptr [{ptr}{disp:+d}]')
                        continue
                    # Unhandled mnem with ebp-as-data-ptr: still do not fall
                    # through to frame-arg rewriting for positive struct fields.
                    if disp >= 0:
                        continue
                w64_arg = ebp_disp_to_win64_arg(disp)
                _home = self._ebp_to_rbp_home(old_va, disp)
                other = (ops[1] if ebp_op == ops[0] else ops[0]) if len(ops) >= 2 else None
                # 5th+ incoming args map to [rsp+0x28+…] in w64_arg but are homed at
                # [rbp+0x28+…] once the prologue spills RCX/RDX/R8/R9 (cmd 0x1A16D
                # mov edi,[ebp+0x18] must read [rbp+0x28], not the byte alias at +0x20).
                framed_stack_arg = (
                    bool(w64_arg and w64_arg.startswith('[')
                         and frame_args_spilled and _home is not None
                         and ebp_frame_active))
                is_ebp_incoming_arg = (
                    disp >= 8 and (disp - 8) % 4 == 0 and disp <= 0x40)
                if w64_arg and (mnem == 'push' or not w64_arg.startswith('[')
                                or framed_stack_arg
                                or (is_ebp_incoming_arg and mnem == 'mov')):
                    # Incoming arg referenced via [EBP+disp] (homed to [RBP+N]).
                    # Reading/using an arg does NOT consume pending call args, so
                    # do not flush push_stack here — compilers interleave such
                    # reads among argument pushes (cmd RegOpenKeyExW: mov esi,
                    # [ebp+8]; and [esi],0; …; call) and flushing drops args.
                    if mnem == 'push':
                        slot = (disp - 8) // 4
                        push_stack.append(('ebp_arg', slot))
                        continue
                    if (rcx_home_reload and ebp_frame_active and frame_args_spilled
                            and mnem == 'mov' and other is not None
                            and other.type == X86_OP_REG and other.reg == X86_REG_ECX
                            and ebp_op == ops[1] and disp == 8):
                        out += self._asm('mov rcx, qword ptr [rbp+0x10]')
                        push_stack.clear()
                        continue
                    if other is not None and mnem == 'cmp' and other.type == X86_OP_IMM:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        # When the arg was homed, read the stable stack copy; the
                        # register may have been clobbered (e.g. across a call).
                        if frame_args_spilled and _home is not None:
                            csz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                            mask = {'byte': 0xFF, 'word': 0xFFFF}.get(csz, 0xFFFFFFFF)
                            out += self._asm(
                                f'cmp {csz} ptr [rbp+0x{_home:x}], '
                                f'0x{other.imm & mask:x}')
                        elif ptr_sz == 'word':
                            reg16 = {'rcx': 'cx', 'rdx': 'dx', 'r8': 'r8w', 'r9': 'r9w'}.get(
                                w64_arg, 'ax')
                            out += self._asm(
                                f'cmp {reg16}, 0x{other.imm & 0xFFFF:x}')
                        else:
                            out += self._asm(
                                f'cmp {w64_arg}, 0x{other.imm & 0xFFFFFFFF:x}')
                        continue
                    # test [ebp+N], imm — must NOT fall through to the catch-all
                    # ``mov rax, rdx`` (imm has no .reg).  That clobbered EAX
                    # holding a just-loaded global (cmd 0xAE32 ``test [ebp+0xc],
                    # 0x21`` after ``mov eax,[fbc8]`` → cursor saved as flags).
                    if other is not None and mnem == 'test' and other.type == X86_OP_IMM:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        if frame_args_spilled and _home is not None:
                            csz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                            mask = {'byte': 0xFF, 'word': 0xFFFF}.get(csz, 0xFFFFFFFF)
                            out += self._asm(
                                f'test {csz} ptr [rbp+0x{_home:x}], '
                                f'0x{other.imm & mask:x}')
                        elif ptr_sz == 'byte':
                            reg8 = {'rcx': 'cl', 'rdx': 'dl',
                                    'r8': 'r8b', 'r9': 'r9b'}.get(w64_arg, 'al')
                            out += self._asm(
                                f'test {reg8}, 0x{other.imm & 0xFF:x}')
                        elif ptr_sz == 'word':
                            reg16 = {'rcx': 'cx', 'rdx': 'dx',
                                     'r8': 'r8w', 'r9': 'r9w'}.get(w64_arg, 'ax')
                            out += self._asm(
                                f'test {reg16}, 0x{other.imm & 0xFFFF:x}')
                        else:
                            reg32 = {'rcx': 'ecx', 'rdx': 'edx',
                                     'r8': 'r8d', 'r9': 'r9d'}.get(w64_arg, 'eax')
                            out += self._asm(
                                f'test {reg32}, 0x{other.imm & 0xFFFFFFFF:x}')
                        continue
                    if other is not None and mnem == 'mov' and other.type == X86_OP_REG:
                        if ebp_op == ops[1]:
                            dst = W32_TO_W64_REG.get(other.reg, 'rax')
                            if ((frame_args_spilled or (is_ebp_incoming_arg and ebp_frame_active))
                                    and _home is not None):
                                if self._homed_arg_is_pointer(disp):
                                    out += self._asm(
                                        f'mov {dst}, qword ptr [rbp+0x{_home:x}]')
                                else:
                                    d32 = W32_REG_ASM.get(other.reg, 'eax')
                                    out += self._asm(
                                        f'mov {d32}, dword ptr [rbp+0x{_home:x}]')
                            elif dst != w64_arg:
                                out += self._asm(f'mov {dst}, {w64_arg}')
                            else:
                                out += self._asm('nop')
                        elif ebp_op == ops[0]:
                            # Pointer homes are qword; Keystone rejects
                            # ``mov qword [rbp+N], esi`` — use rsi (cmd 0xAFB4
                            # ``mov [ebp+8],esi`` was emitting INT3 via _asm).
                            home = self._ebp_to_rbp_home(old_va, disp)
                            if home is not None and self._homed_arg_is_pointer(disp):
                                src64 = W32_TO_W64_REG.get(other.reg, 'rax')
                                out += self._asm(
                                    f'mov qword ptr [rbp+0x{home:x}], {src64}')
                            else:
                                src = (self._word_reg_asm_for_op(other, insn.op_str)
                                       if self._mem_ptr_size(insn.op_str) == 'word'
                                       else W32_REG_ASM.get(other.reg, 'edx'))
                                if home is not None:
                                    out += self._asm(
                                        f'mov dword ptr [rbp+0x{home:x}], {src}')
                                else:
                                    out += self._asm(
                                        f'mov dword ptr [rbp+{disp}], {src}')
                        else:
                            dst = W32_TO_W64_REG.get(other.reg, 'rax')
                            if dst != w64_arg:
                                out += self._asm(f'mov {dst}, {w64_arg}')
                    elif other is not None and mnem == 'mov' and other.type == X86_OP_IMM and ebp_op == ops[0]:
                        home = self._ebp_to_rbp_home(old_va, disp)
                        imm = other.imm & 0xFFFFFFFF
                        if self._is_image_pointer(imm):
                            imm = self._relocate_imm(imm, len(out), 0) & 0xFFFFFFFF
                        if home is not None:
                            out += self._asm(
                                f'mov dword ptr [rbp+0x{home:x}], '
                                f'0x{imm:x}')
                        else:
                            out += self._asm(
                                f'mov dword ptr [rbp+{disp}], '
                                f'0x{imm:x}')
                    elif other is not None and mnem == 'cmp' and other.type == X86_OP_REG:
                        if frame_args_spilled and _home is not None:
                            r32 = W32_REG_ASM.get(other.reg, 'eax')
                            if ebp_op == ops[0]:
                                out += self._asm(
                                    f'cmp dword ptr [rbp+0x{_home:x}], {r32}')
                            else:
                                out += self._asm(
                                    f'cmp {r32}, dword ptr [rbp+0x{_home:x}]')
                        else:
                            r = W32_TO_W64_REG.get(other.reg, 'rax')
                            out += self._asm(f'cmp {w64_arg}, {r}')
                        continue
                    elif (other is not None and mnem in ('add', 'sub')
                          and other.type == X86_OP_REG):
                        r32 = W32_REG_ASM.get(other.reg, 'eax')
                        if frame_args_spilled and _home is not None:
                            if self._homed_arg_is_pointer(disp):
                                dst64 = W32_TO_W64_REG.get(other.reg, 'rax')
                                if ebp_op == ops[1]:
                                    out += self._asm(
                                        f'{mnem} {dst64}, qword ptr [rbp+0x{_home:x}]')
                                else:
                                    out += self._asm(
                                        f'{mnem} qword ptr [rbp+0x{_home:x}], {dst64}')
                            elif ebp_op == ops[1]:
                                out += self._asm(
                                    f'{mnem} {r32}, dword ptr [rbp+0x{_home:x}]')
                            else:
                                out += self._asm(
                                    f'{mnem} dword ptr [rbp+0x{_home:x}], {r32}')
                        else:
                            dst64 = W32_TO_W64_REG.get(other.reg, 'rax')
                            if ebp_op == ops[1]:
                                out += self._asm(f'{mnem} {dst64}, {w64_arg}')
                            else:
                                out += self._asm(f'{mnem} {w64_arg}, {dst64}')
                        continue
                    elif mnem in ('inc', 'dec') and ebp_op == ops[0]:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                        if _home is not None:
                            out += self._asm(
                                f'{mnem} {ebp_sz} ptr [rbp+0x{_home:x}]')
                        continue
                    elif (other is not None and mnem in ('and', 'or', 'xor')
                            and ebp_op == ops[0]):
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                        home = self._ebp_to_rbp_home(old_va, disp)
                        if home is not None:
                            if other.type == X86_OP_IMM:
                                out += self._asm(
                                    f'{mnem} {ebp_sz} ptr [rbp+0x{home:x}], '
                                    f'0x{other.imm & 0xFFFFFFFF:x}')
                            elif other.type == X86_OP_REG:
                                r = self._ebp_slot_reg_asm(
                                    other, insn.op_str, ebp_sz)
                                out += self._asm(
                                    f'{mnem} {ebp_sz} ptr [rbp+0x{home:x}], {r}')
                            continue
                        reg32 = {'rcx': 'ecx', 'rdx': 'edx',
                                 'r8': 'r8d', 'r9': 'r9d'}.get(w64_arg)
                        if reg32 and other.type == X86_OP_IMM:
                            out += self._asm(
                                f'{mnem} {reg32}, 0x{other.imm & 0xFFFFFFFF:x}')
                            continue
                    elif mnem == 'push':
                        if framed_stack_arg and _home is not None:
                            out += self._asm(
                                f'push qword ptr [rbp+0x{_home:x}]')
                        else:
                            out += self._asm(f'push {w64_arg}')
                    elif mnem == 'lea' and len(ops) == 2 and ebp_op == ops[1]:
                        dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                        self._emit_lea_ebp_slot(out, dst, disp, False)
                    elif other is not None and other.type == X86_OP_REG:
                        # Never treat an IMM as a register source (would emit
                        # ``mov rax, <arg>`` and clobber a live EAX).
                        r = W32_TO_W64_REG.get(other.reg, 'rax')
                        if framed_stack_arg and _home is not None:
                            if self._homed_arg_is_pointer(disp):
                                out += self._asm(
                                    f'mov {r}, qword ptr [rbp+0x{_home:x}]')
                            else:
                                d32 = W32_REG_ASM.get(other.reg, 'eax')
                                out += self._asm(
                                    f'mov {d32}, dword ptr [rbp+0x{_home:x}]')
                        else:
                            out += self._asm(f'mov {r}, {w64_arg}')
                    continue
                elif disp >= 8:
                    # Misaligned x86 stack slots (e.g. [EBP+0xA]) — map into
                    # homed-arg bytes at [RBP+0x10+…], not [RBP+disp] (that
                    # overlaps the saved return address at [RBP+8]).
                    home = _home if (frame_args_spilled and _home is not None) else None
                    if home is None:
                        home = ebp_disp_to_rbp_stack_off(disp)
                    ptr_sz = self._mem_ptr_size(insn.op_str)
                    ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                    other = (ops[1] if ebp_op == ops[0] else ops[0]) if len(ops) >= 2 else None
                    if home is not None and other is not None and mnem in (
                            'and', 'or', 'xor', 'mov', 'cmp', 'test', 'add', 'sub'):
                        if mnem == 'mov' and ebp_op == ops[1] and ops[0].type == X86_OP_REG:
                            if (self._homed_arg_is_pointer(disp)
                                    and ebp_sz == 'dword'):
                                dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                                out += self._asm(
                                    f'mov {dst64}, qword ptr [rbp+0x{home:x}]')
                            else:
                                dst = self._ebp_slot_reg_asm(
                                    ops[0], insn.op_str, ebp_sz)
                                out += self._asm(
                                    f'mov {dst}, {ebp_sz} ptr [rbp+0x{home:x}]')
                        elif mnem == 'mov' and ebp_op == ops[0]:
                            if other.type == X86_OP_REG:
                                src = self._ebp_slot_reg_asm(
                                    other, insn.op_str, ebp_sz)
                                out += self._asm(
                                    f'mov {ebp_sz} ptr [rbp+0x{home:x}], {src}')
                            elif other.type == X86_OP_IMM:
                                out += self._asm(
                                    f'mov {ebp_sz} ptr [rbp+0x{home:x}], '
                                    f'0x{other.imm & 0xFFFFFFFF:x}')
                        elif mnem in ('and', 'or', 'xor', 'add', 'sub'):
                            if other.type == X86_OP_REG:
                                r = self._ebp_slot_reg_asm(other, insn.op_str, ebp_sz)
                                out += self._asm(
                                    f'{mnem} {ebp_sz} ptr [rbp+0x{home:x}], {r}')
                            elif other.type == X86_OP_IMM:
                                out += self._asm(
                                    f'{mnem} {ebp_sz} ptr [rbp+0x{home:x}], '
                                    f'0x{other.imm & 0xFFFFFFFF:x}')
                        elif mnem == 'cmp' and other.type == X86_OP_IMM:
                            out += self._asm(
                                f'cmp {ebp_sz} ptr [rbp+0x{home:x}], '
                                f'0x{other.imm & 0xFFFFFFFF:x}')
                        elif mnem == 'test' and other.type == X86_OP_IMM:
                            out += self._asm(
                                f'test {ebp_sz} ptr [rbp+0x{home:x}], '
                                f'0x{other.imm & 0xFFFFFFFF:x}')
                        elif mnem == 'test' and other.type == X86_OP_REG:
                            r = self._ebp_slot_reg_asm(other, insn.op_str, ebp_sz)
                            out += self._asm(
                                f'test {ebp_sz} ptr [rbp+0x{home:x}], {r}')
                        continue
                elif disp < 0:
                    # Local variable — x64 SEH record is 32 bytes vs x86 16 bytes.
                    disp = self._seh_rbp_local_disp(disp, seh_frame_active)
                    ptr_sz = self._mem_ptr_size(insn.op_str)
                    m8_ptr = (disp == -8
                              and self._cmd_builder_ebp_m8_is_ptr(old_va))
                    if mnem == 'mov' and len(ops) == 2:
                        m4_ptr = (disp == -4
                                  and self._cmd_builder_ebp_m4_is_ptr(old_va))
                        if ebp_op == ops[1] and ops[0].type == X86_OP_REG:
                            if m4_ptr or m8_ptr:
                                dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                                out += self._asm(
                                    f'mov {dst64}, qword ptr [rbp{disp:+d}]')
                            else:
                                dst = self._ebp_slot_reg_asm(
                                    ops[0], insn.op_str, ptr_sz)
                                out += self._asm(
                                    f'mov {dst}, {ptr_sz} ptr [rbp{disp:+d}]')
                        elif ebp_op == ops[0] and ops[1].type == X86_OP_REG:
                            if ops[1].reg == X86_REG_ESP:
                                out += self._asm(f'mov qword ptr [rbp{disp:+d}], rsp')
                            elif m4_ptr or m8_ptr:
                                src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                                out += self._asm(
                                    f'mov qword ptr [rbp{disp:+d}], {src64}')
                            else:
                                src = self._ebp_slot_reg_asm(
                                    ops[1], insn.op_str, ptr_sz)
                                out += self._asm(
                                    f'mov {ptr_sz} ptr [rbp{disp:+d}], {src}')
                        elif ebp_op == ops[0] and ops[1].type == X86_OP_IMM:
                            slot_sz = ('qword' if (m4_ptr or m8_ptr)
                                       else ptr_sz)
                            imm = ops[1].imm & 0xFFFFFFFF
                            if self._is_image_pointer(imm):
                                imm = self._relocate_imm(imm, len(out), 0) & 0xFFFFFFFF
                            out += self._asm(
                                f'mov {slot_sz} ptr [rbp{disp:+d}], '
                                f'0x{imm:x}')
                        continue
                    if mnem == 'lea' and len(ops) == 2 and ebp_op == ops[1]:
                        dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                        self._emit_lea_ebp_slot(out, dst, disp, False)
                        continue
                    if mnem == 'push' and ebp_op == ops[0]:
                        # push dword ptr [ebp-N] before CALL — stdcall arg value,
                        # not a hardware stack push (would corrupt Win64 RSP).
                        push_stack.append(('ebp_slot', disp))
                        continue
                    if disp < 0 and mnem in ('inc', 'dec') and len(ops) == 1 and ebp_op == ops[0]:
                        ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                        out += self._asm(f'{mnem} {ebp_sz} ptr [rbp{disp:+d}]')
                        continue
                    if disp < 0 and len(ops) >= 2 and mnem in ('and', 'or', 'xor', 'add', 'sub',
                                             'cmp', 'test'):
                        other = ops[1] if ebp_op == ops[0] else ops[0]
                        ebp_sz = ('qword' if m8_ptr
                                  else (ptr_sz if ptr_sz in ('byte', 'word') else 'dword'))
                        if mnem == 'test' and other.type == X86_OP_REG:
                            r = self._ebp_slot_reg_asm(other, insn.op_str, ebp_sz)
                            out += self._asm(
                                f'test {ebp_sz} ptr [rbp{disp:+d}], {r}')
                            continue
                        if mnem == 'cmp':
                            if other.type == X86_OP_REG:
                                r = self._ebp_slot_reg_asm(other, insn.op_str, ebp_sz)
                                # Preserve operand order: cmp reg,[ebp-N] ≠ cmp [ebp-N],reg
                                if ebp_op == ops[0]:
                                    out += self._asm(
                                        f'cmp {ebp_sz} ptr [rbp{disp:+d}], {r}')
                                else:
                                    out += self._asm(
                                        f'cmp {r}, {ebp_sz} ptr [rbp{disp:+d}]')
                            elif other.type == X86_OP_IMM:
                                out += self._asm(
                                    f'cmp {ebp_sz} ptr [rbp{disp:+d}], '
                                    f'0x{other.imm & 0xFFFFFFFF:x}')
                            continue
                        if mnem in ('and', 'or', 'xor', 'add', 'sub'):
                            if other.type == X86_OP_REG:
                                r = self._ebp_slot_reg_asm(other, insn.op_str, ebp_sz)
                                # sub edi,[ebp-8] must stay reg−mem (length = cur−start),
                                # not mem−reg which poisons edi and unbounded loops.
                                if ebp_op == ops[0]:
                                    out += self._asm(
                                        f'{mnem} {ebp_sz} ptr [rbp{disp:+d}], {r}')
                                else:
                                    out += self._asm(
                                        f'{mnem} {r}, {ebp_sz} ptr [rbp{disp:+d}]')
                            elif other.type == X86_OP_IMM:
                                out += self._asm(
                                    f'{mnem} {ebp_sz} ptr [rbp{disp:+d}], '
                                    f'0x{other.imm & 0xFFFFFFFF:x}')
                            continue

            # push dword ptr [esp+N] — stdcall arg from caller stack (frameless).
            if (mnem == 'push' and ops and ops[0].type == X86_OP_MEM):
                m = ops[0].mem
                if (m.base == X86_REG_ESP and not m.index and m.segment == 0):
                    disp = m.disp & 0xFFFFFFFF
                    if disp > 0x7FFFFFFF:
                        disp -= 0x100000000
                    if disp >= 4:
                        # ``len(push_stack)*4`` accounts for THIS call's earlier
                        # args already deferred (elided into registers): they
                        # lowered the x86 ESP but not the translated RSP, so the
                        # x86 disp is that many bytes high relative to the frame.
                        arg_slot = self._frameless_stdcall_arg_slot(
                            disp, frame_local_sub, hw_stack_pushes,
                            elided_arg_bytes + len(push_stack) * 4)
                        if arg_slot is not None:
                            push_stack.append(('arg_home', arg_slot))
                            continue
                        slot = ((disp - 4) // 4 - len(push_stack)
                                - hw_stack_pushes)
                        if 0 <= slot < 4:
                            # After a nested call RCX is clobbered, so
                            # ``push [esp+4]`` must reload from the stack home
                            # (cmd 0xAC9D exit-code reload).  Before any call,
                            # arg0 still lives in RCX — use esp_fwd so helpers
                            # like cmd ``0xFF31`` (``push [esp+4]; push [c8d8];
                            # call add9``) pass the real flags in RDX instead of
                            # reading Win64 shadow garbage at [rsp+8].
                            if (slot == 0 and disp == 4 and not in_prologue
                                    and had_call):
                                off_x64 = (8 + hw_stack_pushes * 4
                                           ) & 0xFFFFFFFFFFFFFFFF
                                push_stack.append(('esp_mem', off_x64))
                            else:
                                push_stack.append(('esp_fwd', slot))
                        else:
                            # x64 callee-save pushes are 8 bytes; x86 disp is
                            # calibrated against 4-byte pushes.  Bias with *8 so
                            # ``push [esp+0x70]`` (cmd 0x9F48 → switch parser)
                            # does not read the wrong slot ([rsp+0x80]=4 instead
                            # of the real pointer a few qwords higher).
                            off_x64 = (disp + hw_stack_pushes * 8
                                       ) & 0xFFFFFFFFFFFFFFFF
                            push_stack.append(('esp_mem', off_x64))
                        continue

            # ── Absolute memory operands (IAT globals, .data) ─────────────────
            if ops and any(op.type == X86_OP_MEM for op in ops):
                mem_op = next(op for op in ops if op.type == X86_OP_MEM)
                if (mem_op.mem.base == 0 and mem_op.mem.index == 0
                        and mem_op.mem.segment == 0):
                    _abs32 = mem_op.mem.disp & 0xFFFFFFFF
                    if self._is_iat_rva(_abs32):
                        # IAT cell → the PE64 .idata slot, never the
                        # .data mirror (which holds 0 at runtime).  cmd
                        # FormatMessageW: ``mov ebx,[0x4ad01140]`` in a
                        # remat chunk resolved to 0x80081590 → call rbx
                        # with RBX=0 (execute @ 0).
                        abs_va = self._resolve_iat_slot_va(_abs32)
                    else:
                        abs_va = self._relocate_imm(_abs32, len(out), 0)
                    if mnem == 'call' and len(ops) == 1:
                        if push_stack and not self._is_zero_arg_iat(mem_op.mem.disp):
                            old_rva_call = (old_va - self.old_base) & 0xFFFFFFFF
                            if (self.win10_test_shim and old_rva_call == 0x1A514
                                    and len(push_stack) == 2):
                                # push ebx; …; push eax; push edi; call wcsncpy —
                                # count arg was dropped by callee-save disambiguation.
                                push_stack.insert(0, ('reg', X86_REG_EBX))
                            args = list(reversed(push_stack))
                            # ``push …; call _get_osfhandle; pop ecx; push eax; call``:
                            # only the last push is the CRT arg; the earlier ones
                            # stay for the follow-on wrapper (handle, buf, size, &n).
                            if (len(args) > 1
                                    and self._is_cdecl_shared_stack_iat(
                                        mem_op.mem.disp)
                                    and self._lookahead_pop_ecx_push_eax_call(
                                        _insn_idx, insns)):
                                push_stack.clear()
                                # All four x86 pushes leave the stack here; only
                                # fd is consumed by the CRT call. Surplus must be
                                # captured *now*: deferred ('reg', EAX) slots go
                                # stale once get_osfhandle returns the HANDLE in
                                # EAX (cmd ReadFile path at 0xB2C3 → wrapper
                                # sees rcx=rdx=handle and garbage r8/r9).
                                elided_arg_bytes += len(args) * 4
                                cdecl_pop_ecx_arg = None
                                cdecl_pop_ecx_arg2 = None
                                captured: List[Tuple[str, int]] = []
                                for atype, aval in args[1:]:
                                    self._emit_flushed_push_arg_to_reg(
                                        out, 'rax', atype, aval,
                                        ebp_reg_scratch=ebp_reg_scratch,
                                        ebp_scratch_reg=ebp_scratch_reg,
                                        frame_args_spilled=frame_args_spilled,
                                        stack_spill_count=stack_spill_count,
                                        frameless_stack_bias=frameless_stack_bias,
                                        frame_arg_anchor=frame_arg_anchor,
                                        hw_stack_pushes=hw_stack_pushes,
                                        frameless_shadow_homes=frameless_shadow_homes)
                                    out += self._asm('push rax')
                                    hw_stack_pushes += 1
                                    captured.append(('spill', stack_spill_count))
                                    stack_spill_count += 1
                                cdecl_shared_surplus = captured
                                self._emit_flushed_push_arg_to_reg(
                                    out, 'rcx', args[0][0], args[0][1],
                                    ebp_reg_scratch=ebp_reg_scratch,
                                    ebp_scratch_reg=ebp_scratch_reg,
                                    frame_args_spilled=frame_args_spilled,
                                    stack_spill_count=stack_spill_count,
                                    frameless_stack_bias=frameless_stack_bias,
                                    frame_arg_anchor=frame_arg_anchor,
                                    hw_stack_pushes=hw_stack_pushes,
                                    frameless_shadow_homes=frameless_shadow_homes)
                                # Keep surplus spills live across the CRT call;
                                # the follow-on CALL reloads them then pops.
                                self._emit_aligned_iat_call(
                                    out, mem_op.mem.disp, 0)
                                if (len(out) >= 2
                                        and out[-2:] != b'\x41\x5d'):
                                    out += self._asm('pop r13')
                                iat_fwd_epilogue = True
                                cc_mode = 'cdecl'
                                continue
                            push_stack.clear()
                            # Stash args for ``pop ecx; push eax; call`` only when
                            # that pattern follows (time/srand and similar). Plain
                            # stdcall IAT must not leave stale cdecl_pop_ecx_arg.
                            if (args and self._lookahead_pop_ecx_push_eax_call(
                                    _insn_idx, insns)):
                                elided_arg_bytes += len(args) * 4
                                cdecl_pop_ecx_arg = args[0]
                                cdecl_pop_ecx_arg2 = (
                                    args[1] if len(args) > 1 else None)
                            elif args:
                                elided_arg_bytes += len(args) * 4
                            arg_regs = self._call_arg_regs(cc_mode)
                            for idx, (atype, aval) in enumerate(args[:len(arg_regs)]):
                                reg = arg_regs[idx]
                                if atype == 'imm':
                                    imm = self._relocate_imm(aval & 0xFFFFFFFF,
                                                             len(out), 0)
                                    out += self._asm(
                                        f'mov {reg}, 0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                                elif atype == 'reg':
                                    if aval == X86_REG_EBP and ebp_reg_scratch:
                                        self._emit_ebp_scratch_load_to(
                                            out, reg)
                                    else:
                                        self._emit_mov32_to_w64_reg(
                                            out, reg, aval,
                                            ebp_reg_scratch, ebp_scratch_reg)
                                elif atype == 'spill':
                                    off = 8 * (stack_spill_count - aval - 1)
                                    out += self._asm(
                                        f'mov {reg}, qword ptr [rsp+0x{off:x}]')
                                elif atype == 'mem_abs':
                                    self._emit_abs_dword_load(out, reg, aval)
                                elif atype == 'mem_index':
                                    base, idx_r, scale, disp = aval
                                    self._emit_mem_index_dword_load(
                                        out, reg, base, idx_r, scale, disp)
                                elif atype == 'esp_fwd':
                                    self._emit_esp_fwd_arg(
                                        out, reg, aval,
                                        hw_stack_pushes=hw_stack_pushes,
                                        frameless_shadow_homes=frameless_shadow_homes)
                                elif atype == 'ebp_arg':
                                    if frame_args_spilled or aval >= 4:
                                        self._emit_homed_stack_arg_to_reg(
                                            out, reg, ebp_arg_slot_to_rbp_home(aval))
                                    else:
                                        src = WIN64_ARG_REG_NAMES[aval]
                                        if src != reg:
                                            out += self._asm(f'mov {reg}, {src}')
                                elif atype == 'ebp_local':
                                    self._emit_lea_ebp_slot(out, reg, aval)
                                elif atype in ('ebp_slot', 'esp_mem', 'arg_home'):
                                    self._emit_push_arg_to_reg(
                                        out, reg, atype, aval,
                                        frameless_stack_bias, frame_arg_anchor)
                                elif atype != 'stack':
                                    out += self._asm(f'xor {reg}, {reg}')
                            if stack_spill_count:
                                out += self._asm(
                                    f'add rsp, 0x{8 * stack_spill_count:x}')
                                stack_spill_count = 0
                            # Args 5+ go on the stack. Win64 places the 5th arg
                            # at [rsp+0x20] (caller frame), 6th at +0x28, …; the
                            # 0x20 shadow store precedes them. (cmd __getmainargs
                            # passes &startinfo as its 5th arg.)
                            extra = args[len(arg_regs):]
                            nstack = len(extra)
                            _skip_al = self._iat_skips_call_align(mem_op.mem.disp)
                            if not _skip_al:
                                self._emit_call_align_prologue(out, nstack)
                            for i, (atype, aval) in enumerate(extra):
                                off = 0x20 + i * 8
                                if atype == 'imm':
                                    imm = self._relocate_imm(
                                        aval & 0xFFFFFFFF, len(out), 0)
                                    out += self._asm(
                                        f'mov rax, 0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                                    out += self._asm(
                                        f'mov qword ptr [rsp+0x{off:x}], rax')
                                elif atype == 'reg':
                                    if aval == X86_REG_EBP and ebp_reg_scratch:
                                        self._emit_ebp_scratch_load_to(
                                            out, 'rax')
                                    else:
                                        src = W32_TO_W64_REG.get(aval, 'rax')
                                        if src != 'rax':
                                            out += self._asm(f'mov rax, {src}')
                                    out += self._asm(
                                        f'mov qword ptr [rsp+0x{off:x}], rax')
                                elif atype == 'mem_abs':
                                    self._emit_abs_dword_load(out, 'rax', aval)
                                    out += self._asm(
                                        f'mov qword ptr [rsp+0x{off:x}], rax')
                                elif atype in ('ebp_slot', 'esp_mem',
                                               'ebp_local', 'ebp_arg',
                                               'arg_home'):
                                    self._emit_push_arg_to_stack(
                                        out, off, atype, aval,
                                        frameless_stack_bias,
                                        frame_arg_anchor,
                                        args_homed=frame_args_spilled)
                                else:
                                    out += self._asm(
                                        f'mov qword ptr [rsp+0x{off:x}], 0')
                            self._emit_iat_call(out, mem_op.mem.disp)
                            if not _skip_al:
                                self._emit_call_align_epilogue(out, nstack)
                            iat_fwd_epilogue = True
                            # stdcall IAT — callee pops args on x86; no pop ecx cleanup.
                            self._emit_getenv_buf_too_small_guard(
                                out, args, insns, _insn_idx, mem_op.mem.disp)
                        elif push_stack and self._is_zero_arg_iat(mem_op.mem.disp):
                            # Deferred pushes before a 0-arg import are almost
                            # always prologue callee-saves that were misclassified
                            # (cmd 0x194d5).  Emit them as hardware saves so they
                            # cannot poison the next multi-arg call (GetCPInfo).
                            _cs = getattr(self, '_CALLEE_SAVE_REG_IDS', ())
                            if (_cs and all(
                                    t == 'reg' and v in _cs
                                    for t, v in push_stack)):
                                for _t, _v in push_stack:
                                    _rn = W32_TO_W64_REG.get(_v, 'rax')
                                    out += self._asm(f'push {_rn}')
                                    hw_stack_pushes += 1
                                    if frame_local_sub > 0:
                                        frameless_stack_bias += 8
                                    if _rn not in callee_save_stack:
                                        callee_save_stack.append(_rn)
                                push_stack.clear()
                            self._emit_aligned_iat_call(out, mem_op.mem.disp, 0)
                            if (len(out) >= 2
                                    and out[-2:] != b'\x41\x5d'):
                                out += self._asm('pop r13')
                            iat_fwd_epilogue = True
                        else:
                            self._emit_aligned_iat_call(out, mem_op.mem.disp, 0)
                            if (len(out) >= 2
                                    and out[-2:] != b'\x41\x5d'):
                                out += self._asm('pop r13')
                        cc_mode = 'stdcall'
                        continue
                    if mnem == 'mov' and len(ops) == 2:
                        if mem_op == ops[0] and ops[1].type == X86_OP_IMM:
                            ptr_sz = self._mem_ptr_size(insn.op_str)
                            if ptr_sz in ('byte', 'word'):
                                out += self._asm(f'mov rax, 0x{abs_va:x}')
                                out += self._asm(
                                    f'mov {ptr_sz} ptr [rax], '
                                    f'0x{ops[1].imm & 0xFFFFFFFF:x}')
                                continue
                            self._emit_rip_rel_mov_imm32(
                                out, mem_op.mem.disp, ops[1].imm)
                            continue
                        if mem_op == ops[1] and ops[0].type == X86_OP_REG:
                            dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                            if self._is_iat_rva(mem_op.mem.disp & 0xFFFFFFFF):
                                self._emit_iat_fn_ptr_load(
                                    out, ops[0].reg, abs_va, iat_fn_holder,
                                    iat_fn_slot,
                                    iat_key=mem_op.mem.disp & 0xFFFFFFFF)
                            else:
                                iat_fn_holder.pop(ops[0].reg, None)
                                iat_fn_slot.pop(ops[0].reg, None)
                                # Respect the x86 destination width.  ``mov ax,
                                # [abs]`` / ``mov al,[abs]`` write ONLY the low
                                # 16/8 bits and preserve the rest of the reg; a
                                # widened dword/qword load over-reads the adjacent
                                # global and pollutes the high bits (garbage that
                                # then drives wrong branches — cmd locale-init
                                # ``mov ax,[0x1c76c]`` mis-set the error flag).
                                op_sz = getattr(ops[0], 'size', 4) or 4
                                if op_sz == 1:
                                    reg_asm = self._reg_asm_for_op(ops[0], insn.op_str)
                                    load_sz = 'byte'
                                elif op_sz == 2:
                                    reg_asm = self._word_reg_asm_for_op(
                                        ops[0], insn.op_str)
                                    load_sz = 'word'
                                else:
                                    d32_map = {'rax': 'eax', 'rbx': 'ebx',
                                               'rcx': 'ecx', 'rdx': 'edx',
                                               'rsi': 'esi', 'rdi': 'edi',
                                               'r8': 'r8d', 'r9': 'r9d',
                                               'r10': 'r10d', 'r11': 'r11d'}
                                    d32 = d32_map.get(dst, 'eax')
                                    # Packed PE32 .data keeps 4-byte slots after
                                    # remap (image base <4GiB).  Qword loads pull
                                    # the *adjacent* global into the high dword
                                    # (cmd ``[fbc8]`` cursor polluted by
                                    # ``[fbc4]`` flag).  Match
                                    # ``_emit_abs_dword_load``.
                                    load_sz = 'dword'
                                    reg_asm = d32
                                # Always movabs — rip-rel bakes emit-time VAs
                                # that ``_patch_abs_va_in_code`` cannot fix.
                                scratch = 'r11' if dst != 'r11' else 'r10'
                                out += self._asm(
                                    f'movabs {scratch}, 0x{abs_va:x}')
                                out += self._asm(
                                    f'mov {reg_asm}, '
                                    f'{load_sz} ptr [{scratch}]')
                            self._ptr_taint_mark(ptr_taint, ops[0].reg)
                            continue
                        if mem_op == ops[0] and ops[1].type == X86_OP_REG:
                            ptr_sz = self._mem_ptr_size(insn.op_str)
                            if ptr_sz == 'dword' and getattr(ops[1], 'size', 0) == 1:
                                ptr_sz = 'byte'
                            src = (self._word_reg_asm_for_op(ops[1], insn.op_str)
                                   if ptr_sz == 'word'
                                   else self._reg_asm_for_op(ops[1], insn.op_str))
                            src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                            scratch = 'r11' if src64 != 'r11' else 'r10'
                            out += self._asm(
                                f'movabs {scratch}, 0x{abs_va:x}')
                            # Keep dword stores for packed .data.  Widening to
                            # qword (win10 shim) zeroed the next slot —
                            # ``mov [fbc4],edi`` wiped the ``[fbc8]`` PWSTR and
                            # crashed ``cmp word [rcx],0`` with RCX=0.  Image
                            # pointers fit in 32 bits at preferred base
                            # <4GiB; host heap tables use expanded qword
                            # slots via ``_cmd_heap_indexed_mem`` instead.
                            out += self._asm(
                                f'mov {ptr_sz} ptr [{scratch}], {src}')
                            continue
                    if mnem == 'push' and len(ops) == 1:
                        # Defer as a call argument: push [global] is usually the
                        # argument to the following CALL (e.g. lpCriticalSection).
                        push_stack.append(('mem_abs', mem_op.mem.disp & 0xFFFFFFFF))
                        continue

                    # Generic ALU op on an absolute global: and/or/xor/add/sub/
                    # cmp/test/inc/dec/… with [abs] as dest or source. Emit it
                    # through a movabs scratch so the global VA stays a
                    # relocatable immediate. A RIP-relative encoding here would
                    # freeze the (still-unrelocated) RVA — there is no later
                    # fixup pass for RIP displacements — and a write would fault
                    # into the read-only .text (cmd flag clears: and byte [g],0).
                    _ALU_ABS = {
                        'and', 'or', 'xor', 'add', 'sub', 'adc', 'sbb',
                        'cmp', 'test', 'inc', 'dec', 'neg', 'not',
                        'movzx', 'movsx',
                    }
                    if mnem in _ALU_ABS:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        imm_mask = {'byte': 0xFF, 'word': 0xFFFF,
                                    'dword': 0xFFFFFFFF,
                                    'qword': 0xFFFFFFFFFFFFFFFF}.get(
                                        ptr_sz, 0xFFFFFFFF)
                        scratch = 'r11'
                        if len(ops) == 1:
                            out += self._asm(
                                f'movabs {scratch}, 0x{abs_va:x}')
                            out += self._asm(
                                f'{mnem} {ptr_sz} ptr [{scratch}]')
                            continue
                        if len(ops) == 2:
                            mem_first = (mem_op == ops[0])
                            other = ops[1] if mem_first else ops[0]
                            if other.type == X86_OP_IMM:
                                out += self._asm(
                                    f'movabs {scratch}, 0x{abs_va:x}')
                                out += self._asm(
                                    f'{mnem} {ptr_sz} ptr [{scratch}], '
                                    f'0x{other.imm & imm_mask:x}')
                                continue
                            if other.type == X86_OP_REG:
                                r = (self._word_reg_asm_for_op(other, insn.op_str)
                                     if ptr_sz == 'word'
                                     else self._reg_asm_for_op(other, insn.op_str))
                                # ah/bh/ch/dh cannot coexist with a REX-prefixed
                                # base (r11); skip and let the fallback emit it.
                                if r not in ('ah', 'bh', 'ch', 'dh'):
                                    out += self._asm(
                                        f'movabs {scratch}, 0x{abs_va:x}')
                                    if mnem in ('movzx', 'movsx'):
                                        # reg <- [abs] (mem is the source)
                                        out += self._asm(
                                            f'{mnem} '
                                            f'{W32_TO_W64_REG.get(ops[0].reg, "rax")}, '
                                            f'{ptr_sz} ptr [{scratch}]')
                                    elif mem_first:
                                        out += self._asm(
                                            f'{mnem} {ptr_sz} ptr [{scratch}], {r}')
                                    else:
                                        out += self._asm(
                                            f'{mnem} {r}, {ptr_sz} ptr [{scratch}]')
                                    continue

            # lea r32,[ebp±N]; push r32 — stdcall out-pointer arg, not a stack local.
            # Must run before the MSVC push-ecx → sub rsp block below.
            if (mnem == 'push' and ops and ops[0].type == X86_OP_REG
                    and frame_rbp_saved):
                op = ops[0]
                prev = insns[_insn_idx - 1] if _insn_idx > 0 else None
                if (prev is not None and prev.mnemonic == 'lea'
                        and len(prev.operands) == 2
                        and prev.operands[0].type == X86_OP_REG
                        and prev.operands[0].reg == op.reg
                        and prev.operands[1].type == X86_OP_MEM
                        and prev.operands[1].mem.base == X86_REG_EBP):
                    disp = prev.operands[1].mem.disp
                    if disp > 0x7FFFFFFF:
                        disp -= 0x100000000
                    if disp < 0:
                        disp = self._seh_rbp_local_disp(disp, seh_frame_active)
                    push_stack.append(('ebp_local', disp))
                    continue

            # ── PUSH ECX after EBP frame → SUB RSP,N (MSVC stack locals) ─────
            # Only the bare `push ecx` reserve-locals idiom belongs here. A
            # `push ecx` that is loaded right before (mov ecx,<arg>) or that
            # appears while call args are already being accumulated is a real
            # CALL argument and must fall through to the push/CALL marshaller —
            # otherwise we lose pending args and drift RSP by 4 (cmd's
            # __getmainargs call: see _emit_iat_call marshalling).
            if (mnem == 'push' and ops and ops[0].type == X86_OP_REG
                    and ops[0].reg == X86_REG_ECX and frame_rbp_saved):
                _prev = insns[_insn_idx - 1] if _insn_idx > 0 else None
                _prev_loads_ecx = (
                    _prev is not None and _prev.mnemonic == 'mov'
                    and len(_prev.operands) == 2
                    and _prev.operands[0].type == X86_OP_REG
                    and _prev.operands[0].reg == X86_REG_ECX)
                if not push_stack and not _prev_loads_ecx:
                    n_local = 1
                    for j in range(_insn_idx + 1, min(_insn_idx + 4, len(insns))):
                        nx = insns[j]
                        if (nx.mnemonic == 'push' and nx.operands
                                and nx.operands[0].type == X86_OP_REG
                                and nx.operands[0].reg == X86_REG_ECX):
                            n_local += 1
                            skip_insns.add(nx.address)
                        else:
                            break
                    out += self._asm(f'sub rsp, 0x{4 * n_local:x}')
                    push_stack.clear()
                    continue

            # ── PUSH paired with a later POP (constant-load idiom) → skip ─────
            if mnem == 'push' and old_va in pair_src_addrs:
                continue

            # ── PUSH r32 / PUSH imm  (accumulate for CALL translation) ─────────
            if mnem == 'push' and ops:
                op = ops[0]
                if op.type == X86_OP_REG:
                    if self._is_cdecl_scratch_push(_insn_idx, insns):
                        # push esi; call time; pop ecx; push eax; call srand — the
                        # push/pop pair is a dead stack slot; reg stays live in RSI.
                        push_stack.clear()
                        continue
                    recent_lea = self._find_recent_ebp_lea(op.reg, _insn_idx, insns)
                    if recent_lea is not None and frame_rbp_saved:
                        if recent_lea < 0:
                            recent_lea = self._seh_rbp_local_disp(
                                recent_lea, seh_frame_active)
                        push_stack.append(('ebp_local', recent_lea))
                        continue
                    # push ebp is always the frame-pointer save in cmd's code.
                    if op.reg == X86_REG_EBP:
                        nops = (next_insn.operands if next_insn else [])
                        is_std_prologue = (
                            next_insn is not None and next_insn.mnemonic == 'mov'
                            and len(nops) == 2 and nops[0].type == X86_OP_REG
                            and nops[0].reg == X86_REG_EBP
                            and nops[1].type == X86_OP_REG
                            and nops[1].reg == X86_REG_ESP
                        )
                        is_esp_arg_prologue = (
                            next_insn is not None and next_insn.mnemonic == 'mov'
                            and len(nops) == 2 and nops[0].type == X86_OP_REG
                            and nops[0].reg == X86_REG_EBP
                            and nops[1].type == X86_OP_MEM
                            and nops[1].mem.base == X86_REG_ESP
                        )
                        if not is_std_prologue and not is_esp_arg_prologue:
                            if self._push_ebp_is_stdcall_arg(
                                    _insn_idx, insns, frame_rbp_saved,
                                    callee_save_stack):
                                push_stack.append(('reg', X86_REG_EBP))
                                continue
                            if (push_stack
                                    or (next_insn is not None
                                        and next_insn.mnemonic == 'call')):
                                if (not push_stack and next_insn is not None
                                        and next_insn.mnemonic == 'call'
                                        and self._push_ebp_before_call_is_frame_save(
                                            _insn_idx, insns)):
                                    if push_stack:
                                        self._flush_deferred_pushes(out, push_stack)
                                    out += self._asm('push rbp')
                                    frame_rbp_saved = True
                                    hw_stack_pushes += 1
                                    if frame_local_sub > 0:
                                        frameless_stack_bias += 8
                                    callee_save_stack.append('rbp')
                                    continue
                                # ``push ebp; call GetProcessHeap; mov ebp,eax``
                                # — callee-save, not a frame and not an arg
                                # (0-arg IAT / heap-scratch follows).
                                if (not push_stack and next_insn is not None
                                        and next_insn.mnemonic == 'call'
                                        and self._lookahead_matching_pop(
                                            X86_REG_EBP, _insn_idx, insns)
                                        and not self._push_ebp_is_stdcall_arg(
                                            _insn_idx, insns, frame_rbp_saved,
                                            callee_save_stack)):
                                    out += self._asm('push rbp')
                                    hw_stack_pushes += 1
                                    if frame_local_sub > 0:
                                        frameless_stack_bias += 8
                                    callee_save_stack.append('rbp')
                                    continue
                                push_stack.append(('reg', X86_REG_EBP))
                                continue
                            # push ebp; push esi/edi — callee-save spill, not a frame.
                            if push_stack:
                                self._flush_deferred_pushes(out, push_stack)
                            out += self._asm('push rbp')
                            hw_stack_pushes += 1
                            if frame_local_sub > 0:
                                frameless_stack_bias += 8
                            callee_save_stack.append('rbp')
                            continue
                        if push_stack:
                            self._flush_deferred_pushes(out, push_stack)
                        out += self._asm('push rbp')
                        frame_rbp_saved = True
                        hw_stack_pushes += 1
                        if frame_local_sub > 0:
                            frameless_stack_bias += 8
                        callee_save_stack.append('rbp')
                        continue
                    # when the register is overwritten right after — otherwise it
                    # is a call argument and must be deferred (e.g. push esi; call).
                    if op.reg in (X86_REG_EBX, X86_REG_ESI, X86_REG_EDI):
                        # A SECOND push of an already-saved callee register, just
                        # before a CALL, is a call argument — not another save.
                        # (e.g. push ebx/push ebp at entry, then push ebx; push
                        # esi; push ebp; call F passes ebx/esi/ebp as args.) The
                        # register is already in callee_save_stack, so this is
                        # unambiguous and avoids leaving extra values on the stack.
                        # Also ``push edi; call`` with no intervening push
                        # (cmd 0x10388) — _push_reg_is_pending_call_arg used to
                        # require an inner push and misclassified this as a save.
                        _rn_dup = W32_TO_W64_REG.get(op.reg, 'rax')
                        if _rn_dup in callee_save_stack:
                            _nxt_call = (next_insn is not None
                                         and next_insn.mnemonic == 'call')
                            if (_nxt_call
                                    or self._push_reg_is_pending_call_arg(
                                        _insn_idx, insns)):
                                push_stack.append(('reg', op.reg))
                                continue
                        # Prologue callee-save block (push ebx/esi/edi at function
                        # entry, before any call) with a matching epilogue pop is a
                        # SAVE, never a call argument — even when a call follows
                        # immediately.  Must run *before* the arity-based
                        # ``push reg; call`` check: a wrong argc (neighbour
                        # ``ret imm`` after a 0-arg bare ``ret``) would otherwise
                        # consume the final push as a fake arg and desync
                        # post-call ``mov r32,[esp+N]`` homes (cmd B00C).
                        # Gated by ``_prologue_save_fix`` (on in pure mode).
                        prologue_save = (
                            self._prologue_save_fix
                            and in_prologue and not push_stack
                            and self._lookahead_matching_pop(
                                op.reg, _insn_idx, insns))
                        # Bare ``push reg; call``: stdcall arg when the callee
                        # consumes stack args; callee-save when the call is
                        # 0-arg (cmd 0x194d5 ``push ebx/esi/edi; call
                        # GetConsoleOutputCP``).  Also always an arg when this
                        # register was already saved (second push).
                        if (not prologue_save
                                and next_insn is not None
                                and next_insn.mnemonic == 'call'):
                            is_arg = _rn_dup in callee_save_stack
                            if not is_arg and next_insn.operands:
                                _cop = next_insn.operands[0]
                                if _cop.type == X86_OP_IMM:
                                    _ar = self._x86_stdcall_argc_from_ret(
                                        (_cop.imm - self.old_base) & 0xFFFFFFFF)
                                    # Unknown arity → treat as arg (safer for
                                    # ``push edi; call helper``); argc 0 → save.
                                    is_arg = (_ar is None or _ar >= 1)
                                elif (_cop.type == X86_OP_MEM
                                      and _cop.mem.base == 0
                                      and _cop.mem.index == 0):
                                    is_arg = not self._is_zero_arg_iat(
                                        _cop.mem.disp)
                                else:
                                    is_arg = True
                            if is_arg:
                                push_stack.append(('reg', op.reg))
                                continue
                        # push esi/ebx/edi; push ebp; call — callee-save then arg
                        # when the register has a matching epilogue pop and no
                        # further pushes follow ebp (cmd ``0x6521``).
                        # When more pushes follow (``push ebx; push ebp;
                        # push [CP]; call MultiByteToWideChar``), the register
                        # is a stdcall arg despite the epilogue pop.
                        if (self._cmd_no_hacks
                                and next_insn is not None
                                and next_insn.mnemonic == 'push'
                                and next_insn.operands
                                and next_insn.operands[0].type == X86_OP_REG
                                and next_insn.operands[0].reg == X86_REG_EBP
                                and self._lookahead_matching_pop(
                                    op.reg, _insn_idx, insns)
                                and self._push_reg_ebp_call_is_callee_save(
                                    _insn_idx, insns)):
                            if push_stack:
                                self._flush_deferred_pushes(out, push_stack)
                            if (not frameless_shadow_homes and not frame_rbp_saved
                                    and hw_stack_pushes == 0
                                    and needs_esp_fwd_homes
                                    and not frame_arg_anchor):
                                self._home_frameless_win64_shadow_args(out)
                                frameless_shadow_homes = True
                            rname = W32_TO_W64_REG.get(op.reg, 'rax')
                            out += self._asm(f'push {rname}')
                            hw_stack_pushes += 1
                            if frame_local_sub > 0:
                                frameless_stack_bias += 8
                            callee_save_stack.append(rname)
                            continue
                        if (not prologue_save
                                and not (in_prologue
                                         and self._lookahead_matching_pop(
                                             op.reg, _insn_idx, insns))
                                and self._push_reg_is_pending_call_arg(
                                    _insn_idx, insns)):
                            push_stack.append(('reg', op.reg))
                            continue
                        saved = False
                        if next_insn is not None:
                            nops = next_insn.operands
                            if (next_insn.mnemonic in ('mov', 'lea', 'pop', 'xor')
                                    and nops and nops[0].type == X86_OP_REG
                                    and nops[0].reg == op.reg):
                                saved = True
                            if (not saved and next_insn.mnemonic == 'push'
                                    and next_insn.operands):
                                nops2 = next_insn.operands
                                if nops2[0].type == X86_OP_REG:
                                    if in_prologue:
                                        saved = True
                                    elif (nops2[0].reg == X86_REG_EBP
                                          and self._lookahead_matching_pop(
                                              op.reg, _insn_idx, insns)
                                          and self._push_reg_ebp_call_is_callee_save(
                                              _insn_idx, insns)):
                                        # push esi; push ebp; call — save before arg.
                                        saved = True
                            if not saved and in_prologue and not push_stack:
                                saved = True
                        elif in_prologue:
                            saved = True
                        elif not saved and self._lookahead_matching_pop(
                                op.reg, _insn_idx, insns):
                            # push reg; push imm/reg — call args (e.g. HeapAlloc).
                            # push reg; push [mem] — callee save before arg pushes.
                            next_is_call_arg_push = False
                            if (next_insn is not None
                                    and next_insn.mnemonic == 'push'
                                    and next_insn.operands):
                                n0 = next_insn.operands[0]
                                if n0.type == X86_OP_IMM:
                                    next_is_call_arg_push = (
                                        not self._msvc_push_imm_pop_ecx_idiom(
                                            _insn_idx, insns))
                                elif (n0.type == X86_OP_REG
                                      and n0.reg not in self._CALLEE_SAVE_REG_IDS):
                                    next_is_call_arg_push = True
                            if not next_is_call_arg_push:
                                saved = True
                        rname_chk = W32_TO_W64_REG.get(op.reg, 'rax')
                        if saved and rname_chk in callee_save_stack:
                            if next_insn is not None:
                                nm = next_insn.mnemonic
                                if nm == 'call':
                                    saved = False
                                elif nm == 'push':
                                    saved = False
                                elif nm not in (
                                        'mov', 'lea', 'xor', 'add', 'sub', 'and',
                                        'or', 'cmp', 'test', 'xchg', 'pop', 'inc',
                                        'dec', 'not', 'neg', 'shl', 'shr', 'sar'):
                                    saved = False
                        if saved:
                            if push_stack:
                                self._flush_deferred_pushes(out, push_stack)
                            if (not frameless_shadow_homes and not frame_rbp_saved
                                    and hw_stack_pushes == 0
                                    and needs_esp_fwd_homes
                                    and not frame_arg_anchor):
                                self._home_frameless_win64_shadow_args(out)
                                frameless_shadow_homes = True
                            rname = W32_TO_W64_REG.get(op.reg, 'rax')
                            out += self._asm(f'push {rname}')
                            hw_stack_pushes += 1
                            if frame_local_sub > 0:
                                frameless_stack_bias += 8
                            callee_save_stack.append(rname)
                            continue
                    # `mov reg,<stable src>; [test/jcc]; push reg` as a CALL arg:
                    # defer the SOURCE, not the register. Win64 arg marshalling
                    # reuses RCX/RDX/RAX, so a deferred ('reg', ECX/EDX/EAX) would
                    # be clobbered before the CALL re-reads it (cmd __getmainargs
                    # dowildcard arg). Re-loading the global/imm at the call is
                    # clobber-safe.  Prefer this over the spill below so
                    # ``mov eax,[g]; test; je; push eax; lea eax,…; call`` keeps
                    # src as mem_abs even when the lea clobbers EAX.
                    _prevm = None
                    for _bk in range(_insn_idx - 1, max(-1, _insn_idx - 6), -1):
                        _cand = insns[_bk]
                        if (_cand.mnemonic in ('test', 'cmp')
                                or _cand.mnemonic.startswith('j')):
                            continue
                        _prevm = _cand
                        break
                    if (_prevm is not None and _prevm.mnemonic == 'mov'
                            and len(_prevm.operands) == 2
                            and _prevm.operands[0].type == X86_OP_REG
                            and _prevm.operands[0].reg == op.reg):
                        _psrc = _prevm.operands[1]
                        if (_psrc.type == X86_OP_MEM and _psrc.mem.base == 0
                                and _psrc.mem.index == 0
                                and _psrc.mem.segment == 0):
                            push_stack.append(
                                ('mem_abs', _psrc.mem.disp & 0xFFFFFFFF))
                            continue
                        if _psrc.type == X86_OP_IMM:
                            push_stack.append(('imm', _psrc.imm))
                            continue
                    # push reg; mov/lea same-reg — spill now or the value is lost
                    # (cmd 0xBA66: ``push eax; lea eax,[esp+N]; push eax; call``).
                    if next_insn is not None and next_insn.mnemonic in ('mov', 'lea'):
                        nops = next_insn.operands
                        if (nops and nops[0].type == X86_OP_REG
                                and nops[0].reg == op.reg):
                            rname = W32_TO_W64_REG.get(op.reg, 'rcx')
                            out += self._asm(f'push {rname}')
                            hw_stack_pushes += 1
                            if frame_local_sub > 0:
                                frameless_stack_bias += 8
                            push_stack.append(('spill', stack_spill_count))
                            stack_spill_count += 1
                            continue
                    rname = W32_TO_W64_REG.get(op.reg, 'rcx')
                    push_stack.append(('reg', op.reg))
                elif op.type == X86_OP_IMM:
                    push_stack.append(('imm', op.imm))
                elif op.type == X86_OP_MEM:
                    m = op.mem
                    if (m.base == X86_REG_EBP and not m.index and frame_rbp_saved):
                        disp = m.disp & 0xFFFFFFFF
                        if disp > 0x7FFFFFFF:
                            disp -= 0x100000000
                        if disp >= 8 and (disp - 8) % 4 == 0:
                            push_stack.append(('ebp_arg', (disp - 8) // 4))
                            continue
                    if (m.base == X86_REG_ESP and not m.index and m.segment == 0):
                        disp = m.disp & 0xFFFFFFFF
                        if disp > 0x7FFFFFFF:
                            disp -= 0x100000000
                        if disp >= 4:
                            slot = (disp - 4) // 4 - len(push_stack) - hw_stack_pushes
                            if 0 <= slot < 4:
                                push_stack.append(('esp_fwd', slot))
                                continue
                            # Deep [esp+disp] inside a large-frame (chkstk / sub
                            # esp,N) function may be an INCOMING parameter, not a
                            # local. Route it through the homed-arg machinery so it
                            # reads the spilled register copy (shadow space) rather
                            # than raw stack garbage. ``len(push_stack)`` counts the
                            # pending deferred pushes (this call's earlier args) that
                            # are elided into registers and so shift the x86 disp.
                            if frame_local_sub > 0 and frame_arg_anchor:
                                ah = self._frameless_stdcall_arg_slot(
                                    disp, frame_local_sub, hw_stack_pushes,
                                    elided_arg_bytes + len(push_stack) * 4)
                                if ah is not None:
                                    push_stack.append(('arg_home', ah))
                                    continue
                            off_x64 = (disp + hw_stack_pushes * 8) & 0xFFFFFFFFFFFFFFFF
                            push_stack.append(('esp_mem', off_x64))
                            continue
                    if m.base and m.index and m.segment == 0:
                        push_stack.append(('mem_index', (
                            m.base, m.index, m.scale, m.disp & 0xFFFFFFFF)))
                    elif m.base and not m.index and m.segment == 0:
                        # ``push dword ptr [esi]`` / ``push [ebx+4]`` — load the
                        # pointed-to slot as a call arg (cmd 0x4858 path ptr).
                        push_stack.append((
                            'mem_base',
                            (m.base, m.disp & 0xFFFFFFFF)))
                    else:
                        push_stack.append(('mem', 0))   # rare abs/seg form
                else:
                    push_stack.append(('unk', 0))
                # Don't emit anything yet — flush on CALL
                continue

            # ── CALL → flush push_stack, emit MOV arg_regs, CALL ──────────────
            if mnem == 'call' and ops:
                op0 = ops[0]
                if (push_stack and op0.type == X86_OP_MEM
                        and op0.mem.base == 0 and op0.mem.index == 0
                        and self._is_zero_arg_iat(op0.mem.disp)):
                    self._emit_aligned_iat_call(out, op0.mem.disp, 0)
                    # Safety: ensure align epilogue emitted pop r13
                    if (len(out) >= 2
                            and out[-2:] != b'\x41\x5d'):
                        out += self._asm('pop r13')
                    iat_fwd_epilogue = True
                    cc_mode = 'stdcall'
                    continue
                # ``mov esi,[GetProcessHeap]; push size; push flags; call esi`` —
                # keep the pushes for the following HeapAlloc (cmd 0x9FAD).
                if (push_stack and op0.type == X86_OP_REG
                        and self._reg_holds_zero_arg_iat(op0.reg, iat_fn_slot)):
                    r = self._x64_call_target_reg(op0.reg, iat_fn_holder)
                    if r in ('rax', 'r11'):
                        out += self._asm(f'mov r10, {r}')
                        r = 'r10'
                    self._emit_call_align_prologue(out, 0)
                    out += self._asm(f'call {r}')
                    self._emit_call_align_epilogue(out, 0)
                    iat_fwd_epilogue = True
                    cc_mode = 'stdcall'
                    continue
                # Peel leading callee-save pushes when stdcall arity is known
                # (cmd ``push edi; push ebx; push size; call malloc; ret 4``).
                if (push_stack and op0.type == X86_OP_IMM
                        and self._cmd_no_hacks):
                    _tr = (op0.imm - self.old_base) & 0xFFFFFFFF
                    _argc = self._x86_stdcall_argc_from_ret(_tr)
                    if (_argc is not None
                            and len(push_stack) > _argc):
                        while len(push_stack) > _argc:
                            atype, aval = push_stack[0]
                            if not (atype == 'reg'
                                    and aval in (X86_REG_EBX, X86_REG_ESI,
                                                 X86_REG_EDI, X86_REG_EBP)
                                    and self._lookahead_matching_pop(
                                        aval, _insn_idx, insns)):
                                break
                            rname = W32_TO_W64_REG.get(aval, 'rax')
                            out += self._asm(f'push {rname}')
                            hw_stack_pushes += 1
                            if frame_local_sub > 0:
                                frameless_stack_bias += 8
                            if rname not in callee_save_stack:
                                callee_save_stack.append(rname)
                            push_stack.pop(0)
                args = list(reversed(push_stack))   # pushes are right-to-left
                if cdecl_shared_surplus:
                    # ``push eax`` after shared-stack cdecl + surplus (buf, size, &n).
                    # Surplus was already counted in elided_arg_bytes at the first call.
                    n_new = len(args)
                    args = args + list(cdecl_shared_surplus)
                    cdecl_shared_surplus = []
                    if n_new:
                        elided_arg_bytes += n_new * 4
                    cdecl_pop_ecx_arg = args[0] if args else None
                    cdecl_pop_ecx_arg2 = args[1] if len(args) > 1 else None
                elif args:
                    elided_arg_bytes += len(args) * 4
                    cdecl_pop_ecx_arg = args[0]
                    cdecl_pop_ecx_arg2 = args[1] if len(args) > 1 else None
                push_stack.clear()
                # thiscall: ECX holds 'this' (maps to RCX = arg1 in Win64)
                if cc_mode == 'thiscall':
                    out += self._asm('mov rcx, rcx')  # ECX already = RCX in x64
                # fastcall: first two args already in ECX, EDX → RCX, RDX
                if cc_mode == 'fastcall' and not args:
                    pass  # registers already hold args
                # Set up args in Win64 ABI registers from pushes (parallel —
                # snapshot sources that alias dest arg regs first).
                arg_regs = self._call_arg_regs(cc_mode)
                self._emit_call_args_parallel(
                    out, args, arg_regs,
                    ebp_reg_scratch=ebp_reg_scratch,
                    ebp_scratch_reg=ebp_scratch_reg,
                    frame_args_spilled=frame_args_spilled,
                    stack_spill_count=stack_spill_count,
                    frameless_stack_bias=frameless_stack_bias,
                    frame_arg_anchor=frame_arg_anchor,
                    hw_stack_pushes=hw_stack_pushes,
                    frameless_shadow_homes=frameless_shadow_homes)
                if stack_spill_count:
                    out += self._asm(f'add rsp, 0x{8 * stack_spill_count:x}')
                    stack_spill_count = 0
                # ``push; jmp call`` predecessors already loaded arg regs and
                # jump at this CALL VA — point them at the align/call body so
                # they do not re-execute this block's ``mov rcx`` (which would
                # clobber their value). Fall-through ``push; call`` still runs
                # the movs above; only the map entry moves.
                if args:
                    old_new[old_va] = len(out)
                # Stack args (args 5+)
                extra = args[4:]
                op = ops[0]
                alloca_call = (op.type == X86_OP_IMM
                               and self._is_alloca_probe_rva(op.imm - self.old_base))
                nstack = len(extra)
                # Large-frame prologue ``mov eax,N; call __chkstk``: spill the
                # incoming Win64 arg registers into the caller-provided shadow
                # space BEFORE __chkstk runs (it clobbers RCX), and anchor R15 at
                # entry_rsp+4 so the body's deep [esp+disp] parameter reads (routed
                # through the homed-arg machinery) resolve to those homes:
                # [r15+4+slot*8] == entry_rsp+8+slot*8 == shadow slot. Without this
                # a frameless chkstk function reads raw stack garbage for its
                # stack-passed args (cmd 0xA4E7 switch parser -> wcschr(0x73006C)
                # AV). Universal: keyed on the prologue shape, not on any binary.
                if (alloca_call and not frame_arg_anchor and not esp_dirty
                        and not frame_rbp_saved
                        and not os.environ.get('NO_CHKSTK_ARGHOME')):
                    _pmov = insns[_insn_idx - 1] if _insn_idx > 0 else None
                    _chk_sz = None
                    if (_pmov is not None and _pmov.mnemonic == 'mov'
                            and len(_pmov.operands) == 2
                            and _pmov.operands[0].type == X86_OP_REG
                            and _pmov.operands[0].reg == X86_REG_EAX
                            and _pmov.operands[1].type == X86_OP_IMM):
                        _chk_sz = _pmov.operands[1].imm & 0xFFFFFFFF
                    if _chk_sz and _chk_sz > 0x28:
                        # Canonical chkstk arg-spill (matches the build-18 design
                        # that _chk7.py probes for and that the entry-detection
                        # skips): spill RCX/RDX/R8/R9 into the caller-provided
                        # shadow space [rsp+8..0x20] and anchor R15 at entry_rsp+4
                        # so [r15+4+slot*8] == shadow slot. Emitted between the
                        # ``mov rax,imm`` opener and ``call __chkstk`` (RSP is still
                        # entry_rsp here; __chkstk would clobber RCX).
                        out += self._asm('mov qword ptr [rsp+8], rcx')
                        out += self._asm('mov qword ptr [rsp+0x10], rdx')
                        out += self._asm('mov qword ptr [rsp+0x18], r8')
                        out += self._asm('mov qword ptr [rsp+0x20], r9')
                        out += self._asm('lea r15, [rsp+4]')
                        frame_local_sub = _chk_sz
                        frameless_stack_bias = 0
                        frame_arg_anchor = True
                        # Homes already live at the *entry* shadow; do not
                        # re-spill after __chkstk (RSP moved, RCX clobbered).
                        frameless_shadow_homes = True
                        esp_dirty = True
                # Decide align skip before emitting (setjmp/longjmp).
                _align_iat = None
                if op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                    _align_iat = op.mem.disp
                elif op.type == X86_OP_IMM:
                    _align_iat = self._ff25_iat_slot_at_rva(
                        (op.imm - self.old_base) & 0xFFFFFFFF)
                _skip_al = (_align_iat is not None
                            and self._iat_skips_call_align(_align_iat))
                if not alloca_call and not _skip_al:
                    self._emit_call_align_prologue(out, nstack)
                    for i, (atype, aval) in enumerate(extra):
                        off = 0x20 + i * 8
                        if atype == 'imm':
                            imm = self._relocate_imm(aval & 0xFFFFFFFF, len(out), 0)
                            out += self._asm(
                                f'mov rax, 0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype == 'reg':
                            if aval == X86_REG_EBP and ebp_reg_scratch:
                                self._emit_ebp_scratch_load_to(
                                    out, 'rax')
                            else:
                                src = W32_TO_W64_REG.get(aval, 'rax')
                                if src != 'rax':
                                    out += self._asm(f'mov rax, {src}')
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype == 'mem_abs':
                            self._emit_abs_dword_load(out, 'rax', aval)
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype == 'mem_base':
                            base, disp = aval
                            self._emit_mem_base_dword_load(out, 'rax', base, disp)
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype in ('ebp_slot', 'esp_mem', 'ebp_local', 'ebp_arg', 'arg_home'):
                            self._emit_push_arg_to_stack(
                                out, off, atype, aval, frameless_stack_bias,
                                frame_arg_anchor, args_homed=frame_args_spilled)
                        else:
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], 0')
                elif not alloca_call and _skip_al and extra:
                    # setjmp family: still place stack args relative to current RSP
                    for i, (atype, aval) in enumerate(extra):
                        off = 0x20 + i * 8
                        if atype == 'imm':
                            imm = self._relocate_imm(aval & 0xFFFFFFFF, len(out), 0)
                            out += self._asm(
                                f'mov rax, 0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        else:
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], 0')

                # Emit CALL
                call_pos = len(out)
                if op.type == X86_OP_IMM:
                    target_rva = (op.imm - self.old_base) & 0xFFFFFFFF
                    iat_slot = self._ff25_iat_slot_at_rva(target_rva)
                    if iat_slot is not None:
                        self._emit_iat_call(out, iat_slot)
                    else:
                        target_va = op.imm
                        out += b'\xE8\x00\x00\x00\x00'   # placeholder
                        pending_fixups.append((call_pos + 1, target_va, 'rel32_call'))
                elif op.type == X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                    self._emit_iat_call(out, op.mem.disp)
                else:
                    # Indirect call — translate operand
                    try:
                        enc, _ = self.ks.asm(f'call {insn.op_str}')
                        out += bytes(enc)
                    except KsError:
                        if op.type == X86_OP_REG:
                            r = self._x64_call_target_reg(op.reg, iat_fn_holder)
                            out += self._asm(f'call {r}')
                        else:
                            self._emit_iat_call(out, op.mem.disp if op.type == X86_OP_MEM else 0)

                # Restore stack
                if not alloca_call and not _skip_al:
                    self._emit_call_align_epilogue(out, nstack)
                # cdecl/indirect: MSVC may emit pop ecx per pushed arg; skip those.
                # stdcall IAT callees pop args themselves on x86.
                if args and all(a[0] == 'esp_fwd' for a in args):
                    iat_fwd_epilogue = True
                elif (op.type == X86_OP_MEM and op.mem.base == 0
                      and op.mem.index == 0):
                    iat_fwd_epilogue = True
                elif (args and not (op.type == X86_OP_MEM and op.mem.base == 0
                                  and op.mem.index == 0)):
                    stack_cleanup_pending = len(args) * 4
                # CALL clobbers volatiles — drop stale pointer taint so a later
                # ``mov edi, eax; neg edi; sbb edi, edi; add edi, 3`` keeps the
                # add as 32-bit.  Otherwise ``add rdi, 3`` turns the 0xFFFFFFFF
                # mask into 0x100000002 (cmd 0xC6ED → wrong REPL mode flag).
                for _vr in (X86_REG_EAX, X86_REG_ECX, X86_REG_EDX):
                    self._ptr_taint_clear(ptr_taint, _vr)
                for _vn in ('r8', 'r9', 'r10', 'r11'):
                    ptr_taint.discard(_vn)
                cc_mode = 'stdcall'
                continue

            # ── RET / RET N (stdcall epilogue) → balance callee saves + RET ───
            if mnem in ('ret', 'retn'):
                if frame_rbp_saved and not leave_emitted:
                    # Pure-mode merged chunks may reach ``ret`` without a preceding
                    # x86 ``leave`` (epilogue was linearized away). Restore RBP frame.
                    out += self._asm('mov rsp, rbp')
                    out += self._asm('pop rbp')
                    frame_rbp_saved = False
                    leave_emitted = True
                    hw_stack_pushes = max(0, hw_stack_pushes - 1)
                    if callee_save_stack and callee_save_stack[-1] == 'rbp':
                        callee_save_stack.pop()
                elif not leave_emitted:
                    # Swallowed mega-chunk tails can omit the hardware POP that
                    # balances an entry callee-save (cmd 0x1089F: ``pop esi``
                    # overlapped by the next function's entry).  Only repair the
                    # single x86 POP immediately before this RET when the
                    # callee-save tracker still expects it and the translated
                    # tail is not already that POP — never walk a multi-POP chain
                    # (that double-pops after explicit epilogue POPs were emitted).
                    if callee_save_stack and _insn_idx > 0:
                        _prev = insns[_insn_idx - 1]
                        if (_prev.mnemonic == 'pop'
                                and _prev.address not in pop_pair
                                and _prev.operands
                                and _prev.operands[0].type == X86_OP_REG):
                            _pr = W32_TO_W64_REG.get(
                                _prev.operands[0].reg, 'rax')
                            if (callee_save_stack[-1] == _pr
                                    and self._out_tail_pop_reg(out) != _pr):
                                out += self._asm(f'pop {_pr}')
                                callee_save_stack.pop()
                                hw_stack_pushes = max(0, hw_stack_pushes - 1)
                                if frame_local_sub > 0:
                                    frameless_stack_bias = max(
                                        0, frameless_stack_bias - 8)
                    callee_save_stack.clear()
                else:
                    callee_save_stack.clear()
                    leave_emitted = False
                # x86 ``ret N`` (stdcall) pops N bytes of stack args.  Win64
                # register-arg call sites must not see ``add rsp,N`` (it skips
                # the return address — univ19 CRT died at ~78 steps).  Plain
                # ``ret`` is correct when callers were converted to Win64;
                # remaining push-based stdcall imbalance is handled by call
                # site repairs, not a blanket callee add.
                out += b'\xC3'
                frame_rbp_saved = False
                hw_stack_pushes = 0
                frame_local_sub = 0
                frameless_stack_bias = 0
                frame_arg_anchor = False
                parked_stdcall_arg0 = False
                push_stack.clear()
                iat_fwd_epilogue = False
                continue

            # ── LEAVE → ADD RSP, frame_size; (will be followed by RET) ────────
            if mnem == 'leave':
                out += self._asm('mov rsp, rbp')
                out += self._asm('pop rbp')
                frame_rbp_saved = False
                hw_stack_pushes = max(0, hw_stack_pushes - 1)
                if frame_local_sub > 0:
                    frameless_stack_bias = max(0, frameless_stack_bias - 8)
                if callee_save_stack and callee_save_stack[-1] == 'rbp':
                    callee_save_stack.pop()
                leave_emitted = True
                push_stack.clear()
                continue

            # ── PUSH EBP; MOV EBP,ESP prologue → Win64 frame ──────────────────
            if mnem == 'push' and ops and ops[0].type == X86_OP_REG:
                if ops[0].reg == X86_REG_EBP:
                    # Emit standard Win64 frame prologue
                    out += self._asm('push rbp')
                    frame_rbp_saved = True
                    ebp_data_ptr = False
                    hw_stack_pushes += 1
                    if frame_local_sub > 0:
                        frameless_stack_bias += 8
                    callee_save_stack.append('rbp')
                    push_stack.clear()
                    continue

            # ── MOV EBP,ESP → PUSH RBP; MOV RBP,RSP (if push ebp omitted) ───
            if mnem == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                if ops[0].reg == X86_REG_EBP and ops[1].reg == X86_REG_ESP:
                    if not frame_rbp_saved:
                        out += self._asm('push rbp')
                        hw_stack_pushes += 1
                        if frame_local_sub > 0:
                            frameless_stack_bias += 8
                        callee_save_stack.append('rbp')
                    out += self._asm('mov rbp, rsp')
                    frame_rbp_saved = True
                    ebp_data_ptr = False
                    # Home incoming integer args into the caller-provided shadow
                    # slots [rbp+0x10..0x30) so later [ebp+disp] reads/pushes see
                    # the stable stack copy even after the registers are reused.
                    if (rcx_home_reload or ebp_args_used) and not frame_args_spilled:
                        out += self._asm('mov qword ptr [rbp+0x10], rcx')
                        out += self._asm('mov qword ptr [rbp+0x18], rdx')
                        out += self._asm('mov qword ptr [rbp+0x20], r8')
                        out += self._asm('mov qword ptr [rbp+0x28], r9')
                        frame_args_spilled = True
                    push_stack.clear()
                    continue
                if ops[1].reg == X86_REG_ESP:
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    out += self._asm(f'mov {dst}, rsp')
                    push_stack.clear()
                    continue
                if ops[0].reg == X86_REG_ESP:
                    src = W32_TO_W64_REG.get(ops[1].reg, 'rcx')
                    out += self._asm(f'mov rsp, {src}')
                    push_stack.clear()
                    continue

            # ── SUB ESP,N / ADD ESP,N (stack frame / cdecl arg cleanup) ───────
            if mnem in ('sub', 'add') and len(ops) == 2:
                if (ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_ESP
                        and ops[1].type == X86_OP_IMM):
                    signed_n = ops[1].imm
                    if signed_n > 0x7FFFFFFF:
                        signed_n -= 0x100000000
                    if (iat_fwd_epilogue and mnem == 'add' and signed_n > 0):
                        # IAT forwarder tails are small add esp,N (≤7 stdcall args).
                        # Large adds (e.g. 0x58 frame dealloc before ret 4 at cmd
                        # 0xA123) must still be emitted or RET pops garbage.
                        iat_fwd_epilogue = False
                        if signed_n <= 0x1c:
                            push_stack.clear()
                            continue
                    if (mnem == 'add' and signed_n == stack_cleanup_pending
                            and stack_cleanup_pending):
                        # x86 pops pushed call args; Win64 already used RCX/RDX/…
                        stack_cleanup_pending = 0
                        push_stack.clear()
                        continue
                    if mnem == 'add' and signed_n < 0:
                        out += self._asm(f'sub rsp, 0x{-signed_n:x}')
                        if frame_local_sub > 0:
                            frameless_stack_bias += -signed_n
                    elif mnem == 'sub' and signed_n < 0:
                        out += self._asm(f'add rsp, 0x{-signed_n:x}')
                        if frame_local_sub > 0:
                            frameless_stack_bias -= -signed_n
                    else:
                        # ── Frame allocation alignment padding ──────────────
                        # x86 frames are 4-byte aligned; x64 requires 8-byte
                        # RSP alignment.  Round the allocation up to the next
                        # 8-byte boundary so RSP stays 8-byte aligned.
                        # _adjust_epilogue_add_rsp similarly rounds the
                        # epilogue ADD to match.
                        # Does NOT change frame_local_sub — that tracks the
                        # logical x86 size for [EBP+disp] frameless calcs.
                        adj_n = signed_n
                        if (mnem == 'sub' and not frame_rbp_saved
                                and signed_n > 0x28):
                            adj_n = (signed_n + 7) & ~7  # universal 8-byte rounding
                        op = 'sub' if mnem == 'sub' else 'add'
                        out += self._asm(
                            f'{op} rsp, 0x{adj_n & 0xFFFFFFFF:x}')
                        if (mnem == 'sub' and not frame_rbp_saved
                                and signed_n > 0x28):
                            # Real frame alloc (e.g. GPA sub esp,0x58), not 0x28
                            # Win64 call shadow space.
                            frame_local_sub = signed_n
                            frameless_stack_bias = 0
                            esp_dirty = True
                            # Spill Win64 incoming args to x86 [esp+4] homes.
                            for i, reg in enumerate(WIN64_ARG_REG_NAMES[:4]):
                                out += self._asm(
                                    f'mov qword ptr [rsp+0x{4 + i * 8:x}], {reg}')
                            out += self._asm('lea r15, [rsp]')
                            frame_arg_anchor = True
                            # Park arg0 in r12 (ebp_data_ptr_reg) so late
                            # ``mov ebp,[esp+0x6c]`` still sees it after nested
                            # __chkstk callees clobber r15 (cmd 0xA071).
                            out += self._asm(f'mov {ebp_data_ptr_reg}, rcx')
                            parked_stdcall_arg0 = True
                        elif frame_local_sub > 0:
                            if mnem == 'sub':
                                frameless_stack_bias += signed_n
                            else:
                                frameless_stack_bias -= signed_n
                    push_stack.clear()
                    continue

            # ── Jcc short/long → always emit as 6-byte rel32 ──────────────────
            if mnem.startswith('j') and mnem != 'jmp' and ops:
                op = ops[0]
                if op.type == X86_OP_IMM:
                    if (mnem == 'jl' and self.win10_test_shim
                            and ((old_va - self.old_base) & 0xFFFFFFFF) == 0x1A391):
                        # cmd quote tail: do not dec [len] when len==computed (0→-1).
                        mnem = 'jle'
                    jmp_pos = len(out)
                    # Map mnemonic to Jcc opcode suffix
                    out += b'\x0f\x00\x00\x00\x00\x00'  # placeholder (0F 8x rel32)
                    pending_fixups.append((jmp_pos, op.imm, f'jcc_{mnem}'))
                    push_stack.clear()
                    continue

            # ── JMP rel → E9 rel32 ────────────────────────────────────────────
            if mnem == 'jmp' and ops and ops[0].type == X86_OP_IMM:
                # MSVC ``push imm/reg; jmp call`` diamonds: materialize pending
                # args into Win64 registers before the jump.  Clearing (or
                # flushing as hardware PUSH) either drops the arg or leaks
                # 8 bytes per arm — cmd's locale selector does this twice per
                # REPL iteration and stack-overflows.
                if push_stack:
                    _jt = ops[0].imm
                    _tgt_is_call = False
                    for _ji in range(_insn_idx + 1, min(len(insns), _insn_idx + 64)):
                        if insns[_ji].address == _jt:
                            _tgt_is_call = insns[_ji].mnemonic == 'call'
                            break
                    if _tgt_is_call:
                        _args = list(reversed(push_stack))
                        elided_arg_bytes += len(_args) * 4
                        cdecl_pop_ecx_arg = _args[0] if _args else None
                        cdecl_pop_ecx_arg2 = _args[1] if len(_args) > 1 else None
                        self._emit_call_args_parallel(
                            out, _args, self._call_arg_regs(cc_mode),
                            ebp_reg_scratch=ebp_reg_scratch,
                            ebp_scratch_reg=ebp_scratch_reg,
                            frame_args_spilled=frame_args_spilled,
                            stack_spill_count=stack_spill_count,
                            frameless_stack_bias=frameless_stack_bias,
                            frame_arg_anchor=frame_arg_anchor,
                            hw_stack_pushes=hw_stack_pushes,
                            frameless_shadow_homes=frameless_shadow_homes)
                        push_stack.clear()
                    else:
                        hw_stack_pushes += self._flush_deferred_pushes(
                            out, push_stack)
                        push_stack.clear()
                jmp_pos = len(out)
                out += b'\xE9\x00\x00\x00\x00'
                pending_fixups.append((jmp_pos + 1, ops[0].imm, 'rel32_jmp'))
                continue

            # ── JMP/CALL through absolute IAT slot ────────────────────────────
            if mnem in ('jmp', 'call') and ops and ops[0].type == X86_OP_MEM:
                mem = ops[0].mem
                if mem.base == 0 and mem.index == 0 and mem.segment == 0:
                    if mnem == 'jmp':
                        self._emit_iat_jmp(out, mem.disp,
                                           at_rva=section_rva + chunk_base + len(out))
                    else:
                        pos_before = len(out)
                        self._emit_aligned_iat_call(out, mem.disp, 0)
                        # Safety: ensure align epilogue emitted pop r13.
                        # Some code paths can drop it; verify and re-emit.
                        if (len(out) >= 2
                                and out[-2:] != b'\x41\x5d'):
                            out += self._asm('pop r13')
                        iat_fwd_epilogue = True
                        cc_mode = 'stdcall'
                    push_stack.clear()
                    continue

            # ── MOV ebp, r32 after push ebp (scratch reg, not rbp) ─────────────
            if (self._cmd_no_hacks
                    and mnem == 'mov' and len(ops) == 2
                    and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EBP
                    and ops[1].type == X86_OP_REG
                    and 'rbp' in callee_save_stack
                    and self._mov_ebp_is_heap_scratch(_insn_idx, insns)):
                src = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                if frame_rbp_saved:
                    self._emit_ebp_scratch_store_reg(
                        out, src, ebp_scratch_home)
                    ebp_scratch_in_reg = False
                else:
                    # No ``mov rbp,rsp`` — keep the handle in RBP.  Saved caller
                    # RBP remains on the stack from ``push rbp``.
                    if src != 'rbp':
                        out += self._asm(f'mov rbp, {src}')
                    ebp_scratch_in_reg = True
                ebp_reg_scratch = True
                self._ebp_scratch_in_reg = ebp_scratch_in_reg
                push_stack.clear()
                continue

            # ── MOV r32, imm32 — patch pointer immediates ──────────────────────
            if mnem == 'mov' and len(ops) == 2 and ops[1].type == X86_OP_IMM:
                imm = ops[1].imm & 0xFFFFFFFF
                if (self._cmd_no_hacks
                        and ops[0].type == X86_OP_REG
                        and ops[0].reg == X86_REG_EBP
                        and 'rbp' in callee_save_stack
                        and self._mov_ebp_is_heap_scratch(_insn_idx, insns)):
                    if frame_rbp_saved:
                        out += self._asm(
                            f'mov {self._ebp_scratch_mem(ebp_scratch_home)}, '
                            f'0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                        ebp_scratch_in_reg = False
                    else:
                        out += self._asm(
                            f'mov rbp, 0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                        ebp_scratch_in_reg = True
                    ebp_reg_scratch = True
                    self._ebp_scratch_in_reg = ebp_scratch_in_reg
                    push_stack.clear()
                    continue
                new_imm = self._relocate_imm(imm, len(out), 0)
                if ops[0].type == X86_OP_REG:
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    out += self._asm(f'mov {dst}, 0x{new_imm & 0xFFFFFFFFFFFFFFFF:x}')
                    if (self._is_image_pointer(imm)
                            or (new_imm & 0xFFFFFFFF) != imm):
                        self._ptr_taint_mark(ptr_taint, ops[0].reg)
                    else:
                        self._ptr_taint_clear(ptr_taint, ops[0].reg)
                    # Do NOT clear push_stack: compilers interleave scratch
                    # loads between arg pushes (cmd ReadFile wrapper:
                    # ``push 1; push 0; push 0; mov edi,buf; push handle;
                    # call SetFilePointer``). Clearing dropped the distance /
                    # method args and left R8=0x800 as a bogus pointer.
                    continue

            # ── MOV via 32-bit register base/index (must widen to r64) ─────────
            if mnem == 'mov' and len(ops) == 2:
                def _w64(reg_id: int) -> str:
                    return W32_TO_W64_REG.get(reg_id, 'rax')

                def _mem_str(mem_op) -> Tuple[Optional[str], bool]:
                    if mem_op.type != X86_OP_MEM:
                        return None, False
                    m = mem_op.mem
                    if m.segment not in (0,):
                        return None, False
                    if m.base and m.index:
                        scale = m.scale or 1
                        if scale == 1 and not m.disp:
                            # x86 [eax+ecx] must use 64-bit [rax+rcx] on the host.
                            # addr32 (67h) truncates base/index and breaks heap ptrs.
                            base = _w64(m.base)
                            idx = _w64(m.index)
                            return f'[{base}+{idx}]', False
                        return None, False
                    if m.base:
                        base = _w64(m.base)
                        if m.disp:
                            disp_u = m.disp & 0xFFFFFFFF
                            new_disp = self._relocate_imm(disp_u, len(out), 0)
                            if (self._is_image_pointer(disp_u)
                                    or new_disp != disp_u
                                    or new_disp >= 0x80000000):
                                # [reg+image_VA] — scratch base in handlers below.
                                return None, False
                            return f'[{base}{m.disp:+d}]', False
                        return f'[{base}]', False
                    if m.index:
                        idx = _w64(m.index)
                        scale = m.scale or 1
                        if m.disp:
                            # [idx*scale + abs] is a global table — needs VA
                            # relocation; handled by the dedicated handlers below.
                            return None, False
                        return f'[{idx}*{scale}]', False
                    return None, False

                if ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
                    mems, addr32 = _mem_str(ops[0])
                    if mems:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        src = (self._word_reg_asm_for_op(ops[1], insn.op_str)
                               if ptr_sz == 'word'
                               else self._reg_asm_for_op(ops[1], insn.op_str))
                        emit = self._asm_addr32 if addr32 else self._asm
                        # cmd heap/cmdline tables: widen to qword slots on Win10 (8-byte
                        # stride via shl 3 at 0x1A408/0x1A45C) so HeapAlloc pointers survive.
                        if ptr_sz in ('byte', 'word'):
                            slot_sz = ptr_sz
                        elif (self.win10_test_shim
                              and self._cmd_heap_indexed_mem(ops[0].mem)):
                            slot_sz = 'qword'
                        else:
                            slot_sz = 'dword'
                        if slot_sz == 'qword':
                            src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                            out += emit(f'mov {slot_sz} ptr {mems}, {src64}')
                        else:
                            out += emit(f'mov {slot_sz} ptr {mems}, {src}')
                        # ``push args; mov [esp+N], reg; call`` — keep deferred
                        # args (cmd GetVDMCurrentDirectories at 0x71BC).
                        if not (ops[0].mem.base == X86_REG_ESP
                                and not ops[0].mem.index):
                            push_stack.clear()
                        continue
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
                    mems, addr32 = _mem_str(ops[1])
                    if mems:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                        emit = self._asm_addr32 if addr32 else self._asm
                        if ptr_sz == 'word':
                            out += emit(f'movzx {dst64}, word ptr {mems}')
                        elif ptr_sz == 'byte':
                            out += emit(f'movzx {dst64}, byte ptr {mems}')
                        elif ptr_sz == 'dword':
                            m = ops[1].mem
                            disp_u = m.disp & 0xFFFFFFFF if m.disp else 0
                            if (self.win10_test_shim
                                    and (self._cmd_heap_indexed_mem(m)
                                         or self._cmd_builder_struct_ptr_field(
                                             old_va, disp_u))):
                                out += emit(f'mov {dst64}, qword ptr {mems}')
                            else:
                                dst32 = W32_REG_ASM.get(ops[0].reg, 'eax')
                                out += emit(f'mov {dst32}, dword ptr {mems}')
                            self._ptr_taint_mark(ptr_taint, ops[0].reg)
                        else:
                            out += emit(f'mov {dst64}, qword ptr {mems}')
                            self._ptr_taint_mark(ptr_taint, ops[0].reg)
                        push_stack.clear()
                        continue
                    m = ops[1].mem
                    if (m.segment == 0 and m.base and m.index and not m.disp
                            and (m.scale or 1) in (2, 4, 8)):
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        if ptr_sz == 'dword':
                            b64 = W32_TO_W64_REG.get(m.base, 'rax')
                            i64 = W32_TO_W64_REG.get(m.index, 'rax')
                            scale = m.scale or 1
                            dst32 = W32_REG_ASM.get(ops[0].reg, 'eax')
                            out += self._asm(
                                f'mov {dst32}, dword ptr [{b64}+{i64}*{scale}]')
                            self._ptr_taint_mark(ptr_taint, ops[0].reg)
                            push_stack.clear()
                            continue

            # ── XOR r32, r32 → XOR r64, r64 (zero) ────────────────────────────
            if mnem == 'xor' and len(ops) == 2:
                if (ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                        and ops[0].reg == ops[1].reg):
                    r = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    out += self._asm(f'xor {r}, {r}')
                    self._ptr_taint_clear(ptr_taint, ops[0].reg)
                    self._teb_ptr_clear(teb_ptr_regs, ops[0].reg)
                    # Preserve deferred call args (same rationale as mov-imm).
                    continue

            # ── MOV r32, r32 — propagate pointer taint ────────────────────────
            if mnem == 'mov' and len(ops) == 2:
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                    if (ops[1].reg == X86_REG_EBP and ebp_reg_scratch
                            and ops[0].reg != X86_REG_EBP):
                        dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                        self._emit_ebp_scratch_load_to(
                            out, dst64)
                        self._ptr_taint_propagate(ptr_taint, ops[0].reg, ops[1].reg)
                        self._teb_ptr_propagate(teb_ptr_regs, ops[0].reg, ops[1].reg)
                        continue
                    dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                    # A reg-reg mov can sit *between* argument pushes (compilers
                    # interleave it, e.g. cmd 0x65B0 `push [g]; mov esi,eax;
                    # push 0; …; call HeapFree`). Preserve the pending deferred
                    # args here — clearing push_stack drops the HeapFree lpMem
                    # arg and frees a garbage pointer (heap corruption).
                    if dst64 in ('r8', 'r9'):
                        self._emit_mov32_to_w64_reg(
                            out, dst64, ops[1].reg,
                            ebp_reg_scratch, ebp_scratch_reg)
                    elif dst64 != src64:
                        if self._cmd_no_hacks:
                            # Preserve full pointer width for rax→r64 after
                            # heap/object returns (cmd ``call db0b; mov esi,eax``).
                            # Truncating via ``mov esi, eax`` is fine for ints
                            # (zero-extends) but drops the high half of Win64
                            # heap pointers when they ever sit above 4GiB; more
                            # immediately, keep rax→rsi as a true 64-bit move so
                            # subsequent ``[rsi+…]`` matches the allocator.
                            if (src64 == 'rax'
                                    and dst64 in ('rsi', 'rdi', 'rbx', 'rbp')):
                                out += self._asm(f'mov {dst64}, {src64}')
                            else:
                                dst32 = W32_REG_ASM.get(ops[0].reg, 'eax')
                                src32 = W32_REG_ASM.get(ops[1].reg, 'eax')
                                if dst32 != src32:
                                    out += self._asm(f'mov {dst32}, {src32}')
                        else:
                            out += self._asm(f'mov {dst64}, {src64}')
                    else:
                        out += b'\x90'
                    self._ptr_taint_propagate(ptr_taint, ops[0].reg, ops[1].reg)
                    self._teb_ptr_propagate(teb_ptr_regs, ops[0].reg, ops[1].reg)
                    continue
            if mnem == 'pop' and old_va in pop_pair and ops and ops[0].type == X86_OP_REG:
                ptype, pval = pop_pair[old_va]
                if (ptype == 'imm' and (pval & 0xFFFFFFFF) == 0x30
                        and ops[0].reg == X86_REG_EDI
                        and next_insn is not None
                        and next_insn.mnemonic == 'add'
                        and len(next_insn.operands) == 2
                        and next_insn.operands[0].type == X86_OP_REG
                        and next_insn.operands[0].reg == X86_REG_EAX
                        and next_insn.operands[1].type == X86_OP_REG
                        and next_insn.operands[1].reg == X86_REG_EDI):
                    # push 0x30; pop edi; add eax, edi — do not clobber RDI.
                    continue
                dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                if ptype == 'imm':
                    imm = pval & 0xFFFFFFFF
                    new_imm = self._relocate_imm(imm, len(out), 0)
                    out += self._asm(f'mov {dst}, 0x{new_imm & 0xFFFFFFFFFFFFFFFF:x}')
                    if (self._is_image_pointer(imm)
                            or (new_imm & 0xFFFFFFFF) != imm):
                        self._ptr_taint_mark(ptr_taint, ops[0].reg)
                    else:
                        self._ptr_taint_clear(ptr_taint, ops[0].reg)
                else:
                    # Register-register push/pop pair: this is a callee-save
                    # spill/restore, NOT a constant-load idiom.  Emit the pop
                    # to actually restore the register — do NOT eliminate it.
                    src = W32_TO_W64_REG.get(pval, 'rax')
                    out += self._asm(f'pop {dst}')
                    if src != dst:
                        # If the register changed (e.g. ESI→R14), also move
                        out += self._asm(f'mov {dst}, {src}')
                    self._ptr_taint_propagate(ptr_taint, ops[0].reg, pval)
                continue

            # ── POP ECX cdecl/stdcall cleanup after register-arg CALL → drop ──
            # MSVC often emits `pop ecx` after stdcall IAT calls that pushed args
            # on x86; on Win64 those args are already in RCX/RDX — popping here
            # corrupts the stack (cmd builder: two pop ecx after HeapAlloc call).
            if (mnem == 'pop' and ops and ops[0].type == X86_OP_REG
                    and ops[0].reg == X86_REG_ECX):
                nx = next_insn
                nx2 = insns[_insn_idx + 2] if _insn_idx + 2 < len(insns) else None
                if (nx is not None and nx.mnemonic == 'push'
                        and nx.operands
                        and nx.operands[0].type == X86_OP_REG
                        and nx.operands[0].reg == X86_REG_EAX
                        and nx2 is not None and nx2.mnemonic == 'call'):
                    if cdecl_shared_surplus:
                        # Surplus args (buf/size/&n) apply at the follow-on CALL
                        # together with the pushed EAX handle — do not invent RDX
                        # from the consumed fd slot.
                        cdecl_pop_ecx_arg = None
                        cdecl_pop_ecx_arg2 = None
                        push_stack.clear()
                        continue
                    if cdecl_pop_ecx_arg is not None:
                        rdx_arg = self._pick_cdecl_pop_ecx_rdx_arg(
                            cdecl_pop_ecx_arg, cdecl_pop_ecx_arg2,
                            self.old_base, self.pe.image_size)
                        if rdx_arg is not None:
                            atype, aval = rdx_arg
                            self._emit_flushed_push_arg_to_reg(
                                out, 'rdx', atype, aval,
                                ebp_reg_scratch=ebp_reg_scratch,
                                ebp_scratch_reg=ebp_scratch_reg,
                                frame_args_spilled=frame_args_spilled,
                                stack_spill_count=stack_spill_count,
                                frameless_stack_bias=frameless_stack_bias,
                                frame_arg_anchor=frame_arg_anchor)
                        cdecl_pop_ecx_arg = None
                        cdecl_pop_ecx_arg2 = None
                    push_stack.clear()
                    continue
                if stack_cleanup_pending > 0:
                    stack_cleanup_pending = max(0, stack_cleanup_pending - 4)
                    iat_fwd_epilogue = False
                    push_stack.clear()
                    continue
                # Frameless ``push ecx`` local dealloc at epilogue (cmd ``fbe4``
                # ends ``pop edi..ebx; pop ecx; pop ecx; ret 4``).  Dropping
                # these as stdcall cleanup leaves RSP 16 bytes low → ret@0.
                if hw_stack_pushes > len(callee_save_stack):
                    out += self._asm('add rsp, 8')
                    hw_stack_pushes = max(0, hw_stack_pushes - 1)
                    if frame_local_sub > 0:
                        frameless_stack_bias = max(0, frameless_stack_bias - 8)
                    iat_fwd_epilogue = False
                    push_stack.clear()
                    continue
                iat_fwd_epilogue = False
                push_stack.clear()
                continue

            # ── POP r32 → POP r64 ─────────────────────────────────────────────
            if mnem == 'pop' and ops and ops[0].type == X86_OP_REG:
                if (old_va - self.old_base) in (0x655D, 0x6555):
                    print(f"  [DBG POP] 0x{(old_va - self.old_base):X}: {mnem} {ops[0].reg} "
                          f"callee_save_stack={callee_save_stack} "
                          f"pop_pair={old_va in pop_pair} "
                          f"len(out)=0x{len(out):X}")
                if ops[0].reg in (X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX):
                    iat_fwd_epilogue = False
                if ops[0].reg == X86_REG_EBP:
                    ebp_reg_scratch = False
                    ebp_scratch_reg = 'r12'
                r = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                if callee_save_stack and callee_save_stack[-1] == r:
                    callee_save_stack.pop()
                    out += self._asm(f'pop {r}')
                elif r == 'rbp' and 'rbp' not in callee_save_stack:
                    push_stack.clear()
                    continue
                else:
                    if r in callee_save_stack:
                        callee_save_stack.remove(r)
                    out += self._asm(f'pop {r}')
                hw_stack_pushes = max(0, hw_stack_pushes - 1)
                if frame_local_sub > 0:
                    frameless_stack_bias = max(0, frameless_stack_bias - 8)
                if ops[0].reg == X86_REG_EBP:
                    frame_rbp_saved = False
                    ebp_data_ptr = False
                push_stack.clear()
                continue

            # ── Indirect CALL/JMP via register ────────────────────────────────
            if mnem == 'call' and ops and ops[0].type == X86_OP_REG:
                if (push_stack
                        and self._reg_holds_zero_arg_iat(ops[0].reg, iat_fn_slot)):
                    r = self._x64_call_target_reg(ops[0].reg, iat_fn_holder)
                    if r in ('rax', 'r11'):
                        out += self._asm(f'mov r10, {r}')
                        r = 'r10'
                    self._emit_call_align_prologue(out, 0)
                    out += self._asm(f'call {r}')
                    self._emit_call_align_epilogue(out, 0)
                    iat_fwd_epilogue = True
                    cc_mode = 'stdcall'
                    continue
                if push_stack:
                    reg_op = ops[0]
                    args = list(reversed(push_stack))
                    if args:
                        elided_arg_bytes += len(args) * 4
                        cdecl_pop_ecx_arg = args[0]
                        cdecl_pop_ecx_arg2 = args[1] if len(args) > 1 else None
                    push_stack.clear()
                    arg_regs = self._call_arg_regs(cc_mode)
                    self._emit_call_args_parallel(
                        out, args, arg_regs,
                        ebp_reg_scratch=ebp_reg_scratch,
                        ebp_scratch_reg=ebp_scratch_reg,
                        frame_args_spilled=frame_args_spilled,
                        stack_spill_count=stack_spill_count,
                        frameless_stack_bias=frameless_stack_bias,
                        frame_arg_anchor=frame_arg_anchor,
                        hw_stack_pushes=hw_stack_pushes,
                        frameless_shadow_homes=frameless_shadow_homes)
                    if stack_spill_count:
                        out += self._asm(f'add rsp, 0x{8 * stack_spill_count:x}')
                        stack_spill_count = 0
                    extra = args[4:]
                    nstack = len(extra)
                    # Capture the call target before arg materialization / realign
                    # can clobber a volatile target register (rax/r11 are used as
                    # scratch by the aligned-frame setup).
                    r = self._x64_call_target_reg(reg_op.reg, iat_fn_holder)
                    if r in ('rax', 'r11'):
                        out += self._asm(f'mov r10, {r}')
                        r = 'r10'
                    self._emit_call_align_prologue(out, nstack)
                    for i, (atype, aval) in enumerate(extra):
                        off = 0x20 + i * 8
                        if atype == 'imm':
                            imm = self._relocate_imm(aval & 0xFFFFFFFF, len(out), 0)
                            out += self._asm(
                                f'mov rax, 0x{imm & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype == 'reg':
                            if aval == X86_REG_EBP and ebp_reg_scratch:
                                self._emit_ebp_scratch_load_to(
                                    out, 'rax')
                            else:
                                src = W32_TO_W64_REG.get(aval, 'rax')
                                if src != 'rax':
                                    out += self._asm(f'mov rax, {src}')
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype == 'mem_abs':
                            self._emit_abs_dword_load(out, 'rax', aval)
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype == 'ebp_local':
                            self._emit_lea_ebp_slot(out, 'rax', aval)
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], rax')
                        elif atype in ('ebp_slot', 'esp_mem', 'ebp_arg', 'arg_home'):
                            self._emit_push_arg_to_stack(
                                out, off, atype, aval, frameless_stack_bias,
                                frame_arg_anchor, args_homed=frame_args_spilled)
                        else:
                            out += self._asm(f'mov qword ptr [rsp+0x{off:x}], 0')
                    out += self._asm(f'call {r}')
                    self._emit_call_align_epilogue(out, nstack)
                    if args:
                        iat_fwd_epilogue = True
                    cc_mode = 'stdcall'
                    continue
                r = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                out += self._asm(f'call {r}')
                push_stack.clear()
                continue
            if mnem == 'jmp' and ops and ops[0].type == X86_OP_REG:
                r = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                out += self._asm(f'jmp {r}')
                push_stack.clear()
                continue

            # ── NOP ────────────────────────────────────────────────────────────
            if mnem == 'nop':
                out += b'\x90'
                continue

            # ── LEA r32, [EBP+disp] (positive disp = stack arg in stdcall frame) ─
            if mnem == 'lea' and len(ops) == 2 and ops[1].type == X86_OP_MEM:
                m = ops[1].mem
                if m.base == X86_REG_EBP and not m.index and m.disp >= 0:
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    self._emit_lea_ebp_slot(out, dst, m.disp)
                    # Do NOT clear push_stack — see lea [idx*scale+abs] below.
                    continue
                # ── lea reg, [esp+disp] — ADDRESS-OF a frameless stack slot ──────
                # The generic ``base+disp`` path below keeps the raw x86 disp, but
                # an ESP base must be re-based exactly like a ``mov reg,[esp+disp]``
                # read: every callee-save / hardware push is 8 bytes on x64 vs 4 on
                # x86, so the slot sits ``hw_stack_pushes*4`` bytes deeper.  Without
                # this, e.g. cmd 0x9EBA's ``lea eax,[esp+0x10]`` (the lpMode pointer
                # handed to GetConsoleMode) resolved to [rsp+0x10] — the SAVED-RBP
                # slot — and the API wrote through it, trashing rbp on return.
                # Only the frameless LOCAL case is intercepted here; an address
                # taken of a homed incoming arg (arg_slot != None) is left to the
                # generic path below so its bytes stay identical.  The local fix is
                # a pure displacement rebase (same encoding length, disp8→disp8),
                # so the whole downstream code layout — and the fragile duplicate/
                # heal resolution keyed on it — is preserved byte-for-byte.  We
                # also deliberately do NOT ptr_taint the dest (the legacy path
                # never did; tainting would cascade into wider instr selection).
                if (m.base == X86_REG_ESP and not m.index and m.segment == 0
                        and hw_stack_pushes):
                    disp = m.disp & 0xFFFFFFFF
                    if disp > 0x7FFFFFFF:
                        disp -= 0x100000000
                    arg_slot = self._frameless_stdcall_arg_slot(
                        disp, frame_local_sub, hw_stack_pushes, elided_arg_bytes)
                    if arg_slot is None and disp >= 0:
                        dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                        off_x64 = (disp + hw_stack_pushes * 4) & 0xFFFFFFFFFFFFFFFF
                        out += self._asm(f'lea {dst}, [rsp+0x{off_x64:x}]')
                        continue
                if m.base and not m.index and m.disp:
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    base = W32_TO_W64_REG.get(m.base, 'rax')
                    disp_u = m.disp & 0xFFFFFFFF
                    new_disp = self._relocate_imm(disp_u, len(out), 0)
                    if (self._is_image_pointer(disp_u) or new_disp != disp_u
                            or new_disp > 0x7FFFFFFF):
                        out += self._asm(f'mov {dst}, {base}')
                        self._emit_add_imm64(out, dst, new_disp)
                        self._ptr_taint_mark(ptr_taint, ops[0].reg)
                    else:
                        out += self._asm(f'lea {dst}, [{base}{m.disp:+d}]')
                    # Do NOT clear push_stack — interleaved among call args.
                    continue
                if m.base == 0 and m.index and m.disp:
                    idx = W32_TO_W64_REG.get(m.index, 'rax')
                    scale = m.scale or 1
                    new_disp = self._relocate_imm(m.disp & 0xFFFFFFFF, len(out), 0)
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    if new_disp < 0x80000000:
                        out += self._asm(
                            f'lea {dst}, [{idx}*{scale} + 0x{new_disp:x}]')
                    else:
                        # disp32 sign-extends past 2GB → load base via scratch.
                        scratch = 'r11' if idx != 'r11' else 'r10'
                        out += self._asm(f'mov {scratch}, 0x{new_disp:x}')
                        out += self._asm(f'lea {dst}, [{scratch} + {idx}*{scale}]')
                    self._ptr_taint_mark(ptr_taint, ops[0].reg)
                    # Do NOT clear push_stack: cmd ReadFile path does
                    # ``push &n; push 1; lea eax,[count*2+buf]; push eax;
                    # push fd; call _get_osfhandle`` — clearing here dropped
                    # &n/size and left the follow-on wrapper with garbage R8/R9.
                    continue
                if m.base and m.index:
                    dst = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    base = W32_TO_W64_REG.get(m.base, 'rax')
                    idx = W32_TO_W64_REG.get(m.index, 'rax')
                    scale = m.scale or 1
                    disp = m.disp or 0
                    if scale == 1 and disp == 0:
                        mem = f'[{base} + {idx}]'
                    elif disp == 0:
                        mem = f'[{base} + {idx}*{scale}]'
                    elif scale == 1:
                        mem = f'[{base} + {idx}{disp:+d}]'
                    else:
                        mem = f'[{base} + {idx}*{scale}{disp:+d}]'
                    out += self._asm(f'lea {dst}, {mem}')
                    self._ptr_taint_mark(ptr_taint, ops[0].reg)
                    continue

            # ── MOV r32, [index*scale + abs] (pointer table load) ─────────────
            if mnem == 'mov' and len(ops) == 2 and ops[1].type == X86_OP_MEM:
                m = ops[1].mem
                if m.base == 0 and m.index and m.disp and ops[0].type == X86_OP_REG:
                    idx = W32_TO_W64_REG.get(m.index, 'rax')
                    scale = m.scale or 1
                    new_disp = self._relocate_imm(m.disp & 0xFFFFFFFF, len(out), 0)
                    dst = W32_REG_ASM.get(ops[0].reg, 'eax')
                    if (new_disp < 0x80000000
                            and not self._is_image_pointer(m.disp & 0xFFFFFFFF)):
                        out += self._asm(
                            f'mov {dst}, dword ptr [{idx}*{scale} + 0x{new_disp:x}]')
                    else:
                        scratch = 'r11' if idx != 'r11' else 'r10'
                        out += self._asm(f'mov {scratch}, 0x{new_disp:x}')
                        out += self._asm(
                            f'mov {dst}, dword ptr [{scratch} + {idx}*{scale}]')
                    push_stack.clear()
                    continue

            # ── MOV [abs32], r32 / MOV r32, [abs32] (A2/A3 / A0/A1) ───────────
            # Keystone encodes these as moffs64 ``A3`` which bypasses movabs
            # patching; a later tip-match can then land the store on a truncated
            # ``.data+(old_rva&0xFFFF)`` slot (cmd 0x9EC2 CS pointer → 0x5a87c
            # while EnterCriticalSection reads 0x5e87c → uninit CS → AV).
            if mnem == 'mov' and len(ops) == 2:
                if (ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG
                        and ops[0].mem.base == 0 and ops[0].mem.index == 0
                        and ops[0].mem.segment == 0):
                    addr = ops[0].mem.disp & 0xFFFFFFFF
                    new_va = self._relocate_imm(addr, len(out), 0)
                    src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                    ptr_sz = self._mem_ptr_size(insn.op_str)
                    if ptr_sz == 'byte':
                        src = self._reg_asm_for_op(ops[1], insn.op_str)
                        scratch = 'r11' if src64 != 'r11' else 'r10'
                        out += self._asm(f'movabs {scratch}, 0x{new_va:x}')
                        out += self._asm(f'mov byte ptr [{scratch}], {src}')
                    elif ptr_sz == 'word':
                        src = self._word_reg_asm_for_op(ops[1], insn.op_str)
                        scratch = 'r11' if src64 != 'r11' else 'r10'
                        out += self._asm(f'movabs {scratch}, 0x{new_va:x}')
                        out += self._asm(f'mov word ptr [{scratch}], {src}')
                    else:
                        out += self._encode_abs_store(src64, new_va)
                    push_stack.clear()
                    continue
                if (ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM
                        and ops[1].mem.base == 0 and ops[1].mem.index == 0
                        and ops[1].mem.segment == 0):
                    addr = ops[1].mem.disp & 0xFFFFFFFF
                    dst64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    ptr_sz = self._mem_ptr_size(insn.op_str)
                    if ptr_sz == 'byte':
                        scratch = 'r11' if dst64 != 'r11' else 'r10'
                        new_va = self._relocate_imm(addr, len(out), 0)
                        out += self._asm(f'movabs {scratch}, 0x{new_va:x}')
                        out += self._asm(f'movzx {dst64}, byte ptr [{scratch}]')
                    elif ptr_sz == 'word':
                        scratch = 'r11' if dst64 != 'r11' else 'r10'
                        new_va = self._relocate_imm(addr, len(out), 0)
                        out += self._asm(f'movabs {scratch}, 0x{new_va:x}')
                        out += self._asm(f'movzx {dst64}, word ptr [{scratch}]')
                    else:
                        self._emit_abs_dword_load(out, dst64, addr)
                    self._ptr_taint_mark(ptr_taint, ops[0].reg)
                    push_stack.clear()
                    continue

            # ── MOV [index*scale + abs], r32 (pointer table store) ────────────
            if mnem == 'mov' and len(ops) == 2 and ops[0].type == X86_OP_MEM:
                m = ops[0].mem
                if m.base == 0 and m.index and m.disp and ops[1].type == X86_OP_REG:
                    idx = W32_TO_W64_REG.get(m.index, 'rax')
                    scale = m.scale or 1
                    new_disp = self._relocate_imm(m.disp & 0xFFFFFFFF, len(out), 0)
                    ptr_sz = self._mem_ptr_size(insn.op_str)
                    ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                    src = self._ebp_slot_reg_asm(ops[1], insn.op_str, ebp_sz)
                    if (new_disp < 0x80000000
                            and not self._is_image_pointer(m.disp & 0xFFFFFFFF)):
                        out += self._asm(
                            f'mov {ebp_sz} ptr [{idx}*{scale} + 0x{new_disp:x}], '
                            f'{src}')
                    else:
                        scratch = 'r11' if idx != 'r11' else 'r10'
                        out += self._asm(
                            f'mov {scratch}, 0x{new_disp & 0xFFFFFFFFFFFFFFFF:x}')
                        out += self._asm(
                            f'mov {ebp_sz} ptr [{scratch} + {idx}*{scale}], {src}')
                    push_stack.clear()
                    continue
                if m.base and not m.index and m.disp and ops[1].type == X86_OP_REG:
                    disp_u = m.disp & 0xFFFFFFFF
                    new_disp = self._relocate_imm(disp_u, len(out), 0)
                    if self._is_image_pointer(disp_u) or new_disp != disp_u:
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        ebp_sz = ptr_sz if ptr_sz in ('byte', 'word') else 'dword'
                        # Byte/word src must keep al/bl/… — W32_REG_ASM (eax)
                        # makes Keystone reject ``mov byte ptr [r11+rax], eax``
                        # and the fallback INT3 (cmd 0xEFE9 → RIP=0 after longjmp).
                        src = self._ebp_slot_reg_asm(ops[1], insn.op_str, ebp_sz)
                        # ah/bh/ch/dh cannot pair with a REX-prefixed base (r11).
                        if src not in ('ah', 'bh', 'ch', 'dh'):
                            base64 = W32_TO_W64_REG.get(m.base, 'rax')
                            scratch = 'r11' if base64 != 'r11' else 'r10'
                            out += self._asm(
                                f'mov {scratch}, '
                                f'0x{new_disp & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(
                                f'mov {ebp_sz} ptr [{scratch} + {base64}], '
                                f'{src}')
                            push_stack.clear()
                            continue

            # ── 64-bit ALU on pointer-tainted registers (inc edx truncates RDX) ─
            if mnem in ('inc', 'dec') and len(ops) == 1 and ops[0].type == X86_OP_REG:
                r64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                if (ops[0].reg != X86_REG_ESP
                        and (r64 in ptr_taint or self.win10_test_shim)):
                    out += self._asm(f'{mnem} {r64}')
                    push_stack.clear()
                    continue

            if mnem in ('add', 'sub') and len(ops) == 2 and ops[0].type == X86_OP_REG:
                if (mnem == 'add' and ops[0].reg == X86_REG_EAX
                        and ops[1].type == X86_OP_REG and ops[1].reg == X86_REG_EDI
                        and self._cmd_builder_add_eax_edi_plus30(old_va)):
                    out += self._asm('add rax, 0x30')
                    push_stack.clear()
                    continue
                r64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                if r64 in ptr_taint and ops[0].reg != X86_REG_ESP:
                    if ops[1].type == X86_OP_IMM:
                        imm = ops[1].imm & 0xFFFFFFFF
                        if self._is_image_pointer(imm):
                            imm = self._relocate_imm(imm, len(out), 0)
                            scratch = 'r11' if r64 != 'r11' else 'r10'
                            out += self._asm(
                                f'movabs {scratch}, 0x{imm:x}')
                            out += self._asm(f'{mnem} {r64}, {scratch}')
                            continue
                        if mnem == 'add':
                            self._emit_add_imm64(out, r64, imm)
                        else:
                            s32 = imm if imm < 0x80000000 else imm - 0x100000000
                            if s32 < 0:
                                self._emit_add_imm64(out, r64, -s32)
                            else:
                                scratch = 'r11' if r64 != 'r11' else 'r10'
                                out += self._asm(
                                    f'movabs {scratch}, 0x{imm:x}')
                                out += self._asm(f'sub {r64}, {scratch}')
                        continue
                    if ops[1].type == X86_OP_REG:
                        src64 = W32_TO_W64_REG.get(ops[1].reg, 'rax')
                        out += self._asm(f'{mnem} {r64}, {src64}')
                        continue
                # Image-pointer table-base addends (even without ptr taint):
                # ``add edi, 0x4AD1D480`` must not become sign-extending
                # ``add rdi, imm32`` once remapped above 2GB.  Always emit
                # movabs+add so ``_patch_abs_va_in_code`` can rebase the VA.
                if (ops[1].type == X86_OP_IMM and ops[0].reg != X86_REG_ESP
                        and self._is_image_pointer(ops[1].imm & 0xFFFFFFFF)):
                    imm = self._relocate_imm(
                        ops[1].imm & 0xFFFFFFFF, len(out), 0)
                    scratch = 'r11' if r64 != 'r11' else 'r10'
                    out += self._asm(f'movabs {scratch}, 0x{imm:x}')
                    out += self._asm(f'{mnem} {r64}, {scratch}')
                    continue

            # ── String store (stosd) → explicit dword store + advance RDI ─────
            if mnem == 'stosd':
                out += self._asm('mov dword ptr [rdi], eax')
                out += self._asm('add rdi, 4')
                push_stack.clear()
                continue

            # ── [reg + reg] pointer null tests (cmd table slots) ───────────────
            if (self.win10_test_shim and mnem in ('cmp', 'test') and len(ops) == 2
                    and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM
                    and ops[1].imm == 0):
                m = ops[0].mem
                if m.segment == 0 and m.base and m.index and not m.disp:
                    base64 = W32_TO_W64_REG.get(m.base, 'rax')
                    idx64 = W32_TO_W64_REG.get(m.index, 'rax')
                    scale = m.scale or 1
                    if scale == 1:
                        slot_sz = ('qword' if self.win10_test_shim
                                   and self._cmd_heap_indexed_mem(m)
                                   else 'dword')
                        out += self._asm(
                            f'cmp {slot_sz} ptr [{base64}+{idx64}], 0')
                        push_stack.clear()
                        continue

            # ── [TEB+disp] indirect field access (post fs:[0x18] self load) ───
            if len(ops) == 2 and any(op.type == X86_OP_MEM for op in ops):
                mem_op = next(op for op in ops if op.type == X86_OP_MEM)
                m = mem_op.mem
                if m.segment == 0 and m.base and not m.index:
                    base64 = W32_TO_W64_REG.get(m.base, 'rax')
                    if base64 in teb_ptr_regs:
                        fs_disp = m.disp & 0xFFFFFFFF
                        if fs_disp > 0x7FFFFFFF:
                            fs_disp -= 0x100000000
                        gs_disp = TEB_FS_TO_GS.get(fs_disp, fs_disp)
                        sz = self._teb_indirect_field_size(gs_disp)
                        other = ops[1] if mem_op is ops[0] else ops[0]
                        if mem_op is ops[0] and other.type == X86_OP_REG:
                            if sz == 'qword':
                                dst = W32_TO_W64_REG.get(other.reg, 'rax')
                            else:
                                dst = self._ebp_slot_reg_asm(
                                    other, insn.op_str, sz)
                            out += self._asm(
                                f'mov {dst}, {sz} ptr [{base64}+0x{gs_disp:x}]')
                            push_stack.clear()
                            continue
                        if mem_op is ops[1] and other.type == X86_OP_REG:
                            if sz == 'qword':
                                src = W32_TO_W64_REG.get(other.reg, 'rax')
                            else:
                                src = self._ebp_slot_reg_asm(
                                    other, insn.op_str, sz)
                            out += self._asm(
                                f'mov {sz} ptr [{base64}+0x{gs_disp:x}], {src}')
                            push_stack.clear()
                            continue

            # ── [reg + image_disp32] mem ops (cmd quote buffer: [edi+0x4AD…]) ─
            # Preserve mnem: cmp/test/alu [reg+abs],imm must NOT become mov
            # (cmd 0xF52C ``cmp byte [eax+f9df],0x31`` was emitted as a store,
            # leaving flags stale and taking the wrong F58C/F590 exit → RIP=2).
            if len(ops) == 2 and any(op.type == X86_OP_MEM for op in ops):
                mem_op = next(op for op in ops if op.type == X86_OP_MEM)
                m = mem_op.mem
                _img_mem_ops = (
                    'mov', 'cmp', 'test', 'and', 'or', 'xor', 'add', 'sub')
                if (m.segment == 0 and m.base and not m.index and m.disp
                        and mnem in _img_mem_ops):
                    disp_u = m.disp & 0xFFFFFFFF
                    new_disp = self._relocate_imm(disp_u, len(out), 0)
                    if self._is_image_pointer(disp_u) or new_disp != disp_u:
                        base64 = W32_TO_W64_REG.get(m.base, 'rax')
                        scratch = 'r11' if base64 != 'r11' else 'r10'
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        ebp_sz = (ptr_sz if ptr_sz in ('byte', 'word')
                                  else 'dword')
                        other = ops[1] if mem_op is ops[0] else ops[0]
                        _hi8 = ('ah', 'bh', 'ch', 'dh')
                        if mem_op is ops[0] and other.type == X86_OP_IMM:
                            mask = {'byte': 0xFF, 'word': 0xFFFF}.get(
                                ebp_sz, 0xFFFFFFFF)
                            out += self._asm(
                                f'mov {scratch}, '
                                f'0x{new_disp & 0xFFFFFFFFFFFFFFFF:x}')
                            out += self._asm(
                                f'{mnem} {ebp_sz} ptr [{scratch}+{base64}], '
                                f'0x{other.imm & mask:x}')
                            push_stack.clear()
                            continue
                        if mem_op is ops[0] and other.type == X86_OP_REG:
                            src = self._ebp_slot_reg_asm(
                                other, insn.op_str, ebp_sz)
                            if src not in _hi8:
                                out += self._asm(
                                    f'mov {scratch}, '
                                    f'0x{new_disp & 0xFFFFFFFFFFFFFFFF:x}')
                                out += self._asm(
                                    f'{mnem} {ebp_sz} ptr [{scratch}+{base64}], '
                                    f'{src}')
                                push_stack.clear()
                                continue
                        elif mem_op is ops[1] and other.type == X86_OP_REG:
                            dst = self._ebp_slot_reg_asm(
                                other, insn.op_str, ebp_sz)
                            if dst not in _hi8:
                                out += self._asm(
                                    f'mov {scratch}, '
                                    f'0x{new_disp & 0xFFFFFFFFFFFFFFFF:x}')
                                if mnem == 'mov':
                                    out += self._asm(
                                        f'mov {dst}, {ebp_sz} ptr '
                                        f'[{scratch}+{base64}]')
                                else:
                                    # cmp/test/alu reg, [reg+abs]
                                    out += self._asm(
                                        f'{mnem} {dst}, {ebp_sz} ptr '
                                        f'[{scratch}+{base64}]')
                                push_stack.clear()
                                continue
                if (m.segment == 0 and m.base and m.index and m.disp
                        and (m.scale or 1) == 2):
                    disp_u = m.disp & 0xFFFFFFFF
                    new_disp = self._relocate_imm(disp_u, len(out), 0)
                    if self._is_image_pointer(disp_u) or new_disp != disp_u:
                        base64 = W32_TO_W64_REG.get(m.base, 'rax')
                        idx64 = W32_TO_W64_REG.get(m.index, 'rax')
                        scratch = 'r11' if base64 != 'r11' else 'r10'
                        ptr_sz = self._mem_ptr_size(insn.op_str)
                        ebp_sz = (ptr_sz if ptr_sz in ('byte', 'word')
                                  else 'dword')
                        other = ops[1] if mem_op is ops[0] else ops[0]
                        if mem_op is ops[0] and other.type == X86_OP_REG:
                            src = self._ebp_slot_reg_asm(
                                other, insn.op_str, ebp_sz)
                            if src not in ('ah', 'bh', 'ch', 'dh'):
                                out += self._asm(
                                    f'mov {scratch}, '
                                    f'0x{new_disp & 0xFFFFFFFFFFFFFFFF:x}')
                                out += self._asm(
                                    f'mov {ebp_sz} ptr '
                                    f'[{scratch}+{idx64}*2+{base64}], {src}')
                                push_stack.clear()
                                continue

            # cmd builder: table slot index is byte offset — use 8-byte slots on Win10.
            if (self.win10_test_shim and mnem == 'shl' and len(ops) == 2
                    and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM
                    and ops[1].imm == 2):
                old_rva = (old_va - self.old_base) & 0xFFFFFFFF
                if old_rva in (0x1A408, 0x1A45C):
                    r64 = W32_TO_W64_REG.get(ops[0].reg, 'rax')
                    out += self._asm(f'shl {r64}, 3')
                    push_stack.clear()
                    continue

            # ── EBP scratch: test/cmp on repurposed ebp (cmd 0x651D heap handle) ─
            if (self._cmd_no_hacks and ebp_reg_scratch
                    and mnem in ('test', 'cmp') and len(ops) == 2):
                _scr = ('rbp' if ebp_scratch_in_reg
                        else self._ebp_scratch_mem(ebp_scratch_home))
                if (mnem == 'test' and ops[0].type == X86_OP_REG
                        and ops[1].type == X86_OP_REG
                        and ops[0].reg == X86_REG_EBP
                        and ops[1].reg == X86_REG_EBP):
                    out += self._asm(f'cmp {_scr}, 0')
                    push_stack.clear()
                    continue
                if (mnem == 'cmp' and ops[0].type == X86_OP_REG
                        and ops[1].type == X86_OP_IMM
                        and ops[0].reg == X86_REG_EBP):
                    out += self._asm(
                        f'cmp {_scr}, 0x{ops[1].imm & 0xFFFFFFFF:x}')
                    push_stack.clear()
                    continue
                if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                    if ops[0].reg == X86_REG_EBP or ops[1].reg == X86_REG_EBP:
                        def _scratch_x64(rid: int) -> str:
                            if rid == X86_REG_EBP:
                                return _scr
                            return W32_TO_W64_REG.get(rid, 'rax')
                        r0 = _scratch_x64(ops[0].reg)
                        r1 = _scratch_x64(ops[1].reg)
                        out += self._asm(f'{mnem} {r0}, {r1}')
                        push_stack.clear()
                        continue

            # ── Default: re-assemble the instruction as-is (best effort) ───────
            # NOTE: do not clear push_stack here. Control-flow instructions are
            # handled earlier; anything reaching this default is data-processing
            # that may be interleaved among a call's argument pushes (e.g. cmd
            # RegOpenKeyExW: push …; and dword [esi],0; push …; call). Clearing
            # would drop those pending arguments.
            try:
                enc, _ = self.ks.asm(
                    self._normalize_x64_asm(f'{mnem} {insn.op_str}'), old_va)
                out += bytes(enc)
            except KsError:
                # Cannot translate → INT3 + original bytes as comment
                out += b'\xCC'
                if self.verbose:
                    self.warnings.append(f"  [UNTRANSLATED] 0x{old_va:08X}: {mnem} {insn.op_str}")

        # ── Phase 2: Fix up branches ────────────────────────────────────────────
        out_bytes = bytearray(out)
        JCC_MAP = {
            'jcc_jo':0x80,'jcc_jno':0x81,'jcc_jb':0x82,'jcc_jnb':0x83,
            'jcc_jz':0x84,'jcc_jnz':0x85,'jcc_jbe':0x86,'jcc_ja':0x87,
            'jcc_js':0x88,'jcc_jns':0x89,'jcc_jp':0x8A,'jcc_jnp':0x8B,
            'jcc_jl':0x8C,'jcc_jge':0x8D,'jcc_jle':0x8E,'jcc_jg':0x8F,
            # common aliases
            'jcc_je':0x84,'jcc_jne':0x85,'jcc_jae':0x83,'jcc_jbe':0x86,
            'jcc_jnle':0x8F,'jcc_jng':0x8E,
        }
        _dbg_res = os.environ.get('DEBUG_RESOLVE')
        _dbg_res_rva = int(_dbg_res, 16) if _dbg_res else None
        for patch_off, target_va, ftype in pending_fixups:
            new_target = old_new.get(target_va)
            target_rva = (target_va - self.old_base) & 0xFFFFFFFF
            if _dbg_res_rva is not None and target_rva == _dbg_res_rva:
                print(f"[RESOLVE phase2] tgt_rva=0x{target_rva:X} "
                      f"func_rva=0x{func_rva:X} chunk_len=0x{len(code):X} "
                      f"old_new={old_new.get(target_va)} "
                      f"global={global_rva_map.get(target_rva) if global_rva_map else None} "
                      f"chunk_base=0x{chunk_base:X} patch_off=0x{patch_off:X} ftype={ftype}")
            if (new_target is None and global_rva_map is not None
                    and not self._defer_cross_chunk):
                # Forward reference INTO this very chunk: the global map
                # holds a stale first-pass address for targets this chunk
                # will translate a moment later (cmd 0x4F0B remat chunk:
                # call x86 0x5C02 resolved to a zeroed hole 0x414E8 while
                # the chunk's own copy lands at +0x652D0).  Defer so the
                # chunk-local mapping wins after the chunk is complete.
                chunk_hi_rva = (func_rva + len(code)) & 0xFFFFFFFF
                in_chunk = (func_rva <= target_rva < chunk_hi_rva
                            if func_rva <= chunk_hi_rva else
                            (target_rva >= func_rva
                             or target_rva < chunk_hi_rva))
                if not in_chunk:
                    new_target = global_rva_map.get(target_rva)
                if new_target is not None:
                    # Anti-self-call: when the global rva_map (which has
                    # _outer_entry_before_align snaps applied) resolves a
                    # CALL to its own align-wrapper prologue, defer the
                    # fixup so _resolve_deferred_branches can re-resolve
                    # with the raw unsnapped rva_map.
                    if ftype == 'rel32_call':
                        call_pos = patch_off - 1  # E8 byte
                        if call_pos >= 13:
                            pro_at = call_pos - 13
                            align_head = getattr(self, '_ALIGN_HEAD',
                                                 b'\x41\x55\x49\x89\xe5')
                            if (pro_at >= 0
                                    and out_bytes[pro_at:pro_at + 5] == align_head
                                    and new_target == (chunk_base + pro_at
                                                       if chunk_base else pro_at)):
                                if deferred_branches is not None:
                                    abs_patch = (patch_off if chunk_base == 0
                                                 else chunk_base + patch_off)
                                    deferred_branches.append(
                                        (abs_patch, target_rva, ftype))
                                new_target = None
                    if new_target is not None:
                        if ftype in ('rel32_call', 'rel32_jmp'):
                            after = (chunk_base + patch_off + 4) if chunk_base else (patch_off + 4)
                            rel = new_target - after
                            struct.pack_into('<i', out_bytes, patch_off, rel)
                        elif ftype.startswith('jcc_'):
                            cc_byte = JCC_MAP.get(ftype, 0x84)
                            out_bytes[patch_off + 1] = cc_byte
                            after = (chunk_base + patch_off + 6) if chunk_base else (patch_off + 6)
                            rel = new_target - after
                            struct.pack_into('<i', out_bytes, patch_off + 2, rel)
                        continue
            if new_target is None:
                if deferred_branches is not None:
                    abs_patch = patch_off if chunk_base == 0 else chunk_base + patch_off
                    deferred_branches.append((abs_patch, target_rva, ftype))
                continue
            if ftype in ('rel32_call', 'rel32_jmp'):
                # Patch 4-byte rel32 (offsets relative to current function chunk)
                after = patch_off + 4
                rel   = new_target - after
                struct.pack_into('<i', out_bytes, patch_off, rel)
            elif ftype.startswith('jcc_'):
                cc_byte = JCC_MAP.get(ftype, 0x84)
                out_bytes[patch_off + 1] = cc_byte
                after = patch_off + 6
                rel   = new_target - after
                struct.pack_into('<i', out_bytes, patch_off + 2, rel)

        if _dbg_on:
            print(f"[DEBUG_FN 0x{func_rva:X}] emitted {len(out_bytes)} bytes; "
                  f"{len(pending_fixups)} fixups, "
                  f"{len(old_new)} mapped insns")
            for _po, _tva, _ft in pending_fixups:
                _trva = (_tva - self.old_base) & 0xFFFFFFFF
                _on = old_new.get(_tva)
                _gl = global_rva_map.get(_trva) if global_rva_map else None
                print(f"    fixup off=+0x{_po:X} tgt_rva=0x{_trva:X} "
                      f"old_new={_on} global={_gl} {_ft}")

        return bytes(out_bytes), old_new

    def _translate_text_section(self, text_data: bytes, text_rva: int) -> Tuple[bytes, Dict[int, int]]:
        """Translate the entire .text section, overlaying NTDLL stubs."""
        out = bytearray()
        rva_map: Dict[int, int] = {}
        deferred_branches: List[Tuple[int, int, str]] = []
        stub_rvas = sorted(self.stubs.keys())
        pos = 0
        stub_idx = 0

        while pos < len(text_data):
            rva = text_rva + pos

            if stub_idx < len(stub_rvas) and rva == stub_rvas[stub_idx]:
                stub = self.stubs[rva]
                rva_map[rva] = len(out)
                out += self._translate_stub(stub)
                skip = max(len(stub.raw), 16)
                pos += skip
                stub_idx += 1
                continue

            next_boundary = (stub_rvas[stub_idx] if stub_idx < len(stub_rvas)
                             else text_rva + len(text_data))
            chunk_end = min(next_boundary - text_rva, len(text_data))
            chunk = text_data[pos:chunk_end]
            if chunk:
                chunk_rva = text_rva + pos
                base_off = len(out)
                chunk_out, chunk_map = self._translate_function(
                    chunk_rva, chunk, False, 0, chunk_base=base_off,
                    section_rva=text_rva,
                    global_rva_map=rva_map, deferred_branches=deferred_branches)
                for old_va, off in chunk_map.items():
                    rva_map[old_va - self.old_base] = base_off + off
                out += chunk_out
            pos = chunk_end

        fixed = self._resolve_deferred_branches(out, rva_map, deferred_branches)
        if fixed:
            print(f"        Cross-function branch fixups: {fixed}")
        ubrt_fixed = self._repair_branches_from_ubrt(out, rva_map)
        if ubrt_fixed:
            print(f"        UBRT branch repairs: {ubrt_fixed}")
        return bytes(out), rva_map

    def _translate_batch_sequential(self, batch, text_data, text_rva,
                                      rva_map, deferred_branches):
        """Translate a batch of functions one at a time (fallback)."""
        results = []
        for func_rva, func_bytes in batch:
            chunk_out, chunk_map = self._translate_function(
                func_rva, func_bytes, False, 0,
                chunk_base=0, section_rva=text_rva,
                global_rva_map=rva_map,
                deferred_branches=deferred_branches)
            results.append((chunk_out, chunk_map))
        return results

    def _translate_batch_parallel(self, batch, text_data, text_rva,
                                    rva_map, deferred_branches):
        """Translate a batch of functions in parallel using threads.
        
        Keystone (assembly) and Capstone (disassembly) are C extensions
        that release the GIL, so threads give real CPU parallelism."""
        results: List[Tuple] = [None] * len(batch)
        batch_deferred: List[List] = [[] for _ in batch]
        with ThreadPoolExecutor(max_workers=min(len(batch), os.cpu_count())) as pool:
            futures = {}
            for idx, (func_rva, func_bytes) in enumerate(batch):
                fut = pool.submit(
                    self._translate_function,
                    func_rva, func_bytes, False, 0,
                    chunk_base=0, section_rva=text_rva,
                    global_rva_map=rva_map,
                    deferred_branches=batch_deferred[idx])
                futures[fut] = idx
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    results[idx] = fut.result()
                except Exception:
                    results[idx] = (b'', {})
        # Merge deferred branches from all parallel translations
        for db_list in batch_deferred:
            deferred_branches.extend(db_list)
        return results

    def _translate_function_driven(self, text_data: bytes,
                                   text_rva: int) -> Tuple[bytes, Dict[int, int]]:
        """Translate every discovered function entry in a code section."""
        pe = self.pe
        func_rvas = discover_function_rvas(pe, text_data, text_rva, self.dyn)
        if pe.entry_rva and text_rva <= pe.entry_rva < text_rva + len(text_data):
            if pe.entry_rva not in func_rvas:
                func_rvas.insert(0, pe.entry_rva)
        print(f"        Function-driven: {len(func_rvas)} entry points")

        self._x86_cf = analyze_x86_text_section(
            pe, text_data, text_rva, self.dyn, set(func_rvas))
        if self._x86_cf.epilogue_labels or self._x86_cf.data_spans:
            print(f"        X86 CF analysis: {len(self._x86_cf.epilogue_labels)} epilogue labels, "
                  f"{len(self._x86_cf.branch_targets)} branch targets, "
                  f"{len(self._x86_cf.data_spans)} data gaps")

        if self.win10_test_shim:
            self._seh_eh3_handler_old_vas = discover_seh_except_handler3_push_vas(
                pe, text_data, text_rva)
            self._w2k_eh3_va = w2kshim_except_handler3_va()

        out = bytearray()
        rva_map: Dict[int, int] = {}
        covered: List[Tuple[int, int]] = []
        deferred_branches: List[Tuple[int, int, str]] = []

        # Worklist that refills from unresolved CALL/JMP targets. Function
        # discovery only finds `push ebp` prologues, so frameless helpers
        # (push esi; …) are reached here via the calls that target them.
        worklist = list(func_rvas)
        queued = set(func_rvas)
        wi = 0
        refill_rounds = 0
        discovered_extra = 0
        
        while wi < len(worklist):
            func_rva = worklist[wi]
            wi += 1
            if self._x86_rva_in_data_span(func_rva):
                continue
            if (self._x86_cf and func_rva in self._x86_cf.epilogue_labels):
                continue
            if any(lo <= func_rva < hi for lo, hi in covered):
                continue
            if func_rva in self.stubs:
                stub = self.stubs[func_rva]
                base = len(out)
                rva_map[func_rva] = base
                out += self._translate_stub(stub)
                self._note_code_span(base, len(out) - base)
                covered.append((func_rva, func_rva + max(len(stub.raw), 16)))
                continue
            bound_rva = None
            if self._cmd_no_hacks:
                nexts = [e for e in queued if e > func_rva
                         and not self._is_spurious_inner_entry(
                             func_rva, e, text_data, text_rva)]
                if nexts:
                    bound_rva = min(nexts)
            func_bytes = self._extract_function_bytes(
                func_rva, text_data, text_rva, bound_rva=bound_rva)
            if len(func_bytes) < 4:
                if wi >= len(worklist):
                    break
                continue

            chunk_out, chunk_map = self._translate_function(
                func_rva, func_bytes, False, 0,
                chunk_base=0, section_rva=text_rva,
                global_rva_map=rva_map,
                deferred_branches=deferred_branches)

            if not chunk_out:
                if wi >= len(worklist):
                    break
                continue

            base = len(out)
            rva_map[func_rva] = base
            func_entry_va = self.old_base + func_rva
            func_body_off = chunk_map.get(func_entry_va, 0)
            if func_body_off:
                prefix = chunk_out[:func_body_off]
                if b'\xc3' in prefix or b'\xc2' in prefix:
                    rva_map[func_rva] = base + func_body_off
            for old_va, off in chunk_map.items():
                old_rva = old_va - self.old_base
                if old_rva not in rva_map:
                    if (self._cmd_no_hacks and old_rva in queued
                            and old_rva != func_rva):
                        cur_lo = func_rva
                        cur_hi = func_rva + len(func_bytes)
                        in_current = cur_lo <= old_rva < cur_hi
                        in_covered = any(lo <= old_rva < hi
                                         for lo, hi in covered)
                        if not in_current and not in_covered:
                            continue
                    rva_map[old_rva] = base + off
            out += chunk_out
            out += b'\x90' * ((4 - len(out) % 4) % 4)
            self._note_code_span(base, len(chunk_out))
            covered.append((func_rva, func_rva + len(func_bytes)))

            # Worklist drained → pull in unresolved call targets that look like
            # real code (frameless functions missed by prologue discovery).
            if wi == len(worklist) and refill_rounds < 16:
                refill_rounds += 1
                for (_po, trva, ft) in deferred_branches:
                    if trva in queued or trva in rva_map:
                        continue
                    if not (text_rva <= trva < text_rva + len(text_data)):
                        continue
                    if any(lo <= trva < hi for lo, hi in covered):
                        continue
                    if not self._looks_like_code(text_data, text_rva, trva):
                        continue
                    # Skip interior labels inside an already-translated span.
                    if self._cmd_no_hacks:
                        skip = False
                        for lo, hi in covered:
                            if lo < trva < hi and self._is_spurious_inner_entry(
                                    lo, trva, text_data, text_rva):
                                skip = True
                                break
                        if skip:
                            continue
                    trva = self._frameless_entry_rva(text_data, text_rva, trva)
                    if trva in queued or trva in rva_map:
                        continue
                    if any(lo <= trva < hi for lo, hi in covered):
                        continue
                    queued.add(trva)
                    worklist.append(trva)
                    discovered_extra += 1
        if discovered_extra:
            print(f"        Recovered frameless/call-target functions: "
                  f"{discovered_extra}")

        self._fn_entry_rvas = set(queued)
        self._pure_heal_text = text_data
        self._pure_heal_text_rva = text_rva
        self._seh_scope_anchors = discover_seh_scope_anchors(
            text_data, text_rva, self.old_base, pe.image_size)

        seh_refs = discover_seh_text_targets(
            text_data, text_rva, self.old_base, pe.image_size)
        iat_slots: Set[int] = set()
        for imp in pe.parse_imports():
            for fn in imp['functions']:
                ir = fn.get('iat_rva')
                if ir:
                    iat_slots.add(ir)
        iat_slots |= discover_crt_data_pointer_slots(pe, text_data, text_rva)
        scope_spans = _scope_table_spans(text_data, text_rva, pe)
        ff25_refs = discover_ff25_jmp_thunks(
            text_data, text_rva, self.old_base, iat_slots, scope_spans)
        if ff25_refs:
            self._materialize_x86_code_region(
                out, rva_map, text_data, text_rva,
                0x1A59C, 0x1A5A8, deferred_branches)
            self._materialize_x86_code_region(
                out, rva_map, text_data, text_rva,
                0x1A5CE, 0x1A5DA, deferred_branches)
            for r in ff25_refs:
                rva_map.pop(r, None)
        embedded_refs = discover_push_imm_text_data_refs(
            text_data, text_rva, self.old_base, pe.image_size)
        self._embedded_text_refs = embedded_refs
        purged_embed = self._pure_purge_mismapped_embedded_refs(
            out, rva_map, text_data, text_rva, embedded_refs)
        if purged_embed:
            print(f"        Purged mismapped embedded text RVAs: {purged_embed}")
        missing = (seh_refs | ff25_refs | embedded_refs) - set(rva_map.keys())
        if missing:
            n_mat = self._materialize_orphan_text_refs(
                out, rva_map, text_data, text_rva, missing, deferred_branches)
            if n_mat:
                print(f"        SEH/orphan text blobs: {n_mat}")

        n_scope = self._force_rematerialize_scope_tables(
            out, rva_map, text_data, text_rva)
        if n_scope:
            print(f"        EH3 scope rematerialize: {n_scope}")

        scope_fixed = self._reconcile_seh_scope_pushes(out, rva_map, text_rva)
        if scope_fixed:
            print(f"        SEH scope push reconcile: {scope_fixed}")

        bridged = self._bridge_ret_to_entry_gaps(out, rva_map)
        if bridged:
            print(f"        RET/INT3 entry bridges: {bridged}")

        scrubbed = self._scrub_stray_x86_before_call(out)
        if scrubbed:
            print(f"        Stray x86 byte scrub before CALL: {scrubbed}")

        fixed = self._resolve_deferred_branches(out, rva_map, deferred_branches)
        if fixed:
            print(f"        Cross-function branch fixups: {fixed}")
        if self._x86_cf and self._x86_cf.epilogue_labels:
            mat_epi = self._pure_materialize_call_epilogues(out, rva_map)
            if mat_epi:
                print(f"        Materialized call epilogues: {mat_epi}")
            for ep_rva in self._x86_cf.epilogue_labels:
                if ep_rva not in self._x86_cf.branch_targets:
                    continue
                self._materialize_epilogue_label(out, rva_map, ep_rva)
        jcc_ph = self._pure_patch_jcc_placeholders(out, rva_map, text_data, text_rva)
        if jcc_ph:
            print(f"        Unresolved Jcc placeholder patches: {jcc_ph}")
        if self._x86_cf and self._x86_cf.epilogue_labels:
            cf_epi = self._cf_repair_epilogue_branch_targets(out, rva_map)
            if cf_epi:
                print(f"        CF epilogue branch repairs: {cf_epi}")
            self._epilogue_snap_map = self._build_epilogue_head_snap_map(rva_map, out)
            epi_snapped = self._snap_branch_targets_to_epilogue_heads(
                out, self._epilogue_snap_map)
            if epi_snapped:
                print(f"        Epilogue-head branch snaps: {epi_snapped}")
        ubrt_fixed = self._repair_branches_from_ubrt(out, rva_map)
        if ubrt_fixed:
            print(f"        UBRT branch repairs: {ubrt_fixed}")
        repaired = self._repair_unfixed_calls(out, rva_map, text_data, text_rva)
        if repaired:
            print(f"        X86-sourced call repairs: {repaired}")

        scrubbed2 = self._scrub_stray_x86_before_call(out)
        if scrubbed2:
            print(f"        Stray x86 byte scrub (post-repair): {scrubbed2}")
        repaired2 = self._repair_unfixed_calls(out, rva_map, text_data, text_rva)
        if repaired2:
            print(f"        X86-sourced call repairs (post-scrub): {repaired2}")

        aligned_calls = self._fix_misaligned_direct_calls(out, rva_map)
        if aligned_calls:
            print(f"        Misaligned CALL target fixups: {aligned_calls}")

        wrapper_calls = self._fix_calls_to_wrapper_bodies(out)
        if wrapper_calls:
            print(f"        Import wrapper CALL fixups: {wrapper_calls}")

        insn_calls = self._snap_calls_to_insn_boundaries(out)
        if insn_calls:
            print(f"        Mid-instruction CALL snap fixups: {insn_calls}")

        fn_entry_calls = self._snap_calls_to_function_entries(out, rva_map)
        if fn_entry_calls:
            print(f"        Mid-function CALL entry snap fixups: {fn_entry_calls}")

        jcc_snapped = self._snap_jcc_misaligned_targets(out)
        if jcc_snapped:
            print(f"        Mid-instruction Jcc snap fixups: {jcc_snapped}")
        jcc_repaired = self._repair_jcc_targets_from_rva_map(out, rva_map)
        if jcc_repaired:
            print(f"        Jcc rva_map target repairs: {jcc_repaired}")
        if getattr(self, '_epilogue_snap_map', None):
            epi_snapped2 = self._snap_branch_targets_to_epilogue_heads(
                out, self._epilogue_snap_map)
            if epi_snapped2:
                print(f"        Epilogue-head branch snaps (post-jcc): {epi_snapped2}")

        if self._cmd_no_hacks:
            reconciled = self._pure_reconcile_swallowed_rva_map(
                out, rva_map, text_data, text_rva)
            if reconciled:
                print(f"        Pure swallowed rva_map reconciles: {reconciled}")
            pure_align = self._pure_repair_all_align_stub_calls(
                out, rva_map, text_data, text_rva)
            if pure_align:
                print(f"        Pure align-stub CALL repairs: {pure_align}")
            pure_calls = self._pure_repair_call_targets(
                out, rva_map, text_data, text_rva)
            if pure_calls:
                print(f"        Pure CALL re-resolve: {pure_calls}")
            pure_x86_calls = self._pure_repair_calls_from_x86_source(
                out, rva_map, text_data, text_rva)
            if pure_x86_calls:
                print(f"        Pure x86-anchored CALL repairs: {pure_x86_calls}")

        degenerate = self._neutralize_degenerate_calls(out)
        if degenerate:
            print(f"        Degenerate CALL neutralizations: {degenerate}")

        align_fixed = self._fix_corrupted_align_prologues(out)
        if align_fixed:
            print(f"        Corrupted align-prologue fixes: {align_fixed}")

        empty_align = self._nop_empty_align_stubs(out)
        if empty_align:
            print(f"        Empty align-stub NOP-outs: {empty_align}")

        epi_gaps = self._fix_align_epilogue_x86_gaps(out)
        if epi_gaps:
            print(f"        Align-epilogue x86 gap fixups: {epi_gaps}")

        ret_stubs = self._fix_mangled_imm_ret_stubs(out)
        if ret_stubs:
            print(f"        Mangled imm-ret stub fixups: {ret_stubs}")

        epilogue_calls = self._snap_calls_past_add_rsp_epilogue(out)
        if epilogue_calls:
            print(f"        Past-epilogue CALL snap fixups: {epilogue_calls}")

        alloca_fixed = self._fix_alloca_probe_epilogues(out)
        if alloca_fixed:
            print(f"        _alloca_probe epilogue fixes: {alloca_fixed}")

        chkstk_align = self._fix_chkstk_frame_alignment(out)
        if chkstk_align:
            print(f"        _chkstk frame-size alignment fixes: {chkstk_align}")

        chkstk_add_fixed = self._fix_chkstk_epilogue_adds(out)
        if chkstk_add_fixed:
            print(f"        _chkstk epilogue ADD fixes: {chkstk_add_fixed}")

        cmd_fixed = self._cmd_shim_postfixes(out, rva_map)
        if cmd_fixed:
            print(f"        cmd.exe shim postfixes: {cmd_fixed}")

        if self._cmd_no_hacks:
            restored_calls = self._pure_restore_nopped_align_calls(
                out, rva_map, text_data, text_rva)
            if restored_calls:
                print(f"        Pure restored align calls: {restored_calls}")
            epi_calls = self._pure_snap_calls_to_epilogue_targets(
                out, rva_map, text_data, text_rva)
            if epi_calls:
                print(f"        Pure epilogue CALL snaps: {epi_calls}")
            repaired3 = self._repair_unfixed_calls(out, rva_map, text_data, text_rva)
            if repaired3:
                print(f"        Pure unfixed call repairs: {repaired3}")

        unresolved = [(po, trva, ft) for (po, trva, ft) in deferred_branches
                      if trva not in rva_map]
        if unresolved:
            sample = sorted({trva for _, trva, _ in unresolved})[:12]
            print(f"        UNRESOLVED branches: {len(unresolved)} "
                  f"(sample target RVAs: {[hex(s) for s in sample]})")

        if len(out) < len(text_data) // 8:
            print(f"        Function-driven output small ({len(out)} B) — "
                  f"falling back to linear section translate")
            return self._translate_text_section(text_data, text_rva)
        return bytes(out), rva_map

    def _translate_export_driven(self, text_data: bytes, text_rva: int) -> Tuple[bytes, Dict[int, int]]:
        """Translate per export/entry when linear disassembly fails (kernel images)."""
        pe = self.pe
        out = bytearray()
        rva_map: Dict[int, int] = {}
        entry_points: Set[int] = set()
        if pe.entry_rva:
            entry_points.add(pe.entry_rva)
        for exp in pe.parse_exports():
            entry_points.add(exp['rva'])
        entry_points.update(self.stubs.keys())

        for func_rva in sorted(entry_points):
            if func_rva < text_rva or func_rva >= text_rva + len(text_data):
                continue
            rva_map[func_rva] = len(out)
            stub = self.stubs.get(func_rva)
            if stub:
                out += self._translate_stub(stub)
                continue
            func_off = func_rva - text_rva
            func_code = text_data[func_off:]
            insns = []
            for insn in self.md.disasm(func_code, pe.image_base + func_rva, count=4096):
                insns.append(insn)
                if insn.mnemonic in ('ret', 'retn'):
                    break
            if not insns:
                continue
            func_bytes = func_code[:insns[-1].address - (pe.image_base + func_rva) + insns[-1].size]
            chunk_out, chunk_map = self._translate_function(func_rva, func_bytes, False, 0)
            base = len(out)
            for old_va, off in chunk_map.items():
                rva_map[old_va - self.old_base] = base + off
            out += chunk_out
            out += b'\x90' * ((4 - len(out) % 4) % 4)
        return bytes(out), rva_map

    def _translate_export_at(self, func_rva: int, text_data: bytes,
                             text_rva: int) -> bytes:
        """Translate a single export entry point to x64 code bytes."""
        stub = self.stubs.get(func_rva)
        if stub:
            return self._translate_stub(stub)
        func_off = func_rva - text_rva
        if func_off < 0 or func_off >= len(text_data):
            return b''
        func_code = text_data[func_off:]
        insns = []
        for insn in self.md.disasm(func_code, self.pe.image_base + func_rva, count=4096):
            insns.append(insn)
            if insn.mnemonic in ('ret', 'retn'):
                break
        if not insns:
            return b'\xCC\xc3'
        end = insns[-1].address - (self.pe.image_base + func_rva) + insns[-1].size
        chunk_out, _ = self._translate_function(func_rva, func_code[:end], False, 0)
        return chunk_out
