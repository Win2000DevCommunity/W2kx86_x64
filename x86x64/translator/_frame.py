"""Stack frames and argument marshalling between the two ABIs.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class FrameMixin:
    """See the module docstring."""

    def _is_zero_arg_iat(self, iat_va: int) -> bool:
        """Imports whose x86 thunks take no stack args (pushes belong to next call)."""
        name = self._iat_name_at(iat_va)
        return name in {
            'GetProcessHeap', 'GetCurrentProcess', 'GetCurrentThread',
            'GetCommandLineA', 'GetCommandLineW', 'GetACP', 'GetOEMCP',
            'GetVersion', 'GetTickCount', 'GetLastError',
            'GetConsoleOutputCP', 'GetConsoleCP', 'GetStdHandle',
        }

    def _is_cdecl_shared_stack_iat(self, iat_va: int) -> bool:
        """1-arg cdecl whose extra pushes feed the next ``pop ecx; push eax; call``.

        Classic MSVC pattern (cmd ReadFile path)::

            push &n; push size; push buf; push fd
            call _get_osfhandle   ; uses only fd; leaves buf/size/&n on stack
            pop ecx               ; drop fd slot
            push eax              ; HANDLE
            call ReadFile_wrapper ; (handle, buf, size, &n)

        Without this, the translator packs all four pushes into the first call
        and the follow-on wrapper sees only EAX (cmd echo → longjmp → AV).
        """
        name = self._iat_name_at(iat_va)
        return name in {
            '_get_osfhandle', 'get_osfhandle',
        }

    @staticmethod
    def _lookahead_pop_ecx_push_eax_call(insn_idx: int, insns) -> bool:
        """True when the next three insns are ``pop ecx; push eax; call``."""
        if insn_idx + 3 >= len(insns):
            return False
        pop_ecx, push_eax, call2 = insns[insn_idx + 1:insn_idx + 4]
        if (pop_ecx.mnemonic != 'pop' or not pop_ecx.operands
                or pop_ecx.operands[0].type != X86_OP_REG
                or pop_ecx.operands[0].reg != X86_REG_ECX):
            return False
        if (push_eax.mnemonic != 'push' or not push_eax.operands
                or push_eax.operands[0].type != X86_OP_REG
                or push_eax.operands[0].reg != X86_REG_EAX):
            return False
        return call2.mnemonic == 'call' and bool(call2.operands)

    def _call_arg_regs(self, cc_mode: str) -> List[str]:
        """Win64 registers for push-derived CALL args (skip RCX on thiscall)."""
        if cc_mode == 'thiscall':
            return list(WIN64_ARG_REG_NAMES[1:4])
        return list(WIN64_ARG_REG_NAMES[:4])

    def _dword_arg_reg(self, reg: str) -> str:
        """Keystone needs 32-bit reg names for dword ptr loads into Win64 arg regs."""
        return {'rcx': 'ecx', 'rdx': 'edx', 'r8': 'r8d', 'r9': 'r9d',
                'rax': 'eax', 'rbx': 'ebx', 'rsi': 'esi', 'rdi': 'edi'}.get(
                    reg, 'eax')

    def _homed_arg_is_pointer(self, disp: int) -> bool:
        """Homed stdcall args that hold pointers (or pointer-sized values on x64)."""
        if self._cmd_no_hacks:
            if disp >= 8 and (disp - 8) % 4 == 0 and disp <= 0x28:
                return True
        if not self.win10_test_shim:
            return False
        # [EBP+8] arg1 / [EBP+0x18] arg2 in cmd's parse→builder caller (0x1A16D).
        return disp in (8, 0x18)

    def _entry_for_x86_target(self, out: bytearray, x86_tgt_rva: int,
                              rva_map: Dict[int, int]) -> Optional[int]:
        """Resolve x86 call target RVA to a snap-worthy shim function entry."""
        located = self._locate_shim_entry_for_x86_fn(out, x86_tgt_rva, rva_map)
        if located is not None:
            return located
        if x86_tgt_rva in rva_map:
            exact = rva_map[x86_tgt_rva]
            if (0 <= exact < len(out)
                    and self._offset_is_mapped_entry(out, exact)):
                return exact
        mapped = self._shim_offset_for_x86_rva(x86_tgt_rva, rva_map)
        if mapped is None or mapped < 0 or mapped >= len(out):
            return None
        if self._offset_is_mapped_entry(out, mapped):
            return mapped
        entry = self._find_enclosing_function_entry(out, mapped, rva_map)
        if entry is not None and self._entry_snapworthy(out, entry, rva_map):
            return entry
        return None

    def _ebp_to_rbp_home(self, old_va: int, disp: int) -> Optional[int]:
        """Map x86 [EBP+disp] to x64 [RBP+off], with cmd-builder local fixes."""
        if (disp == 0xC and self._cmd_builder_ebp_m4_is_ptr(old_va)):
            rva = (old_va - self.old_base) & 0xFFFFFFFF
            if rva >= 0x1A36B:
                # After 0x1A36B, [EBP+0xC] is repurposed as the quote flag byte.
                return 0x38
            # Before that it is incoming arg2 (pointer) — keep [RBP+0x18].
            return 0x18
        return ebp_disp_to_rbp_home(disp)

    def _ebp_scratch_mem(self, home: int = -0x20) -> str:
        if home >= 0:
            return f'qword ptr [rbp+0x{home:x}]'
        return f'qword ptr [rbp{home:+d}]'

    def _x64_call_target_reg(self, x86_reg_id: int,
                              iat_fn_holder: Dict[int, str]) -> str:
        if x86_reg_id in iat_fn_holder:
            return iat_fn_holder[x86_reg_id]
        return W32_TO_W64_REG.get(x86_reg_id, 'rax')

    def _reg_holds_zero_arg_iat(self, x86_reg_id: int,
                                iat_fn_slot: Dict[int, int]) -> bool:
        """True when *x86_reg_id* still holds a 0-arg import loaded from the IAT.

        Classic MSVC heap idiom (cmd 0x9FAD)::

            mov esi, [GetProcessHeap]
            mov ebp, size
            push ebp / push flags
            call esi                 ; 0-arg — pushes must survive
            push eax
            call HeapAlloc           ; (heap, flags, size)
        """
        slot = iat_fn_slot.get(x86_reg_id)
        if slot is None:
            return False
        return self._is_zero_arg_iat(slot)

    @staticmethod
    def _pick_cdecl_pop_ecx_rdx_arg(
            arg0: Optional[Tuple[str, int]],
            arg1: Optional[Tuple[str, int]],
            old_base: int, image_size: int) -> Optional[Tuple[str, int]]:
        """``pop ecx; push eax; call`` → RDX is mode (arg0) or &global (arg1)."""
        if arg1 and arg1[0] == 'imm':
            imm = arg1[1] & 0xFFFFFFFF
            if old_base <= imm < old_base + image_size:
                return arg1
        return arg0

    def _ebp_slot_reg_asm(self, other, op_str: str, ebp_sz: str) -> str:
        if ebp_sz == 'word':
            return self._word_reg_asm_for_op(other, op_str)
        if ebp_sz == 'byte':
            return self._reg_asm_for_op(other, op_str)
        return W32_REG_ASM.get(other.reg, 'eax')

    def _push_reg_is_pending_call_arg(self, insn_idx: int, insns) -> bool:
        """push reg; …; push …; call — reg is a cdecl arg, not callee-save.

        cmd builder: push ebx; …; push eax; push edi; call wcsncpy uses ebx as
        the count arg; add esp,0xc cleans the stack so there is no pop ebx before
        the epilogue pop ebx — _lookahead_matching_pop would misclassify it.

        Requires an *inner* push before the call so prologue
        ``push ebx; …; call`` (no args from ebx) stays a callee-save.  Bare
        ``push edi; call`` of an *already-saved* register is handled separately
        via ``callee_save_stack`` membership in the push translator.

        Zero-arg callees (``push ebx/esi/edi; call GetConsoleOutputCP``) must
        NOT count as pending args — the inner pushes are prologue saves that
        would otherwise survive the 0-arg IAT path and poison the next call.
        """
        saw_inner_push = False
        for j in range(insn_idx + 1, min(insn_idx + 16, len(insns))):
            nx = insns[j]
            nm = nx.mnemonic
            if nm == 'push':
                saw_inner_push = True
            elif nm == 'call':
                if not saw_inner_push:
                    return False
                if nx.operands:
                    cop = nx.operands[0]
                    if (cop.type == X86_OP_MEM and cop.mem.base == 0
                            and cop.mem.index == 0):
                        if self._is_zero_arg_iat(cop.mem.disp):
                            return False
                    elif cop.type == X86_OP_IMM:
                        old_base = int(getattr(self, 'old_base', 0) or 0)
                        ar = self._x86_stdcall_argc_from_ret(
                            (cop.imm - old_base) & 0xFFFFFFFF)
                        if ar == 0:
                            return False
                return True
            elif nm in ('ret', 'retn', 'leave'):
                return False
            elif nm == 'pop' and nx.operands and nx.operands[0].type == X86_OP_REG:
                return False
        return False

    def _x86_stdcall_argc_from_ret(self, target_rva: int) -> Optional[int]:
        """Return stdcall arg count from the callee's ``ret imm16``, if found.

        Used to peel leading callee-save pushes off a deferred push_stack when
        the call only consumes N args (cmd ``push edi; push ebx; push size;
        call malloc_wrapper`` / ``ret 4``).
        """
        pe = getattr(self, 'pe', None)
        if pe is None:
            return None
        text = getattr(self, '_pure_heal_text', None)
        text_rva = int(getattr(self, '_pure_heal_text_rva', 0) or 0)
        if not text or not text_rva:
            sec = None
            if hasattr(pe, 'section_for_rva'):
                sec = pe.section_for_rva(target_rva)
            if not sec:
                return None
            text = pe.get_section_data(sec)
            text_rva = sec['vaddr'] if isinstance(sec, dict) else sec.get('vaddr', 0)
        off = target_rva - text_rva
        if off < 0 or off >= len(text):
            return None
        # 0x100 missed cmd 0x640e ``ret 4`` at +0x100; keep headroom for
        # mid-sized helpers without walking into unrelated neighbours forever.
        end = min(len(text), off + 0x280)
        if HAS_CAPSTONE:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = True
            try:
                seen_bare = False
                for insn in md.disasm(bytes(text[off:end]), pe.image_base + target_rva):
                    if insn.mnemonic in ('ret', 'retn'):
                        if insn.operands:
                            imm = int(insn.operands[0].imm) & 0xFFFF
                            if imm % 4 == 0 and imm <= 64:
                                return imm // 4
                            return None
                        # Bare ``ret``: keep scanning briefly for a later
                        # ``ret imm16`` on an early-fail layout, but stop at
                        # the next function's prologue — otherwise a neighbour
                        # ``ret 0x10`` (cmd B1E6 after 0-arg B186) inflates
                        # argc and turns ``push edi; call B186`` into a fake
                        # stdcall arg (B00C → RSI=0 → AV on ``test [esi]``).
                        seen_bare = True
                        continue
                    if seen_bare:
                        ops = insn.operands or []
                        if (insn.mnemonic == 'push' and ops
                                and ops[0].type == X86_OP_REG
                                and ops[0].reg in (
                                    X86_REG_EBP, X86_REG_EBX,
                                    X86_REG_ESI, X86_REG_EDI)):
                            return 0
                        if (insn.mnemonic == 'mov' and len(ops) == 2
                                and ops[0].type == X86_OP_REG
                                and ops[0].reg == X86_REG_EBP
                                and ops[1].type == X86_OP_REG
                                and ops[1].reg == X86_REG_ESP):
                            return 0
                    # Do NOT stop at internal ``jmp`` — cmd 0x1039a has
                    # ``jmp shared; …; ret 4`` and stopping early made argc=0,
                    # which peeled the sole ``push edi`` arg into a hardware
                    # push (path AV via stale RCX).
                if seen_bare:
                    return 0
                # Capstone saw no ret in-window — do NOT fall through to a
                # raw C2/C3 byte scan: immediates inside ``mov``/displacements
                # false-match (cmd 0x640e has ``C3`` noise before real
                # ``ret 4``) and force argc=0, turning ``push edi; call`` into
                # a callee-save (GetEnvironmentVariableW → RCX garbage).
                return None
            except CsError:
                pass
        i = off
        while i < end - 1:
            b = text[i]
            if b == 0xC2 and i + 3 <= len(text):
                imm = struct.unpack_from('<H', text, i + 1)[0]
                if imm % 4 == 0 and imm <= 64:
                    return imm // 4
            i += 1
        return None

    @staticmethod
    def _push_reg_ebp_call_is_callee_save(insn_idx: int, insns) -> bool:
        """True for ``push reg; push ebp; call`` with no further arg pushes.

        Distinguishes callee-save + one stdcall arg (cmd ``0x6521``
        ``push esi; push ebp; call``) from multi-arg sequences
        (``push ebx; push ebp; push [CP]; call MultiByteToWideChar``).
        """
        if insn_idx + 2 >= len(insns):
            return False
        n1 = insns[insn_idx + 1]
        if not (n1.mnemonic == 'push' and n1.operands
                and n1.operands[0].type == X86_OP_REG
                and n1.operands[0].reg == X86_REG_EBP):
            return False
        for j in range(insn_idx + 2, min(insn_idx + 10, len(insns))):
            nx = insns[j]
            if nx.mnemonic == 'push':
                return False
            if nx.mnemonic == 'call':
                return True
            if nx.mnemonic in ('ret', 'retn', 'leave', 'pop'):
                return False
        return False

    @staticmethod
    def _find_recent_ebp_lea(reg_id: int, insn_idx: int, insns, max_back: int = 5) -> Optional[int]:
        """lea r,[ebp±N] within a few insns before push r (may have stores in between)."""
        for j in range(insn_idx - 1, max(insn_idx - max_back - 1, -1), -1):
            nx = insns[j]
            if nx.mnemonic == 'lea' and len(nx.operands) == 2:
                op0, op1 = nx.operands
                if (op0.type == X86_OP_REG and op0.reg == reg_id
                        and op1.type == X86_OP_MEM
                        and op1.mem.base == X86_REG_EBP):
                    disp = op1.mem.disp
                    if disp > 0x7FFFFFFF:
                        disp -= 0x100000000
                    return disp
            if nx.mnemonic == 'mov' and len(nx.operands) == 2:
                if (nx.operands[0].type == X86_OP_REG
                        and nx.operands[0].reg == reg_id):
                    break
        return None

    @staticmethod
    def _push_ebp_before_call_is_frame_save(insn_idx: int, insns) -> bool:
        """push ebp; call f; mov ebp, esp — frame save, not a call argument.

        Do NOT treat ``mov ebp, eax`` (heap-scratch after GetProcessHeap) as
        frame setup — that leaves ``frame_rbp_saved`` set without
        ``mov rbp,rsp``, so later scratch stores hit ``[rbp-0x20]`` through
        the caller's frame (cmd ``0x6511``).
        """
        if insn_idx + 1 >= len(insns):
            return False
        if insns[insn_idx + 1].mnemonic != 'call':
            return False
        j = insn_idx + 2
        while j < min(insn_idx + 8, len(insns)):
            nx = insns[j]
            if nx.mnemonic == 'pop':
                j += 1
                continue
            if (nx.mnemonic == 'mov' and len(nx.operands) == 2
                    and nx.operands[0].type == X86_OP_REG
                    and nx.operands[0].reg == X86_REG_EBP
                    and nx.operands[1].type == X86_OP_REG
                    and nx.operands[1].reg == X86_REG_ESP):
                return True
            break
        return False

    @staticmethod
    def _mov_ebp_is_heap_scratch(insn_idx: int, insns) -> bool:
        """``mov ebp,reg`` reuses the frame reg as a temp (cmd 0x6519 GetProcessHeap)."""
        if insn_idx < 0 or insn_idx >= len(insns):
            return False
        ins = insns[insn_idx]
        if not (ins.mnemonic == 'mov' and len(ins.operands) == 2
                and ins.operands[0].type == X86_OP_REG
                and ins.operands[0].reg == X86_REG_EBP
                and ins.operands[1].type in (X86_OP_REG, X86_OP_IMM)):
            return False
        if (ins.operands[1].type == X86_OP_REG
                and ins.operands[1].reg == X86_REG_ESP):
            return False
        for j in range(insn_idx + 1, min(insn_idx + 16, len(insns))):
            nx = insns[j]
            if nx.mnemonic == 'test' and len(nx.operands) == 2:
                o0, o1 = nx.operands
                if (o0.type == X86_OP_REG and o1.type == X86_OP_REG
                        and o0.reg == X86_REG_EBP and o1.reg == X86_REG_EBP):
                    return True
            if (nx.mnemonic == 'push' and nx.operands
                    and nx.operands[0].type == X86_OP_REG
                    and nx.operands[0].reg == X86_REG_EBP):
                for k in range(j + 1, min(j + 3, len(insns))):
                    if insns[k].mnemonic == 'call':
                        return True
                break
            if nx.mnemonic in ('leave', 'ret', 'retn', 'pop'):
                if nx.mnemonic == 'pop' and nx.operands:
                    if nx.operands[0].type == X86_OP_REG:
                        if nx.operands[0].reg == X86_REG_EBP:
                            break
                elif nx.mnemonic in ('leave', 'ret', 'retn'):
                    break
        return False

    @staticmethod
    def _push_ebp_is_stdcall_arg(insn_idx: int, insns,
                                 frame_rbp_saved: bool,
                                 callee_save_stack: list) -> bool:
        """push ebp as a CALL argument (cmd 0x9FB8/0x9FC5), not a frame spill."""
        if insn_idx <= 0:
            return False
        prev = insns[insn_idx - 1]
        if (prev.mnemonic == 'mov' and len(prev.operands) == 2
                and prev.operands[0].type == X86_OP_REG
                and prev.operands[0].reg == X86_REG_EBP
                and prev.operands[1].type in (X86_OP_IMM, X86_OP_REG)):
            return True
        # mov ebp,reg may be several insns before push ebp (cmd 0x6556 after rep movs).
        for k in range(max(0, insn_idx - 8), insn_idx):
            pk = insns[k]
            if (pk.mnemonic == 'mov' and len(pk.operands) == 2
                    and pk.operands[0].type == X86_OP_REG
                    and pk.operands[0].reg == X86_REG_EBP
                    and pk.operands[1].type in (X86_OP_IMM, X86_OP_REG)):
                return True
        if frame_rbp_saved:
            return False
        if 'rbp' not in callee_save_stack:
            return False
        if insn_idx + 1 >= len(insns):
            return False
        n1 = insns[insn_idx + 1]
        return n1.mnemonic in ('push', 'call')

    def _call_target_offsets(self, out: bytearray) -> Set[int]:
        """Blob offsets that are E8 rel32 call destinations."""
        targets: Set[int] = set()
        for i in range(len(out) - 5):
            if out[i] != 0xE8:
                continue
            rel = struct.unpack_from('<i', out, i + 1)[0]
            tgt = i + 5 + rel
            if 0 <= tgt < len(out):
                targets.add(tgt)
        return targets

    def _find_ebp_global_table_rva(self, insns: list, from_idx: int) -> Optional[int]:
        """Detect GetProcAddress trio stores + [ebp+0/+4/+8] cmps (cmd 0x9FC5)."""
        stores: List[int] = []
        ebp_cmps = 0
        for j in range(from_idx, min(from_idx + 140, len(insns))):
            ins = insns[j]
            ops = ins.operands
            if ins.mnemonic == 'cmp' and len(ops) == 2:
                for op in ops:
                    if (op.type == X86_OP_MEM and op.mem.base == X86_REG_EBP
                            and op.mem.index == 0):
                        ebp_cmps += 1
            if (ins.mnemonic == 'mov' and len(ops) == 2
                    and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG
                    and ops[1].reg == X86_REG_EAX):
                m = ops[0].mem
                if m.base == 0 and m.index == 0 and m.segment == 0:
                    stores.append(self._abs_mem_disp_to_rva(m.disp))
        if ebp_cmps < 2 or len(stores) < 3:
            return None
        for base in stores:
            if (base + 4) in stores and (base + 8) in stores:
                return base
        return None

    @staticmethod
    def _frameless_stdcall_arg_slot(disp: int, frame_local_sub: int,
                                    hw_stack_pushes: int,
                                    elided_arg_bytes: int = 0) -> Optional[int]:
        """[esp+disp] → caller stdcall arg slot after sub esp,N + callee pushes."""
        if frame_local_sub <= 0:
            return None
        if frame_local_sub == 0x58 and disp >= 0x6c:
            slot = (disp - 0x6c) // 4
            if 0 <= slot < 4:
                return slot
        arg_byte = disp - hw_stack_pushes * 4 - frame_local_sub - elided_arg_bytes
        if arg_byte in (4, 8, 12, 16):
            # Plain ``sub esp,N`` frames: arg0 sits at +4 above the frame+pushes.
            # Large ``__chkstk`` probes (≥4KiB) allocate so the return address
            # sits inside the probed region; the same incoming arg then appears
            # 4 bytes higher (arg_byte 8/12/16/20).  Prefer the probe mapping
            # when the frame was probe-sized — otherwise slot 0 is mis-read as
            # slot 1 and cmdline helpers get a wchar immediate as a PWSTR
            # (cmd 0xA4E7 → [rsi+2] AV on 0x2F).
            if frame_local_sub >= 0x1000 and arg_byte >= 8:
                return (arg_byte // 4) - 2
            return (arg_byte // 4) - 1
        if frame_local_sub >= 0x1000 and arg_byte in (8, 12, 16, 20):
            return (arg_byte // 4) - 2
        return None

    @staticmethod
    def _frameless_arg_home_slot_off(slot: int) -> int:
        """Byte offset from frame base to spilled arg slot."""
        return 4 + slot * 8

    @staticmethod
    def _frameless_arg_home_rsp_off(slot: int, frame_rsp_bias: int) -> int:
        """Byte offset from current RSP to spilled arg at frame_base+4+slot*8."""
        return 4 + slot * 8 + frame_rsp_bias

    def _gap_target_after_align_epilogue(self, out: bytearray, gap: int,
                                         limit: int = 48) -> Optional[int]:
        """Find the next real PE64 insn after orphaned x86 bytes post-align-epilogue."""
        end = min(gap + limit, len(out) - 3)
        # After ``call rax`` IAT thunks the next real use is usually ``mov *, rax``.
        for k in range(gap, end):
            if k + 3 <= len(out) and out[k] == 0x48 and out[k + 1] == 0x89:
                modrm = out[k + 2]
                if (modrm & 0xC0) == 0xC0 and ((modrm >> 3) & 7) == 0:
                    return k
            if k + 2 <= len(out) and out[k] == 0x89:
                modrm = out[k + 1]
                if (modrm & 0xC0) == 0xC0 and ((modrm >> 3) & 7) == 0:
                    return k
            if k + 2 <= len(out) and out[k:k + 2] in (b'\x85\xc0', b'\x48\x85'):
                return k
        prefer = (
            b'\x41\x55', b'\x48\xb8', b'\x48\xb9', b'\x48\xba', b'\x48\x8b',
            b'\x48\x8d', b'\x4c\x8b', b'\xe8',
        )
        for k in range(gap, end):
            for p in prefer:
                if k + len(p) <= len(out) and out[k:k + len(p)] == p:
                    return k
            if self._looks_like_x64_insn_start(out, k):
                b2 = out[k:k + 2]
                if b2 in (b'\x33\xc0', b'\x31\xc0', b'\x48\x31', b'\x31\xd2', b'\x31\xdb'):
                    continue
                b3 = out[k:k + 3]
                if b3 in (b'\x48\x31\xc0', b'\x48\x31\xd2', b'\x48\x31\xdb'):
                    continue
                if b2[0:1] in (b'\xd9', b'\xd8'):
                    continue
                return k
        return None

    def _refine_shim_target_off(self, out: bytearray, target_rva: int,
                                hint: int) -> int:
        """When rva_map points mid-instruction, locate the real PE64 insn start."""
        if hint < 0 or hint >= len(out):
            return hint
        if self._x86_cf and target_rva in self._x86_cf.epilogue_labels:
            snap = getattr(self, '_epilogue_snap_map', None) or {}
            return snap.get(hint, hint)
        abs_load = False
        sec = self.pe.section_for_rva(target_rva) if self.pe else None
        if sec:
            x86 = self.pe.get_section_data(sec)
            off = target_rva - sec['vaddr']
            if (0 <= off < len(x86) and x86[off] == 0x8B
                    and off + 1 < len(x86)
                    and x86[off + 1] in (0x0D, 0x05, 0x15, 0x1D, 0x35, 0x3D)):
                abs_load = True
                for pos in range(max(0, hint - 16), min(len(out) - 3, hint + 96)):
                    if out[pos:pos + 2] in (b'\x49\xbb', b'\x48\xb8'):
                        return pos
        if not abs_load and HAS_CAPSTONE:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            insns = list(md.disasm(out[hint:hint + 8], hint, count=1))
            if insns and insns[0].address == hint:
                return hint
        for pos in range(hint, min(hint + 64, len(out))):
            if self._looks_like_x64_insn_start(out, pos):
                return pos
        return hint

    def _resolve_call_target_off(self, out: bytearray, target_rva: int,
                                 rva_map: Dict[int, int]) -> Optional[int]:
        """Map a call/jmp target RVA to a snap-worthy shim offset."""
        if self._is_alloca_probe_rva(target_rva):
            ck = self._pure_chkstk_entry_off(out)
            if ck is not None:
                return ck
        if self._x86_cf and target_rva in self._x86_cf.epilogue_labels:
            ep = self._materialize_epilogue_label(out, rva_map, target_rva)
            if ep is not None:
                snap = getattr(self, '_epilogue_snap_map', None) or {}
                return snap.get(ep, ep)
        tgt = rva_map.get(target_rva)
        if tgt is not None:
            tgt = self._refine_shim_target_off(out, target_rva, tgt)
            outer = self._outer_entry_before_align(out, tgt)
            if outer is not None:
                tgt = outer
            # Universal: a recognized x86 function entry maps 1:1 onto its
            # translated prologue, so rva_map is authoritative.  Trust it even
            # when the strict prologue-quality gate would reject an unusual
            # opener (e.g. SEH frames that start ``push rbp; … push -1; movabs``).
            # Without this, valid entries like the CRT ``main`` get discarded and
            # the call is mis-snapped to an unrelated function.
            # Exception: when the recorded slot is clearly the *previous*
            # function's epilogue tail (``pop*; ret`` / ``mov [reg],r8``), snap
            # forward onto a real prologue — classic early map for frameless
            # ``cmp [esp+4],0`` helpers.
            if (target_rva in self._fn_entry_rvas
                    and 0 <= tgt < len(out)):
                if self._x64_entry_prologue_ok(out, tgt):
                    # Large-frame ``mov rax,imm; home rcx..; call __chkstk``:
                    # rva_map often lands on the first ``mov [rsp+8],rcx`` home
                    # (7 bytes after ``mov rax,imm``).  Callers that skip the
                    # imm leave RAX wrong for __chkstk and under-allocate.
                    if (tgt >= 7 and out[tgt:tgt + 4] == b'\x48\x89\x4c\x24'
                            and out[tgt - 7:tgt - 4] == b'\x48\xc7\xc0'):
                        return tgt - 7
                    if (tgt >= 5 and out[tgt:tgt + 4] == b'\x48\x89\x4c\x24'
                            and out[tgt - 5] == 0xB8):
                        return tgt - 5
                    # Frameless stdcall: homes prepended before body; rva_map
                    # / VA fingerprint often pins the post-home movabs.
                    return self._pure_snap_back_past_frameless_shadow_homes(
                        out, tgt)
                # Landing on post-home movabs fails prologue_ok — walk back.
                back = self._pure_snap_back_past_frameless_shadow_homes(out, tgt)
                if (back != tgt
                        and self._x64_entry_prologue_ok(out, back)):
                    return back
                for d in range(1, 16):
                    cand = tgt + d
                    if cand >= len(out):
                        break
                    if out[cand] in (0xC3, 0xC2):
                        continue
                    if self._x64_entry_prologue_ok(out, cand):
                        return cand
                return tgt
            if (0 <= tgt < len(out)
                    and self._offset_is_valid_entry(out, tgt)):
                return tgt
            entry = self._find_enclosing_function_entry(out, tgt, rva_map)
            if entry is not None:
                return entry
        return self._entry_for_x86_target(out, target_rva, rva_map)

    @staticmethod
    def _frameless_entry_rva(text_data: bytes, text_rva: int, rva: int) -> int:
        """Walk back over push ebx/esi/edi/ebp so the real entry is translated."""
        off = rva - text_rva
        walked = 0
        while off > 0 and walked < 4:
            # Do not walk into a prior function's RET tail.
            window = text_data[max(0, off - 8):off]
            if b'\xc3' in window or b'\xc2' in window:
                break
            b = text_data[off - 1]
            if b in (0x53, 0x56, 0x57, 0x55):  # push ebx/esi/edi/ebp
                off -= 1
                walked += 1
                continue
            break
        # cmd helpers often start with `and word ptr [global], 0` before pushes.
        if off > 0 and b'\xc3' not in text_data[max(0, off - 8):off]:
            if off >= 7 and text_data[off - 7:off - 5] == b'\x66\x83' and text_data[off - 5] == 0x25:
                if text_data[off - 1] == 0:
                    off -= 7
            elif off >= 6 and text_data[off - 6:off - 4] == b'\x83\x25' and text_data[off - 1] == 0:
                off -= 6
        return text_rva + off

