"""Instruction emission helpers bound to translator state.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class EncodingMixin:
    """See the module docstring."""

    _W32_TO_W64_TEXT = {
        'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx',
        'esp': 'rsp', 'ebp': 'rbp', 'esi': 'rsi', 'edi': 'rdi',
    }


    @staticmethod
    def _encode_gs_load(reg: str, disp: int) -> bytes:
        """mov reg64, qword ptr gs:[disp32] — avoids Keystone RIP-relative bugs."""
        rn = _W64_REG_NUM.get(reg.lower(), 0)
        return (bytes([0x65, 0x48, 0x8B, 0x04 | (rn << 3), 0x25])
                + struct.pack('<I', disp & 0xFFFFFFFF))

    @staticmethod
    def _encode_gs_store(reg: str, disp: int) -> bytes:
        """mov qword ptr gs:[disp32], reg64"""
        rn = _W64_REG_NUM.get(reg.lower(), 0)
        return (bytes([0x65, 0x48, 0x89, 0x04 | (rn << 3), 0x25])
                + struct.pack('<I', disp & 0xFFFFFFFF))

    @staticmethod
    def _encode_abs_load(reg: str, addr: int) -> bytes:
        """reg32 = *(dword*)addr — packed .data slot (zero-extends to 64-bit).

        NOTE: the [disp32] SIB form sign-extends disp32, so it cannot reach our
        0x180000000+ image; use movabs to load the absolute address first.
        """
        rn = _W64_REG_NUM.get(reg.lower(), 0)
        hi = (rn >> 3) & 1
        out = bytearray()
        out += bytes([0x48 | hi, 0xB8 | (rn & 7)]) + struct.pack('<Q', addr & 0xFFFFFFFFFFFFFFFF)
        # mov reg32, dword ptr [reg]  (mod=01, disp8=0)
        rex_load = 0x40 | (hi << 2) | hi  # no REX.W
        modrm = 0x40 | ((rn & 7) << 3) | (rn & 7)
        out += bytes([rex_load, 0x8B, modrm, 0x00])
        return bytes(out)

    @staticmethod
    def _encode_abs_store(reg: str, addr: int) -> bytes:
        """*(dword*)addr = reg32 — packed .data slot via R11 scratch.

        Image globals stay 4-byte-packed (preferred base <4GiB).  A qword
        store would zero the adjacent slot.
        """
        rn = _W64_REG_NUM.get(reg.lower(), 0)
        out = bytearray()
        # movabs r11, addr ; mov dword [r11], reg32
        out += bytes([0x49, 0xBB]) + struct.pack('<Q', addr & 0xFFFFFFFFFFFFFFFF)
        rex = 0x41 | (((rn >> 3) & 1) << 2)  # REX.B (+REX.R if src>=8); no W
        out += bytes([rex, 0x89, 0x03 | ((rn & 7) << 3)])
        return bytes(out)

    def _emit_abs_dword_load(self, out: bytearray, dst: str, addr: int) -> None:
        """Load a value from an absolute VA (x86 push [global] args)."""
        addr32 = addr & 0xFFFFFFFF
        if self._is_iat_rva(addr32):
            if self._iat_rva_map:
                new_va = self._resolve_iat_slot_va(addr32)
            else:
                new_va = addr32  # patched once _iat_rva_map exists
            load_sz = 'qword' if self._cmd_no_hacks else 'dword'
        else:
            new_va = self._relocate_imm(addr32, len(out), 0)
            # x86 program globals are 4-byte slots and the data section keeps
            # that 4-byte layout after relocation (only *code* VA immediates are
            # widened).  Reading a global as qword therefore pulls 4 valid bytes
            # plus 4 bytes of the *adjacent* global as a bogus high dword — which
            # is exactly how a runtime-stored 32-bit heap pointer became
            # 0x0219A040_006122E0 and crashed HeapFree.  All shim addresses are
            # <4GB, so a 32-bit zero-extended load is always the correct value.
            load_sz = 'dword'
        d32_map = {'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
                   'rsi': 'esi', 'rdi': 'edi', 'r8': 'r8d', 'r9': 'r9d',
                   'r10': 'r10d', 'r11': 'r11d'}
        d32 = d32_map.get(dst, dst)
        dst_asm = dst if load_sz == 'qword' else d32
        # Always movabs+load — never rip-rel.  Emit-time section RVAs are often
        # still the stale ``new_base+old_rva`` linear form; rip-rel bakes that
        # into a displacement that ``_patch_abs_va_in_code`` cannot rewrite
        # (cmd format buffer loads ``[0x4ad1fbc8]`` → rip→0x71a64 while stores
        # correctly movabs 0x6abc8).  Movabs immediates are patched later.
        scratch = 'r11' if dst != 'r11' else 'r10'
        out += self._asm(f'movabs {scratch}, 0x{new_va:x}')
        out += self._asm(f'mov {dst_asm}, {load_sz} ptr [{scratch}]')

    def _emit_iat_call(self, out: bytearray, iat_va: int,
                       chunk_rva: int = 0) -> None:
        """call through IAT slot.

        Uses ``movabs rax, <IAT_VA>`` followed by an indirect call.  The
        absolute address is patched by the delta-shift pass once the final
        ``.idata`` layout is known.  RIP-relative ``FF 15`` is avoided
        during function-driven translation because the chunk's final RVA
        is not yet known (``chunk_base=0``)."""
        # Prefer _resolve_iat_slot_va which uses the precise _iat_rva_map
        # (per-slot mapping).  _relocate_imm applies a linear section offset
        # which is wrong when import transforms move individual slots between
        # DLLs (e.g. __p__commode moves from MSVCRT to w2kshim64).
        new_va = self._resolve_iat_slot_va(iat_va)
        out += self._asm(f'mov rax, 0x{new_va:x}')
        out += self._asm('mov rax, qword ptr [rax]')
        out += self._asm('call rax')

    def _emit_runtime_pointer_slot(self, out: bytearray, text_data: bytes,
                                   text_rva: int, old_slot_rva: int,
                                   rva_map: Dict[int, int]) -> int:
        """Copy an x86 pointer cell (CRT tail slots in .data) as a PE64 qword."""
        ptr32 = self._read_pe_dword(old_slot_rva)
        if ptr32 == 0:
            q = 0
        elif self.old_base <= ptr32 < self.old_base + self.pe.image_size:
            old_ptr_rva = ptr32 - self.old_base
            if old_ptr_rva in rva_map:
                q = self.new_base + text_rva + rva_map[old_ptr_rva]
            elif (self._iat_rva_map and old_ptr_rva in self._iat_rva_map):
                q = self.new_base + self._iat_rva_map[old_ptr_rva]
            else:
                q = self._relocate_imm(ptr32)
        else:
            q = ptr32
        slot_off = len(out)
        out += struct.pack('<Q', q & 0xFFFFFFFFFFFFFFFF)
        pad = (8 - len(out) % 8) % 8
        if pad:
            out += b'\x00' * pad
        self._runtime_slot_map[old_slot_rva] = text_rva + slot_off
        return slot_off

    def _emit_iat_jmp(self, out: bytearray, iat_va: int,
                      at_rva: Optional[int] = None,
                      chunk_rva: int = 0) -> None:
        """jmp through IAT slot (SEH filter thunks, import tail jumps).

        *chunk_rva* is the RVA of the code chunk in the PE64 layout.
        When *at_rva* is provided it overrides the computed call-site RVA."""
        new_va = self._resolve_iat_slot_va(iat_va)
        jmp_rva = at_rva if at_rva is not None else (chunk_rva + len(out))
        jmp_va = self.new_base + jmp_rva
        rel = new_va - (jmp_va + 6)
        jmp_off = len(out)
        if -2147483648 <= rel <= 2147483647:
            out += b'\\xff\\x25\\x00\\x00\\x00\\x00'
            struct.pack_into('<i', out, jmp_off + 2, rel)
        else:
            out += self._asm(f'mov rax, 0x{new_va:x}')
            out += self._asm('mov rax, qword ptr [rax]')
            out += self._asm('jmp rax')

    def _emit_rip_rel_mov_imm32(self, out: bytearray, mem_va: int, imm32: int) -> None:
        """mov dword ptr [mem], imm32 via movabs (layout-safe).

        Early translate runs before ``_old_to_new_section`` exists.  A
        ``mov [rip+disp], imm32`` encoding is 10 bytes (C7 05 disp imm); the
        old ``pack_into(..., insn_len-4)`` wrote the displacement into the
        *immediate* slot and left disp=0, so the store hit the instruction
        stream (cmd ``/c`` AV at ``mov dword ptr [rip], …``).  Movabs leaves
        the absolute VA for ``_patch_abs_va_in_code`` / C7-imm patching.
        """
        new_va = self._relocate_imm(mem_va & 0xFFFFFFFF, len(out), 0)
        imm = imm32 & 0xFFFFFFFF
        if self._is_image_pointer(imm):
            imm = self._relocate_imm(imm, len(out), 0) & 0xFFFFFFFF
        out += self._asm(f'movabs rax, 0x{new_va:x}')
        out += self._asm(f'mov dword ptr [rax], 0x{imm:x}')

    def _emit_add_imm64(self, out: bytearray, dst: str, imm: int) -> None:
        """dst += imm — use scratch when imm does not fit in signed disp32."""
        imm_u = imm & 0xFFFFFFFFFFFFFFFF
        # Image VAs (incl. deferred old-base) must use movabs+add.  A plain
        # ``add r64, imm32`` sign-extends; after section remap the VA often
        # has bit 31 set (base 0x80000000+) and becomes 0xFFFFFFFF8xxxxxxx
        # (cmd ``lea edi,[eax+0x4AD1D480]`` → ``rep stos`` AV).
        if (self._is_image_pointer(imm_u & 0xFFFFFFFF)
                or imm_u > 0x7FFFFFFF):
            scratch = 'r11' if dst != 'r11' else 'r10'
            out += self._asm(f'movabs {scratch}, 0x{imm_u:x}')
            out += self._asm(f'add {dst}, {scratch}')
            return
        s32 = imm_u if imm_u < 0x80000000 else imm_u - 0x100000000
        if -0x80000000 <= s32 <= 0x7FFFFFFF:
            if s32 < 0:
                out += self._asm(f'sub {dst}, 0x{-s32:x}')
            else:
                out += self._asm(f'add {dst}, 0x{s32:x}')
            return
        scratch = 'r11' if dst != 'r11' else 'r10'
        out += self._asm(f'movabs {scratch}, 0x{imm_u:x}')
        out += self._asm(f'add {dst}, {scratch}')

    def _emit_push_imm64(self, out: bytearray, imm: int) -> None:
        """Push a 64-bit immediate (Keystone truncates push imm32 >16-bit oddly)."""
        imm_u = imm & 0xFFFFFFFFFFFFFFFF
        s32 = imm_u if imm_u < 0x80000000 else imm_u - 0x100000000
        if -128 <= s32 <= 127:
            out += self._asm(f'push {s32}')
        elif 0 <= imm_u <= 0x7FFF:
            out += self._asm(f'push 0x{imm_u:x}')
        else:
            out += self._asm(f'mov rax, 0x{imm_u:x}')
            out += self._asm('push rax')

    def _emit_frame_arg_spills(self, out: bytearray, slots: Set[int]) -> None:
        """Spill selected Win64 arg regs to [RBP+0x10..] MSVC home slots."""
        for i in sorted(slots):
            if i < len(WIN64_ARG_REG_NAMES):
                out += self._asm(
                    f'mov qword ptr [rbp+{0x10 + i * 8}], {WIN64_ARG_REG_NAMES[i]}')

    def _emit_mem_index_dword_load(self, out: bytearray, dest_reg: str,
                                   base: int, index: int,
                                   scale: int, disp: int) -> None:
        """push [base+index] call args — 32-bit address wrap on all hosts."""
        scale = scale or 1
        disp &= 0xFFFFFFFF
        if self.win10_test_shim:
            b64 = W32_TO_W64_REG.get(base, 'rax')
            i64 = W32_TO_W64_REG.get(index, 'rcx')
            d32 = self._dword_arg_reg(dest_reg)
            if scale == 1 and disp == 0:
                mem = f'dword ptr [{b64}+{i64}]'
            elif scale in (1, 2, 4, 8) and disp == 0:
                mem = f'dword ptr [{b64}+{i64}*{scale}]'
            else:
                mem = f'dword ptr [{b64}+{i64}*{scale}+0x{disp:x}]'
            # Use _asm_addr32 so Keystone emits the 67h address-size
            # prefix — x86 address arithmetic wraps at 32 bits, and
            # the translated code must preserve that behaviour.
            out += self._asm_addr32(f'mov {d32}, {mem}')
            return
        b32 = W32_REG_ASM.get(base, 'eax')
        i32 = W32_REG_ASM.get(index, 'ecx')
        scratch = 'r11d' if dest_reg in ('r10', 'r10d', 'r11', 'r11d') else 'r10d'
        if scale == 1 and disp == 0:
            mem = f'dword ptr [{b32}+{i32}]'
        elif scale in (1, 2, 4, 8) and disp == 0:
            mem = f'dword ptr [{b32}+{i32}*{scale}]'
        else:
            mem = f'dword ptr [{b32}+{i32}+0x{disp:x}]'
        out += self._asm_addr32(f'mov {scratch}, {mem}')
        d32 = {'rcx': 'ecx', 'rdx': 'edx', 'r8': 'r8d', 'r9': 'r9d'}.get(
            dest_reg, dest_reg)
        if d32 != scratch:
            out += self._asm(f'mov {d32}, {scratch}')

    def _emit_mem_base_dword_load(self, out: bytearray, dest_reg: str,
                                  base: int, disp: int) -> None:
        """``push dword ptr [reg+disp]`` → dword load into a Win64 arg reg.

        x86 structure slots are 4-byte packed; a qword load would pull the
        next field into the high half (cmd path ptr → ``0x1_xxxxxxxx`` AV).
        """
        disp &= 0xFFFFFFFF
        if disp > 0x7FFFFFFF:
            disp_s = disp - 0x100000000
        else:
            disp_s = disp
        b64 = W32_TO_W64_REG.get(base, 'rax')
        d32 = self._dword_arg_reg(dest_reg)
        if disp_s == 0:
            mem = f'dword ptr [{b64}]'
        else:
            mem = f'dword ptr [{b64}{disp_s:+d}]'
        out += self._asm(f'mov {d32}, {mem}')

    def _emit_homed_stack_arg_to_reg(self, out: bytearray, reg: str,
                                       home: int) -> None:
        """Load a homed incoming arg from ``[rbp+home]`` into a Win64 arg reg.

        Homes are written as full QWORD spills of RCX/RDX/R8/R9.  Loading with
        ``mov r8d/r9d, dword…`` truncates pointers (cmd 0x4A8F path → AV in
        the callee writing through a chopped R9).
        """
        out += self._asm(f'mov {reg}, qword ptr [rbp+0x{home:x}]')

    def _emit_lea_ebp_slot(self, out: bytearray, dest_reg: str, disp: int,
                           seh_active: bool = False) -> None:
        """lea reg,[ebp±N] — map stdcall arg slots to MSVC [rbp+home]."""
        if disp > 0x7FFFFFFF:
            disp -= 0x100000000
        disp = self._seh_rbp_local_disp(disp, seh_active)
        home = ebp_disp_to_rbp_home(disp) if disp >= 8 else None
        if home is not None:
            out += self._asm(f'lea {dest_reg}, [rbp+0x{home:x}]')
        else:
            out += self._asm(f'lea {dest_reg}, [rbp{disp:+d}]')

    def _emit_ebp_scratch_store_reg(self, out: bytearray, src64: str,
                                    home: int = -0x20) -> None:
        if getattr(self, '_ebp_scratch_in_reg', False):
            if src64 != 'rbp':
                out += self._asm(f'mov rbp, {src64}')
            return
        out += self._asm(f'mov {self._ebp_scratch_mem(home)}, {src64}')

    def _emit_iat_fn_ptr_load(self, out: bytearray, x86_dst: int,
                              slot_va: int,
                              iat_fn_holder: Dict[int, str],
                              iat_fn_slot: Optional[Dict[int, int]] = None,
                              iat_key: Optional[int] = None) -> None:
        """Load an import fn ptr from its IAT cell into a stable x64 register.

        *slot_va* is the relocated PE64 cell address used for codegen.
        *iat_key* (when set) is the original x86 absolute IAT VA / key for
        ``_iat_name_at`` / ``_is_zero_arg_iat`` lookups.
        """
        holder = _IAT_FN_HOLDER_W64.get(x86_dst, W32_TO_W64_REG.get(x86_dst, 'rax'))
        out += self._asm(f'movabs {holder}, 0x{slot_va:x}')
        out += self._asm(f'mov {holder}, qword ptr [{holder}]')
        if holder in _IAT_FN_HOLDER_W64.values():
            iat_fn_holder[x86_dst] = holder
        if iat_fn_slot is not None:
            # Prefer the original x86 IAT VA so zero-arg detection works;
            # relocated PE64 cells are not in ``_iat_func_by_rva``.
            iat_fn_slot[x86_dst] = (
                iat_key if iat_key is not None else slot_va)

    def _emit_ebp_scratch_load_to(self, out: bytearray, dst64: str,
                                  home: int = -0x20) -> None:
        if getattr(self, '_ebp_scratch_in_reg', False):
            if dst64 != 'rbp':
                out += self._asm(f'mov {dst64}, rbp')
            return
        out += self._asm(f'mov {dst64}, {self._ebp_scratch_mem(home)}')

    def _emit_mov32_to_w64_reg(self, out: bytearray, dst_w64: str,
                               src_w32_id: int,
                               ebp_reg_scratch: bool = False,
                               ebp_scratch_reg: str = 'r12') -> None:
        """Move a 32-bit x86 GPR into a Win64 register (zero-extend, no sign extend)."""
        if src_w32_id == X86_REG_EBP and ebp_reg_scratch:
            self._emit_ebp_scratch_load_to(out, dst_w64)
            return
        src64 = W32_TO_W64_REG.get(src_w32_id, 'rax')
        if dst_w64 in WIN64_ARG_REG_NAMES:
            # Always move the full 64-bit GPR into Win64 arg regs.  x86 code
            # keeps pointers in EBP/ESI/…; truncating via ``mov ecx, ebp`` both
            # risks losing high bits and used to become INT3 when normalize
            # rewrote the operand to ``mov ecx, rbp``.
            if dst_w64 != src64:
                out += self._asm(f'mov {dst_w64}, {src64}')
            return
        if dst_w64 != src64:
            out += self._asm(f'mov {dst_w64}, {src64}')

    def _home_frameless_win64_shadow_args(self, out: bytearray) -> None:
        """Spill RCX/RDX/R8/R9 into the caller-provided 32-byte shadow space.

        Frameless stdcall bodies reload incoming args with ``push [esp+N]``
        after nested calls.  On x64 those args live in volatile registers, so
        they must be copied into the caller's shadow slots *before* any of our
        own pushes.  Reloading through the caller's R13 (left by a call-align
        wrapper) is wrong: that frame does not hold our arguments.
        """
        out += self._asm('mov qword ptr [rsp+0x8], rcx')
        out += self._asm('mov qword ptr [rsp+0x10], rdx')
        out += self._asm('mov qword ptr [rsp+0x18], r8')
        out += self._asm('mov qword ptr [rsp+0x20], r9')

    def _emit_esp_fwd_arg(self, out: bytearray, reg: str, slot: int,
                          *, hw_stack_pushes: int = 0,
                          frameless_shadow_homes: bool = False) -> None:
        """Materialize a ``push [esp+N]`` stdcall-arg forward into *reg*."""
        if frameless_shadow_homes and 0 <= slot < 4:
            # entry home at [entry_rsp + 8 + slot*8]; after hw_stack_pushes
            # callee-saves, current_rsp = entry_rsp - 8*hw_stack_pushes.
            off = 8 * (hw_stack_pushes + 1 + slot)
            out += self._asm(f'mov {reg}, qword ptr [rsp+0x{off:x}]')
            return
        if slot < len(WIN64_ARG_REG_NAMES):
            src = WIN64_ARG_REG_NAMES[slot]
            if src != reg:
                out += self._asm(f'mov {reg}, {src}')

    def _emit_flushed_push_arg_to_reg(
            self, out: bytearray, reg: str, atype: str, aval: int,
            *, ebp_reg_scratch: bool, ebp_scratch_reg: str,
            frame_args_spilled: bool, stack_spill_count: int,
            frameless_stack_bias: int, frame_arg_anchor: bool,
            hw_stack_pushes: int = 0,
            frameless_shadow_homes: bool = False) -> None:
        """Materialize one deferred PUSH operand into a Win64 arg register."""
        if atype == 'imm':
            new_imm = self._relocate_imm(aval & 0xFFFFFFFF, len(out), 0)
            out += self._asm(f'mov {reg}, 0x{new_imm & 0xFFFFFFFFFFFFFFFF:x}')
        elif atype == 'reg':
            if aval == X86_REG_EBP and ebp_reg_scratch:
                self._emit_ebp_scratch_load_to(out, reg)
            else:
                self._emit_mov32_to_w64_reg(
                    out, reg, aval, ebp_reg_scratch, ebp_scratch_reg)
        elif atype == 'spill':
            # Spill index is 0-based at push time; deepest spill sits at
            # ``[rsp + 8*(count-1)]``.  Using ``count - aval`` (without -1)
            # read one slot past the spill block (cmd ReadFile wrapper →
            # R9=&n loaded garbage → KERNELBASE write @ 0x56).
            off = 8 * (stack_spill_count - aval - 1)
            out += self._asm(f'mov {reg}, qword ptr [rsp+0x{off:x}]')
        elif atype == 'mem_abs':
            self._emit_abs_dword_load(out, reg, aval)
        elif atype == 'mem_index':
            base, idx, scale, disp = aval
            self._emit_mem_index_dword_load(out, reg, base, idx, scale, disp)
        elif atype == 'mem_base':
            base, disp = aval
            self._emit_mem_base_dword_load(out, reg, base, disp)
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
                out, reg, atype, aval, frameless_stack_bias, frame_arg_anchor)
        else:
            out += self._asm(f'xor {reg}, {reg}')

    def _emit_call_args_parallel(
            self, out: bytearray, args: list, arg_regs: list,
            *, ebp_reg_scratch: bool, ebp_scratch_reg: str,
            frame_args_spilled: bool, stack_spill_count: int,
            frameless_stack_bias: int, frame_arg_anchor: bool,
            hw_stack_pushes: int = 0,
            frameless_shadow_homes: bool = False) -> None:
        """Load Win64 arg regs from deferred pushes without clobbering sources.

        ``mov rcx, rdx; mov rdx, rcx`` (cmd 0x1A709 ``push edx; push ecx;
        push eax; call``) destroys arg1 — snapshot any source that aliases a
        destination arg register into r10/r11 (then stack) first.
        """
        n = min(len(args), len(arg_regs))
        if n == 0:
            return
        dests = list(arg_regs[:n])
        dest_set = set(dests)
        # Resolve plain register sources; others stay None and use the emitter.
        # ``esp_fwd`` / unhomed ``ebp_arg`` also read live Win64 arg regs — treat
        # them as register sources so ``push [esp+4]; push [global]; call``
        # snapshots RCX before ``mov ecx, [global]`` clobbers it (cmd 0xFF31).
        src_regs: List[Optional[str]] = []
        for i in range(n):
            atype, aval = args[i]
            if (atype == 'reg' and not (aval == X86_REG_EBP and ebp_reg_scratch)):
                src_regs.append(W32_TO_W64_REG.get(aval, 'rax'))
            elif (atype == 'esp_fwd' and isinstance(aval, int)
                  and 0 <= aval < len(WIN64_ARG_REG_NAMES)
                  and not frameless_shadow_homes):
                src_regs.append(WIN64_ARG_REG_NAMES[aval])
            elif (atype == 'ebp_arg' and isinstance(aval, int)
                  and 0 <= aval < 4 and not frame_args_spilled):
                src_regs.append(WIN64_ARG_REG_NAMES[aval])
            else:
                src_regs.append(None)
        # Snapshot sources that live in a destination slot.
        snap: Dict[str, str] = {}
        scratches = ['r10', 'r11']
        si = 0
        stack_snaps: List[str] = []
        for src in src_regs:
            if src is None or src not in dest_set or src in snap:
                continue
            if si < len(scratches):
                sc = scratches[si]
                si += 1
                if sc != src:
                    out += self._asm(f'mov {sc}, {src}')
                snap[src] = sc
            else:
                out += self._asm(f'push {src}')
                stack_snaps.append(src)
                snap[src] = f'stack:{len(stack_snaps) - 1}'
        # Emit each arg; register moves use snap when present.
        for i in range(n):
            dst = dests[i]
            src = src_regs[i]
            if src is not None:
                mapped = snap.get(src, src)
                if mapped.startswith('stack:'):
                    slot = int(mapped.split(':')[1])
                    # Most recently pushed is [rsp]; account for later pushes.
                    off = 8 * (len(stack_snaps) - 1 - slot)
                    out += self._asm(f'mov {dst}, qword ptr [rsp+0x{off:x}]')
                elif mapped != dst:
                    out += self._asm(f'mov {dst}, {mapped}')
            else:
                self._emit_flushed_push_arg_to_reg(
                    out, dst, args[i][0], args[i][1],
                    ebp_reg_scratch=ebp_reg_scratch,
                    ebp_scratch_reg=ebp_scratch_reg,
                    frame_args_spilled=frame_args_spilled,
                    stack_spill_count=stack_spill_count,
                    frameless_stack_bias=frameless_stack_bias,
                    frame_arg_anchor=frame_arg_anchor,
                    hw_stack_pushes=hw_stack_pushes,
                    frameless_shadow_homes=frameless_shadow_homes)
        if stack_snaps:
            out += self._asm(f'add rsp, 0x{8 * len(stack_snaps):x}')

    def _emit_push_arg_to_reg(self, out: bytearray, reg: str,
                              atype: str, aval: int,
                              frame_rsp_bias: int = 0,
                              frame_arg_anchor: bool = False) -> None:
        """Load a deferred x86 PUSH operand into a Win64 call arg register."""
        if atype == 'ebp_slot':
            disp = aval
            if disp > 0x7FFFFFFF:
                disp -= 0x100000000
            d32 = self._dword_arg_reg(reg)
            out += self._asm(f'mov {d32}, dword ptr [rbp{disp:+d}]')
        elif atype == 'esp_mem':
            d32 = self._dword_arg_reg(reg)
            out += self._asm(f'mov {d32}, dword ptr [rsp+0x{aval:x}]')
        elif atype == 'arg_home':
            off = self._frameless_arg_home_slot_off(aval)
            # Shadow homes are full qwords (spilled RCX/RDX/R8/R9).  DWORD
            # loads truncate PE64 pointers in the high half of the low 4GB
            # image window and also drop the upper half of true high VAs.
            if frame_arg_anchor:
                out += self._asm(f'mov {reg}, qword ptr [r15+0x{off:x}]')
            else:
                off = self._frameless_arg_home_rsp_off(aval, frame_rsp_bias)
                out += self._asm(f'mov {reg}, qword ptr [rsp+0x{off:x}]')
        else:
            out += self._asm(f'xor {reg}, {reg}')

    def _emit_call_align_prologue(self, out: bytearray, nstack: int) -> None:
        """Reserve a 16-byte-aligned call frame (32B shadow + nstack stack args).

        Win64 requires RSP ≡ 0 (mod 16) at the `call`. The translated body does
        not maintain that invariant (push rbp + an odd number of callee-save
        pushes leaves RSP off by 8), which is harmless for ordinary callees but
        faults 16-byte-strict instructions like ntdll RtlCaptureContext's
        fxsave. We save the original RSP in R13 (a callee-saved register the
        translator never uses) and realign with `and rsp,-16`. R13 survives the
        call by the ABI, so the restore is robust even when the callee leaves
        the stack unbalanced or never properly returns (e.g. a mistranslated
        `call $+5`). The push/pop keeps R13 nest-safe across calls.

        Caller must already have materialized the register args (RCX/RDX/R8/R9)
        and must write stack args to [rsp + 0x20 + i*8] after this call.

        Do NOT use for ``_setjmp3`` / ``longjmp``: those save/restore RSP via
        jmp_buf, and the R13 restore after a longjmp-return is not in the buf
        (RSP/R13 mismatch → crash). See :meth:`_iat_skips_call_align`.
        """
        frame = 0x20 + nstack * 8
        out += self._asm('push r13')
        out += self._asm('mov r13, rsp')
        out += self._asm(f'sub rsp, 0x{frame:x}')
        out += self._asm('and rsp, -16')

    def _emit_call_align_epilogue(self, out: bytearray, nstack: int) -> None:
        """Restore the RSP/R13 saved by _emit_call_align_prologue."""
        out += self._asm('mov rsp, r13')
        out += self._asm('pop r13')

    _SETJMP_ALIGN_SKIP = frozenset({
        '_setjmp3', '_setjmp', 'setjmp', 'longjmp',
    })

    def _iat_skips_call_align(self, iat_va: int) -> bool:
        """setjmp/longjmp must see the caller's RSP — no R13 align wrapper."""
        return self._iat_name_at(iat_va) in self._SETJMP_ALIGN_SKIP

    def _emit_aligned_iat_call(self, out: bytearray, iat_va: int,
                               nstack: int = 0, chunk_rva: int = 0) -> None:
        """IAT call with optional RSP align; skipped for setjmp/longjmp."""
        skip = self._iat_skips_call_align(iat_va)
        if not skip:
            self._emit_call_align_prologue(out, nstack)
        self._emit_iat_call(out, iat_va, chunk_rva)
        if not skip:
            self._emit_call_align_epilogue(out, nstack)

    def _emit_push_arg_to_stack(self, out: bytearray, rsp_off: int,
                                atype: str, aval: int,
                                frame_rsp_bias: int = 0,
                                frame_arg_anchor: bool = False,
                                args_homed: bool = False) -> None:
        """Store a deferred x86 PUSH operand to a Win64 stack arg slot."""
        if atype == 'ebp_slot':
            disp = aval
            if disp > 0x7FFFFFFF:
                disp -= 0x100000000
            out += self._asm(f'mov eax, dword ptr [rbp{disp:+d}]')
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], rax')
        elif atype == 'esp_mem':
            out += self._asm(f'mov eax, dword ptr [rsp+0x{aval:x}]')
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], rax')
        elif atype == 'arg_home':
            off = self._frameless_arg_home_slot_off(aval)
            if frame_arg_anchor:
                out += self._asm(f'mov rax, qword ptr [r15+0x{off:x}]')
            else:
                off = self._frameless_arg_home_rsp_off(aval, frame_rsp_bias)
                out += self._asm(f'mov rax, qword ptr [rsp+0x{off:x}]')
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], rax')
        elif atype == 'imm':
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], 0x{aval & 0xFFFFFFFF:x}')
        elif atype == 'reg':
            src = W32_TO_W64_REG.get(aval, 'rax')
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], {src}')
        elif atype == 'mem_abs':
            self._emit_abs_dword_load(out, 'rax', aval)
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], rax')
        elif atype == 'ebp_local':
            disp = aval
            self._emit_lea_ebp_slot(out, 'rax', disp)
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], rax')
        elif atype == 'ebp_arg':
            if args_homed or aval >= len(WIN64_ARG_REG_NAMES):
                out += self._asm(
                    f'mov rax, qword ptr [rbp+0x{ebp_arg_slot_to_rbp_home(aval):x}]')
                out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], rax')
            else:
                src = WIN64_ARG_REG_NAMES[aval]
                out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], {src}')
        else:
            out += self._asm(f'mov qword ptr [rsp+0x{rsp_off:x}], 0')

    def _normalize_x64_asm(self, text: str) -> str:
        """Rewrite x86 register names in Keystone text for amd64.

        All registers used inside a memory operand ([...]) must be 64-bit in
        long mode (a 32-bit base/index would emit a 0x67 address-size prefix and
        compute a truncated address).

        Bare ``ebp``/``esp`` are widened to ``rbp``/``rsp`` for push/pop and
        similar, but NOT when a 32-bit GP peer is present: ``mov ecx, ebp`` is
        valid x64 and required for arg setup, while ``mov ecx, rbp`` is rejected
        by Keystone and used to become a silent INT3.
        """
        import re

        def _widen_brackets(m: 're.Match') -> str:
            inner = m.group(1)
            inner = re.sub(
                r'\b(eax|ecx|edx|ebx|esp|ebp|esi|edi)\b',
                lambda r: self._W32_TO_W64_TEXT[r.group(1).lower()],
                inner, flags=re.I)
            return '[' + inner + ']'

        text = re.sub(r'\[([^\]]*)\]', _widen_brackets, text)
        # Widen bare ebp/esp only when safe.  A sized mem op needs a matching
        # 32-bit GP peer (``cmp dword ptr [r11], ebp``) — rewriting to rbp
        # makes Keystone reject the insn and the fallback emits INT3
        # (cmd 0x222E → crash at /c entry).  Same for an existing r32 peer
        # (``mov ecx, ebp``).
        has_sized_mem = bool(re.search(
            r'\b(byte|word|dword)\s+ptr\b', text, flags=re.I))
        has_r32_peer = bool(re.search(
            r'\b(eax|ecx|edx|ebx|esi|edi)\b', text, flags=re.I))
        if not has_sized_mem and not has_r32_peer:
            text = re.sub(r'\bebp\b', 'rbp', text, flags=re.I)
            text = re.sub(r'\besp\b', 'rsp', text, flags=re.I)
        # Keystone encodes ``mov r64, imm`` as sign-extended imm32 (48 C7 /0)
        # when the constant fits in 32 bits.  Two hazards for PE64:
        # 1) Final image VAs with bit 31 set (base 0x80000000+) become
        #    0xFFFFFFFF8xxxxxxx and AV on dereference.
        # 2) Deferred old-base VAs (e.g. 0x4ADxxxxx) assemble as C7, then
        #    ``_patch_mov_rm_imm32_image_vas`` rewrites the imm in place to a
        #    high new-base VA — still C7, still sign-extends at runtime.
        # Always use movabs for image-pointer immediates and high-bit values.
        old_lo = getattr(self, 'old_base', 0) or 0
        old_hi = old_lo + (getattr(getattr(self, 'pe', None), 'image_size', 0) or 0)

        def _mov_imm_no_signext(m: 're.Match') -> str:
            reg, imm_s = m.group(1), m.group(2)
            try:
                imm = int(imm_s, 0) & 0xFFFFFFFFFFFFFFFF
            except ValueError:
                return m.group(0)
            imm32 = imm & 0xFFFFFFFF
            if imm > 0x7FFFFFFF or (old_hi and old_lo <= imm32 < old_hi):
                return f'movabs {reg}, 0x{imm:x}'
            return m.group(0)
        text = re.sub(
            r'\bmov\s+(r(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:8|9|1[0-5]))\s*,\s*'
            r'(0x[0-9a-fA-F]+|\d+)\b',
            _mov_imm_no_signext,
            text,
            flags=re.I)
        return text

    def _asm_addr32(self, text: str) -> bytes:
        """Assemble x86-64 insn with 32-bit address components (67h prefix).

        Used for x86 idioms like mov eax, [eax+ecx] where the effective address
        must wrap at 32 bits, not widen to 64-bit rax+rcx.  Converts 64-bit
        register names inside ``[...]`` to their 32-bit equivalents so that
        Keystone emits the 67h address-size override prefix.
        """
        import re
        # Frame-pointer registers remain 64-bit (they hold real x64 addresses)
        text = re.sub(r'\bebp\b', 'rbp', text, flags=re.I)
        text = re.sub(r'\besp\b', 'rsp', text, flags=re.I)
        # Convert 64-bit regs to 32-bit inside address brackets so Keystone
        # emits the 67h prefix.  The 32-bit reg name causes the assembler to
        # treat the effective address as 32-bit (zero-extended), matching the
        # original x86 behaviour where addresses wrap at 4 GiB.
        _R64_TO_R32 = {
            'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
            'rsi': 'esi', 'rdi': 'edi', 'rbp': 'ebp', 'rsp': 'esp',
            'r8': 'r8d', 'r9': 'r9d', 'r10': 'r10d', 'r11': 'r11d',
            'r12': 'r12d', 'r13': 'r13d', 'r14': 'r14d', 'r15': 'r15d',
        }
        def _replace_in_brackets(m: re.Match) -> str:
            content = m.group(1)
            for r64, r32 in _R64_TO_R32.items():
                content = re.sub(rf'\b{r64}\b', r32, content, flags=re.I)
            return '[' + content + ']'
        text = re.sub(r'\[([^\]]+)\]', _replace_in_brackets, text)
        try:
            enc, _ = self.ks.asm(text)
            return bytes(enc)
        except KsError as e:
            if self.verbose:
                print(f"    [asm error] {text!r}: {e}")
            return b'\xCC'

    def _asm(self, text: str) -> bytes:
        """Assemble x86-64 text using Keystone, return bytes."""
        text = self._normalize_x64_asm(text)
        try:
            enc, _ = self.ks.asm(text)
            return bytes(enc)
        except KsError as e:
            if self.verbose:
                print(f"    [asm error] {text!r}: {e}")
            return b'\xCC'   # INT3 — clearly wrong, easy to spot in debugger

    def _emit_ff15_iat_call(self, out: bytearray, at_off: int,
                            old_iat_va: int, span: int = 15) -> bool:
        """Overwrite ``span`` bytes at ``at_off`` with ``call [IAT]`` (+ NOP pad)."""
        if span < 6 or at_off < 0 or at_off + span > len(out):
            return False
        iat_va = self._resolve_iat_slot_va(old_iat_va)
        call_rva = self.text_rva + at_off
        rel = iat_va - (self.new_base + call_rva + 6)
        if not (-2147483648 <= rel <= 2147483647):
            return False
        patch = b'\xff\x15' + struct.pack('<i', rel) + b'\x90' * (span - 6)
        out[at_off:at_off + span] = patch
        return True
