"""Import address table dispatch and thunk construction.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class IatMixin:
    """See the module docstring."""

    def _is_iat_rva(self, imm32: int) -> bool:
        old_rva = (imm32 - self.old_base) if imm32 >= self.old_base else imm32
        return old_rva in self._iat_rva_map or old_rva in self._iat_old_rvas

    def _iat_name_at(self, iat_va: int) -> str:
        old_rva = (iat_va - self.old_base) if iat_va >= self.old_base else (iat_va & 0xFFFFFFFF)
        return self._iat_func_by_rva.get(old_rva, '')

    def _getenv_size_imm_from_args(self, args, insns, insn_idx: int) -> Optional[int]:
        """Return the nSize immediate for a GetEnvironmentVariable* call, if known."""
        if len(args) < 3:
            return None
        atype, aval = args[2]
        if atype == 'imm':
            return aval & 0xFFFFFFFF
        if atype != 'reg':
            return None
        # Walk backwards for ``mov <reg>, imm`` that loaded the size.
        for j in range(insn_idx - 1, max(-1, insn_idx - 24), -1):
            ins = insns[j]
            if ins.mnemonic != 'mov' or len(ins.operands) != 2:
                continue
            if (ins.operands[0].type == X86_OP_REG
                    and ins.operands[0].reg == aval
                    and ins.operands[1].type == X86_OP_IMM):
                return ins.operands[1].imm & 0xFFFFFFFF
            if ins.mnemonic == 'call':
                break
        return None

    #: When GetEnvironmentVariable reports buffer-too-small (return >= nSize),
    #: force eax=0 so existing ``test eax; jz not_found`` paths stay safe.
    #: Do NOT silently raise nSize: call sites use fixed buffers of different
    #: lengths, and overflowing them corrupts the heap.

    def _emit_getenv_buf_too_small_guard(
            self, out: bytearray, args, insns, insn_idx: int,
            iat_va: int) -> None:
        """After GetEnvironmentVariable*, treat buffer-too-small as not-found.

        The API returns the *required* size (non-zero, ``>= nSize``) when the
        buffer cannot hold the value.  Existing Win32 code typically only
        tests ``eax != 0`` and then reads the buffer — which is undefined in
        that case.  Forcing eax to zero when ``eax >= nSize`` restores the
        "not found / fail" branch instead of consuming an undefined buffer.
        """
        name = self._iat_name_at(iat_va)
        if name not in (
                'GetEnvironmentVariableA', 'GetEnvironmentVariableW',
                'GetEnvironmentVariable'):
            return
        cap = self._getenv_size_imm_from_args(args, insns, insn_idx)
        if not cap or cap > 0x100000:
            return
        out += self._asm(f'cmp eax, 0x{cap:x}')
        out += b'\x72\x02'          # jb +2 — keep eax when eax < nSize
        out += self._asm('xor eax, eax')

    def _resolve_import_iat_va(self, func_name: str) -> int:
        """Map an x86 import name to its loader-resolved PE64 .idata thunk VA."""
        for old_rva, name in self._iat_func_by_rva.items():
            if name == func_name:
                return self._resolve_iat_slot_va(self.old_base + old_rva)
        return 0

    def _loader_iat_va(self, dll: str, func_name: str) -> int:
        """Import-directory IAT cell VA (loader-patched), not merged .text copy."""
        rva = self._iat_name_to_new_rva.get((dll.lower(), func_name), 0)
        return self.new_base + rva if rva else 0

    def _ff25_iat_slot_at_rva(self, rva: int) -> Optional[int]:
        """If *rva* is an x86 ``jmp dword ptr [abs]`` import tail, return its IAT slot VA."""
        data = self.pe.read_rva(rva, 6)
        if not data or len(data) < 6 or data[:2] != b'\xff\x25':
            return None
        return struct.unpack_from('<I', data, 2)[0]

    def _resolve_iat_slot_va(self, iat_va: int) -> int:
        """Map x86 IAT slot VA (often merged into .text) to PE64 .idata slot."""
        old_rva = self._imm_to_old_rva(iat_va)
        if self._iat_rva_map:
            if old_rva in self._iat_rva_map:
                res = self.new_base + self._iat_rva_map[old_rva]
                self._dbg_seh_iat(iat_va, old_rva, res)
                return res
            old_iat = self._old_iat_for_slot_rva(old_rva)
            if old_iat is not None:
                return self.new_base + self._iat_rva_map[old_iat]
            # Slot missing from the per-slot map (late rematerialization
            # chunks emit after the planner ran): resolve by import NAME.
            # cmd 0x4AD01140 (FormatMessageW) fell back to _relocate_imm →
            # a .data mirror slot holding 0 → ``call rbx`` with RBX=0.
            name = self._iat_func_by_rva.get(old_rva, '')
            name_map = getattr(self, '_iat_name_to_new_rva', None) or {}
            if name and name_map:
                for (_dll, fn), rva in name_map.items():
                    if str(fn).lower() == str(name).lower():
                        return self.new_base + int(rva)
        return self._relocate_imm(iat_va & 0xFFFFFFFF, 0, 0)

    def _dbg_seh_iat(self, iat_va: int, old_rva: int, res: int) -> None:
        """DEBUG: log resolution of SEH-family IAT slots to find misrouting."""
        if os.environ.get('DBG_SEH_IAT') and 0x125C <= old_rva <= 0x1288:
            import traceback
            caller = traceback.extract_stack(limit=6)[-3]
            print(f"[SEH-IAT] iat_va=0x{iat_va:X} old_rva=0x{old_rva:X} "
                  f"-> slot=0x{res & 0xFFFFFFFF:X} caller={caller.name}",
                  flush=True)

    def _old_iat_for_slot_rva(self, slot_rva: int,
                              text_rva: int = 0) -> Optional[int]:
        """Map a PE64 .text slot RVA back to its x86 IAT thunk RVA."""
        if slot_rva in self._iat_old_rvas and slot_rva in self._iat_rva_map:
            return slot_rva
        for old_iat in self._iat_old_rvas:
            if old_iat not in self._iat_rva_map:
                continue
            if text_rva and slot_rva == old_iat + text_rva:
                return old_iat
            code_rva = self._final_rva.get(old_iat)
            if code_rva == slot_rva:
                return old_iat
        return None

    def _plan_iat_map_early(self, idata_rva: int = 0) -> None:
        """Pre-compute _iat_rva_map before translation so _emit_iat_call
        can resolve to correct x64 IAT slots immediately (avoids the
        linear-section-offset fallback that breaks cross-DLL redirects).

        When *idata_rva* is provided (from ``_estimate_idata_rva``), the
        map uses a realistic layout position.  The zero fallback preserves
        backward compatibility with the legacy 0x10000 placeholder."""
        imports = self.pe.parse_imports()
        if self.win10_test_shim:
            imports = transform_imports(imports)
        if not imports:
            self._iat_rva_map = {}
            return
        if not idata_rva:
            idata_rva = 0x10000  # legacy fallback
        self._iat_rva_map = self._plan_import_iat_map(idata_rva)
        self._iat_rva_map_placeholder_base = idata_rva

    def _shift_iat_refs_by_delta(self, code: bytes, text_rva: int,
                                  delta: int,
                                  only_slots: Optional[Set[int]] = None) -> Tuple[bytes, int]:
        """Shift all FF 15 / FF 25 IAT references and movabs IAT addresses
        by *delta*.
        
        Called after the real idata_rva is known to adjust code emitted with
        the placeholder _iat_rva_map to the final layout.

        ``only_slots`` (pre-shift IAT slot RVAs) restricts the movabs branch
        to genuine IAT references.  Without it, every movabs whose imm lands
        in the new-base range gets shifted — including predefined handle
        constants (HKCU 0x80000001 → 0x8007F001), data pointers and function
        entry VAs — and later passes only repair data/code pointers, so the
        handle constants stay corrupted (cmd RegOpenKeyExW(HKCU) faults)."""
        if not delta:
            return code, 0
        out = bytearray(code)
        patched = 0
        i = 0
        while i < len(out) - 6:
            if out[i:i + 2] == b'\xff\x15' or out[i:i + 2] == b'\xff\x25':
                # FF 15 (call [IAT]) / FF 25 (jmp [IAT]): shift target slot_rva
                rel = struct.unpack_from('<i', out, i + 2)[0]
                call_rva = text_rva + i
                slot_rva = call_rva + 6 + rel
                new_slot_rva = slot_rva + delta
                new_rel = new_slot_rva - (call_rva + 6)
                if -2147483648 <= new_rel <= 2147483647:
                    struct.pack_into('<i', out, i + 2, new_rel)
                    patched += 1
                i += 6
                continue
            
            # mov r64, imm64: REX.W (0x48 or 0x49) + opcode 0xB8-0xBF
            if (out[i] & 0xFE) == 0x48 and 0xB8 <= out[i + 1] <= 0xBF \
                    and i + 10 <= len(out):
                # movabs r64, <IAT_VA>: shift the embedded absolute address
                slot_va = struct.unpack_from('<Q', out, i + 2)[0]
                # Only shift when the imm is a known pre-shift IAT slot.
                # Header-range values (< .text RVA) are predefined constants
                # (HKEY_* roots, 0xFFFFFFFF) and must never shift.
                if only_slots is not None:
                    is_slot = (slot_va - self.new_base) in only_slots
                else:
                    is_slot = (self.new_base <= slot_va
                               < self.new_base + 0x200000)
                if is_slot:
                    new_slot_va = slot_va + delta
                    struct.pack_into('<Q', out, i + 2, new_slot_va)
                    patched += 1
                i += 10
                continue
            
            i += 1
        return bytes(out), patched

    def _plan_import_iat_map(self, idata_rva: int) -> Dict[int, int]:
        """old IAT thunk RVA → new IAT thunk RVA (same layout as _build_import_directory)."""
        imports = self.pe.parse_imports()
        if self.win10_test_shim:
            imports = transform_imports(imports)
        if not imports:
            return {}
        desc_bytes = (len(imports) + 1) * 20
        cursor = (desc_bytes + 7) & ~7
        layouts: List[Dict] = []
        for imp in imports:
            nfuncs = len(imp['functions'])
            cursor = (cursor + 7) & ~7
            ilt_off = cursor
            cursor += (nfuncs + 1) * 8
            iat_off = cursor
            cursor += (nfuncs + 1) * 8
            name_off = cursor
            dll_name = imp['dll'].encode('ascii') + b'\x00'
            cursor += len(dll_name)
            func_entries: List[Tuple[Dict, Optional[int]]] = []
            for fn in imp['functions']:
                if fn.get('name'):
                    hint_off = cursor
                    cursor += 2 + len(fn['name'].encode('ascii')) + 1
                    func_entries.append((fn, hint_off))
                else:
                    func_entries.append((fn, None))
            layouts.append({
                'iat_off': iat_off,
                'func_entries': func_entries,
            })
        iat_map: Dict[int, int] = {}
        self._hint_rva_to_old_iat: Dict[int, int] = {}
        self._iat_name_to_new_rva = {}
        for imp, lay in zip(imports, layouts):
            dll = imp['dll'].lower()
            for fn_idx, (fn, hint_off) in enumerate(lay['func_entries']):
                new_rva = idata_rva + lay['iat_off'] + fn_idx * 8
                name = fn.get('name')
                if name:
                    self._iat_name_to_new_rva[(dll, name)] = new_rva
                old_rva = fn.get('iat_rva', 0)
                if old_rva:
                    iat_map[old_rva] = new_rva
                    if hint_off is not None:
                        self._hint_rva_to_old_iat[idata_rva + hint_off] = old_rva
        # DEBUG: log shim IAT mappings near 0x12DC
        for k, v in sorted(iat_map.items()):
            if 0x12D0 <= k <= 0x12E8:
                print(f"        [IAT MAP] x86 0x{k:04X} -> x64 0x{v:04X}")
        return iat_map

    def _old_iat_va_for_idata_cell(self, cell_va: int) -> Optional[int]:
        """Map a merged ``.idata`` pointer cell VA to its x86 IAT slot VA."""
        cell_rva = cell_va - self.new_base
        old_rva = self._old_iat_for_slot_rva(cell_rva, self.text_rva or 0)
        if old_rva is not None:
            return self.old_base + old_rva
        idata = getattr(self, '_idata_blob', b'')
        idata_rva = getattr(self, '_idata_rva', 0)
        off = cell_rva - idata_rva
        if idata and 0 <= off <= len(idata) - 8:
            hint_rva = struct.unpack_from('<Q', idata, off)[0]
            old_rva = self._hint_rva_to_old_iat.get(hint_rva)
            if old_rva:
                return self.old_base + old_rva
        return None

    def _patch_ff15_iat_calls_in_code(self, code: bytes, text_rva: int) -> Tuple[bytes, int]:
        """Re-resolve ``call [IAT]`` (FF 15) once _iat_rva_map is final."""
        if not self._iat_rva_map:
            return code, 0
        out = bytearray(code)
        rev_map = {v: k for k, v in self._iat_rva_map.items()}
        patched = 0
        i = 0
        while i < len(out) - 6:
            if out[i:i + 2] != b'\xff\x15':
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            call_rva = text_rva + i
            slot_rva = call_rva + 6 + rel
            old_iat = rev_map.get(slot_rva)
            if old_iat is None:
                for new_rva, old_rva in rev_map.items():
                    if new_rva == slot_rva or new_rva == (slot_rva & ~7):
                        old_iat = old_rva
                        break
            if old_iat is not None and old_iat in self._iat_rva_map:
                new_slot_rva = self._iat_rva_map[old_iat]
                new_rel = new_slot_rva - (call_rva + 6)
                if new_rel != rel:
                    struct.pack_into('<i', out, i + 2, new_rel)
                    patched += 1
            i += 6
        return bytes(out), patched

    def _patch_iat_jmps_in_code(self, code: bytes, text_rva: int) -> Tuple[bytes, int]:
        """Fix FF 25 IAT tail jumps emitted before _iat_rva_map was planned."""
        if not self._iat_rva_map:
            return code, 0
        out = bytearray(code)
        patched = 0
        i = 0
        while i < len(out) - 6:
            if out[i:i + 2] != b'\xff\x25':
                i += 1
                continue
            rel = struct.unpack_from('<i', out, i + 2)[0]
            instr_rva = text_rva + i
            slot_rva = instr_rva + 6 + rel
            old_iat = self._old_iat_for_slot_rva(slot_rva, text_rva)
            if old_iat is not None:
                new_slot_rva = self._iat_rva_map[old_iat]
                new_rel = new_slot_rva - (instr_rva + 6)
                if new_rel != rel:
                    struct.pack_into('<i', out, i + 2, new_rel)
                    patched += 1
            elif self._runtime_slot_map:
                for old_slot, new_slot in self._runtime_slot_map.items():
                    if slot_rva not in (old_slot, old_slot + text_rva):
                        continue
                    new_rel = new_slot - (instr_rva + 6)
                    if new_rel != rel:
                        struct.pack_into('<i', out, i + 2, new_rel)
                        patched += 1
                    break
            i += 6
        return bytes(out), patched

    def _patch_movabs_iat_in_code(self, code: bytes,
                                   text_rva: int) -> Tuple[bytes, int]:
        """Universal fix: shift ALL MSVCRT→shim IAT references by +8 to
        correct a systemic translator off-by-one (-8) bug.

        The bug affects ALL shim-redirected MSVCRT imports (x86 IAT slots
        0x11D4-0x12EC).  We shift every reference to the next slot.
        Slots where runtime evidence proves the translator emits the
        correct value are excluded to avoid false positives.

        NOTE (build 359): IAT-SHIFT tracing proved the translator now emits
        ALL shim-slot refs at their correct x64 slots (setjmp3 at s11,
        except_handler3 at s10, longjmp at s6, _adjust_fdiv at s14, ...).
        The +8 shift is a leftover from an older emission bug and corrupts
        correctly-emitted refs — including NON-shim MSVCRT refs whose x64
        slots are packed differently (wcslen at 0xA5308 etc.).  Disabled.
        """
        return code, 0
        if not self._iat_rva_map:
            return code, 0
        out = bytearray(code)
        rev_map: Dict[int, int] = {v: k for k, v in self._iat_rva_map.items()}
        # All MSVCRT IAT entries — the off-by-one affects every shim redirect
        BROKEN_X86_RANGE = range(0x11D4, 0x12EC)
        # Verified correct by runtime: these must NOT be shifted
        CORRECT_SLOTS = {
            0x1260,  # _except_handler3 (SEH dispatch)
            0x1264,  # _setjmp3 (CRT error recovery)
            0x11D4,  # longjmp (CRT error recovery)
            0x1284,  # _seh_longjmp_unwind (SEH frame unwinding)
        }
        patched = 0
        i = 0
        while i < len(out) - 10:
            if (out[i] & 0xFE) != 0x48 or not (0xB8 <= out[i + 1] <= 0xBF):
                i += 1
                continue
            if i + 10 > len(out):
                break
            slot_va = struct.unpack_from('<Q', out, i + 2)[0]
            slot_rva = slot_va - self.new_base
            old_iat_cur = rev_map.get(slot_rva)
            if old_iat_cur is None or old_iat_cur not in BROKEN_X86_RANGE:
                i += 10
                continue
            if old_iat_cur in CORRECT_SLOTS:
                i += 10
                continue
            # Shift to next slot — fixes the systemic -8 offset
            next_rva = slot_rva + 8
            if next_rva in rev_map:
                correct_va = self.new_base + next_rva
                struct.pack_into('<Q', out, i + 2, correct_va)
                patched += 1
                if os.environ.get('DBG_IAT_SHIFT') and (
                        0x11D0 <= old_iat_cur <= 0x12F0):
                    print(f"[IAT-SHIFT] old_iat=0x{old_iat_cur:X} "
                          f"from=0x{slot_rva:X} to=0x{next_rva:X} "
                          f"@text+0x{i:X}", flush=True)
            elif os.environ.get('DBG_IAT_SHIFT') and (
                    0x11D0 <= old_iat_cur <= 0x12F0):
                print(f"[IAT-SHIFT] NO next slot for old_iat=0x{old_iat_cur:X} "
                      f"from=0x{slot_rva:X} @text+0x{i:X}", flush=True)
            i += 10
        # Summary of where SEH-family refs currently sit (pre-shift state
        # is gone; log the shifted state).
        if os.environ.get('DBG_IAT_SHIFT'):
            for probe in (0x1260, 0x1264, 0x1284, 0x11D4):
                probe_rva = self._iat_rva_map.get(probe)
                if probe_rva is not None:
                    probe_va = self.new_base + probe_rva
                    cnt = out.count(struct.pack('<Q', probe_va))
                    print(f"[IAT-SHIFT] final refs at slot of 0x{probe:X} "
                          f"(0x{probe_va & 0xFFFFFFFF:X}): {cnt}", flush=True)
        return bytes(out), patched

    def _build_import_directory(self, idata_rva: int) -> Tuple[bytes, int]:
        """Build PE64 import directory (descriptors + ILT + IAT + names + hints)."""
        imports = self.pe.parse_imports()
        if self.win10_test_shim:
            imports = transform_imports(imports)
        if not imports:
            return b'', 0

        # Pass 1 — compute final layout with descriptors at the front.
        desc_bytes = (len(imports) + 1) * 20
        cursor = (desc_bytes + 7) & ~7
        layouts: List[Dict] = []

        for imp in imports:
            nfuncs = len(imp['functions'])
            cursor = (cursor + 7) & ~7
            ilt_off = cursor
            cursor += (nfuncs + 1) * 8
            iat_off = cursor
            cursor += (nfuncs + 1) * 8
            name_off = cursor
            dll_name = imp['dll'].encode('ascii') + b'\x00'
            cursor += len(dll_name)

            func_entries: List[Tuple[Dict, Optional[int]]] = []
            for fn in imp['functions']:
                if fn.get('name'):
                    hint_off = cursor
                    cursor += 2 + len(fn['name'].encode('ascii')) + 1
                    func_entries.append((fn, hint_off))
                else:
                    func_entries.append((fn, None))

            layouts.append({
                'ilt_off': ilt_off,
                'iat_off': iat_off,
                'name_off': name_off,
                'dll_name': dll_name,
                'func_entries': func_entries,
            })

        # Pass 2 — emit .idata with RVAs that match the final layout.
        blob = bytearray(cursor)

        for idx, lay in enumerate(layouts):
            struct.pack_into(
                '<IIIII', blob, idx * 20,
                idata_rva + lay['ilt_off'],
                0, 0,
                idata_rva + lay['name_off'],
                idata_rva + lay['iat_off'],
            )

        for lay in layouts:
            blob[lay['name_off']:lay['name_off'] + len(lay['dll_name'])] = lay['dll_name']
            for fn_idx, (fn, hint_off) in enumerate(lay['func_entries']):
                if hint_off is not None:
                    hint_rva = idata_rva + hint_off
                    entry = (struct.pack('<H', fn.get('hint', 0))
                             + fn['name'].encode('ascii') + b'\x00')
                    blob[hint_off:hint_off + len(entry)] = entry
                    struct.pack_into('<Q', blob, lay['ilt_off'] + fn_idx * 8, hint_rva)
                    struct.pack_into('<Q', blob, lay['iat_off'] + fn_idx * 8, hint_rva)
                else:
                    ordinal = 0x8000000000000000 | (fn['ordinal'] & 0xFFFF)
                    struct.pack_into('<Q', blob, lay['ilt_off'] + fn_idx * 8, ordinal)
                    struct.pack_into('<Q', blob, lay['iat_off'] + fn_idx * 8, ordinal)

        return bytes(blob), idata_rva

