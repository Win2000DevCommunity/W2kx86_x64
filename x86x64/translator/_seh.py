"""Structured exception handling: VC6 scope tables and handler fixups.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class SehMixin:
    """See the module docstring."""

    def _seh_rbp_local_disp(self, disp: int, seh_active: bool) -> int:
        """Map x86 [EBP-N] slots below the SEH record for 8-byte x64 pushes."""
        if disp > 0x7FFFFFFF:
            disp -= 0x100000000
        if not seh_active:
            return disp
        if disp == -4:
            return -8
        if disp < -4:
            return disp - 0x10
        return disp

    def _find_scope_reloc_sled(self, out: bytearray, need: int,
                               avoid: int) -> Optional[int]:
        """Find ``need`` bytes for a relocated scope table (zeros/NOPs)."""
        if need <= 0 or need > len(out):
            return None
        best = None
        run = 0
        start = 0
        for i, b in enumerate(out):
            if b in (0x00, 0x90, 0xCC):
                if run == 0:
                    start = i
                run += 1
                if run >= need and start != avoid:
                    return start
            else:
                if run >= need and start != avoid:
                    return start
                run = 0
                start = 0
        if run >= need and start != avoid:
            return start
        tail = len(out) - need
        if tail > avoid + need or tail < avoid:
            if all(out[tail + k] in (0x00, 0x90, 0xCC) for k in range(need)):
                return tail
        return best

    def _scope_handler_dword(self, val: int) -> int:
        """Normalize MSVC scope-table handler slot (0 = catch block at ``end``)."""
        if val == 0:
            return 0
        if val in (0xFFFFFFFF, 0xFFFFFFFE):
            return 0
        if (self.win10_test_shim and self._w2k_eh3_va
                and val in self._seh_eh3_handler_old_vas):
            return 0
        if (self.win10_test_shim and self._w2k_eh3_va
                and val == (self._w2k_eh3_va & 0xFFFFFFFF)):
            return 0
        return val

    def _normalize_scope_table_handlers(self, out: bytearray) -> int:
        """Force scope handler DWORDs to MSVC semantics (0 = catch at end, not eh3/-1)."""
        if not self.win10_test_shim:
            return 0
        fixed = 0
        ranges: List[Tuple[int, int]] = list(self._scope_table_out_ranges)
        known = {s for s, _ in ranges}
        pos = 0
        while pos < len(out) - 19:
            if out[pos:pos + 4] != b'\xff\xff\xff\xff':
                pos += 1
                continue
            if not self._valid_scope_sentinel(out, pos):
                pos += 1
                continue
            if pos not in known:
                ranges.append((pos, 64))
                known.add(pos)
            pos += 4
        for start, size in ranges:
            if start + 4 > len(out) or out[start:start + 4] != b'\xff\xff\xff\xff':
                continue
            rec = start + 4
            end = min(start + size, len(out) - 15)
            while rec + 16 <= end:
                begin, end_va, _filt, handler = struct.unpack_from('<4I', out, rec)
                if not (begin < end_va):
                    break
                if not self._valid_scope_record_begin_end(begin, end_va):
                    break
                new_h = self._scope_handler_dword(handler)
                if new_h != handler:
                    struct.pack_into('<I', out, rec + 12, new_h)
                    fixed += 1
                rec += 16
        return fixed

    def _valid_scope_record_begin_end(self, begin: int, end_va: int) -> bool:
        img_end = self.old_base + self.pe.image_size
        shim_end = self.new_base + 0x01000000
        x86_ok = (self.old_base <= begin < img_end
                  and self.old_base < end_va <= img_end)
        shim_ok = (self.new_base <= begin < shim_end
                   and self.new_base < end_va <= shim_end)
        # Reject EH3 filter/handler pairs misread as EH4 begin/end (cmd
        # 0x1a88: filter..handler span is 4 bytes).  Those must be
        # synthesized into a real function try range — treating them as
        # valid left SEH pushes aimed at a 4-byte island and exceptions
        # in the real body fell through to execute @ garbage / 4.
        if not (begin < end_va) or (end_va - begin) <= 8:
            return False
        return x86_ok or shim_ok

    def _valid_scope_filt_handler(self, filt: int, handler: int) -> bool:
        """Filter/handler: code VA, PE64 VA, zero, or small EH disposition const.

        Rejects UTF-16 false positives (e.g. ``0x2A002E`` = ``.*``) that sit
        after a coincidental ``FF FF FF FF`` in embedded wchar literals.
        """
        img_end = self.old_base + self.pe.image_size
        shim_end = self.new_base + 0x01000000

        def _ok(val: int) -> bool:
            if val == 0 or val >= 0xFFFFFFFE or val <= 0xFFFF:
                return True
            if self.old_base <= val < img_end:
                return True
            if self.new_base <= val < shim_end:
                return True
            return False

        return _ok(filt) and _ok(handler)

    def _valid_scope_sentinel(self, out: bytearray, off: int) -> bool:
        if off + 20 > len(out) or out[off:off + 4] != b'\xff\xff\xff\xff':
            return False
        begin, end_va, filt, handler = struct.unpack_from('<4I', out, off + 4)
        if not self._valid_scope_record_begin_end(begin, end_va):
            return False
        if not self._valid_scope_filt_handler(filt, handler):
            return False
        # Leftover x86 image VAs cannot match PE64 exception RIPs — treat as
        # invalid so synthesize rebuilds a private function-wide table
        # (cmd SEH frames after rematerialize restored raw 0x4adxxxxx ranges).
        img_end = self.old_base + self.pe.image_size
        if (self.old_base <= begin < img_end
                or self.old_base <= end_va < img_end):
            return False
        return True

    def _synthesize_seh_scopes_for_push_sites(self, out: bytearray,
                                              text_rva: int) -> int:
        """Build real MSVC scope records for SEH push sites (x86 tail blobs are often wrong)."""
        if not self.win10_test_shim:
            return 0
        gs_restore = (
            bytes([0xC7, 0x45, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF])
            + bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0])
        )
        synthesized = 0
        i = 0
        while i < len(out) - 14:
            if not (out[i] == 0x6A and out[i + 1] == 0xFF
                    and out[i + 2] == 0x48 and out[i + 3] == 0xB8):
                i += 1
                continue
            scope_imm = struct.unpack_from('<Q', out, i + 4)[0]
            scope_off = scope_imm - self.new_base - text_rva
            if scope_off < 0 or scope_off + 20 > len(out):
                i += 14
                continue
            fn_off = self._fn_blob_off_from_push(out, i)
            # Keep rematerialized x86 EH3 tables (filt/handler may be small
            # disposition constants). Only synthesize when the push still
            # aims at garbage / UTF-16 / a try range that does not belong to
            # this function (cmd several SEH frames shared one scavenged
            # table whose begin/end pointed into a different CRT helper).
            keep = False
            if (out[scope_off:scope_off + 4] == b'\xff\xff\xff\xff'
                    and self._valid_scope_sentinel(out, scope_off)):
                begin_chk = struct.unpack_from('<I', out, scope_off + 4)[0]
                begin_off = int(begin_chk - self.new_base - text_rva)
                if fn_off <= begin_off < fn_off + 0x10000:
                    keep = True
            if keep:
                i += 14
                continue
            setup_end = i
            for fwd in range(i, min(len(out), i + 96)):
                if (out[fwd:fwd + 9] == bytes([0x65, 0x48, 0x89, 0x24, 0x25, 0, 0, 0, 0])
                        and fwd + 12 < len(out) and out[fwd + 9] == 0x48
                        and out[fwd + 10] == 0x83 and out[fwd + 11] == 0xEC):
                    setup_end = fwd + 12 + out[fwd + 12]
                    break
            restore_off = out.find(gs_restore, fn_off, min(len(out), fn_off + 0x8000))
            if restore_off < 0:
                epilog = out.find(b'\x5f\x5e\x5b\x48\x89\xec\x5d\xc3', fn_off,
                                  min(len(out), fn_off + 0x8000))
                restore_off = epilog if epilog >= 0 else min(len(out), fn_off + 0x100)
            begin_va = (self.new_base + text_rva + setup_end) & 0xFFFFFFFF
            end_va = (self.new_base + text_rva + restore_off) & 0xFFFFFFFF
            if begin_va >= end_va:
                i += 14
                continue
            # Handler slot 0 => _except_handler3 uses ``end`` as the catch label.
            # Trailing zero record: out-of-range try levels never match a range.
            scope_blob = (b'\xff\xff\xff\xff'
                          + struct.pack('<IIII', begin_va, end_va, 0, 0)
                          + struct.pack('<IIII', 0, 0, 0, 0))
            # Always append a *private* table and retarget this push.  In-place
            # overwrite of a scavenged shared blob (cmd several SEH frames all
            # pointed at 0x48630) left every frame with the last writer's
            # begin/end — exceptions then dispatched with a stale RIP.
            pad = (4 - (len(out) % 4)) % 4
            if pad:
                out += b'\x00' * pad
            new_off = len(out)
            out += scope_blob
            new_imm = (self.new_base + text_rva + new_off) & 0xFFFFFFFFFFFFFFFF
            struct.pack_into('<Q', out, i + 4, new_imm)
            self._scope_table_out_ranges.append((new_off, len(scope_blob)))
            synthesized += 1
            i += 14
        return synthesized

    def _force_rematerialize_scope_tables(
            self, out: bytearray, rva_map: Dict[int, int],
            text_data: bytes, text_rva: int) -> int:
        """Append every MSVC EH3 scope table as a raw relocated blob.

        Identity/1:1 maps from embedded-data heals often point SEH ``push``
        targets at UTF-16 or mistranslated code. Rebuild tables at the end of
        ``.text`` and retarget ``rva_map`` so reconcile lands on real
        ``ff ff ff ff`` sentinels with the original begin/end records.

        Prefer RVAs from SEH ``push -1; push scope`` sites (anchors) so
        tables that abut UTF-16 literals are still rematerialized.
        """
        if text_data is None or self.pe is None:
            return 0
        targets: Dict[int, int] = {}
        for start_rva, size in _scope_table_spans(text_data, text_rva, self.pe):
            targets[start_rva] = size
        for scope_rva in (self._seh_scope_anchors or {}):
            if scope_rva in targets:
                continue
            off = scope_rva - text_rva
            if off < 0 or off + 4 > len(text_data):
                continue
            if text_data[off:off + 4] != b'\xff\xff\xff\xff':
                continue
            size = _msvc_scope_table_size(self.pe, text_data, text_rva, off)
            targets[scope_rva] = size if size >= 20 else 20
        remat = 0
        for start_rva, size in sorted(targets.items()):
            off = start_rva - text_rva
            if off < 0 or off + size > len(text_data):
                continue
            raw = bytearray(text_data[off:off + size])
            if raw[:4] != b'\xff\xff\xff\xff':
                continue
            # Sanitize filter/handler slots that are UTF-16 bleed from the
            # adjacent string blob (cmd packs literals right after try ranges).
            img_end = self.old_base + self.pe.image_size
            pos = 4
            while pos + 16 <= len(raw):
                begin, end, filt, handler = struct.unpack_from('<4I', raw, pos)
                if not (self.old_base <= begin < img_end
                        and self.old_base < end <= img_end and begin < end):
                    break
                if filt > 0xFFFF and not (self.old_base <= filt < img_end):
                    struct.pack_into('<I', raw, pos + 8, 0)
                    filt = 0
                if (handler not in (0, 0xFFFFFFFF, 0xFFFFFFFE)
                        and handler > 0xFFFF
                        and not (self.old_base <= handler < img_end)):
                    struct.pack_into('<I', raw, pos + 12, 0)
                pos += 16
            xbegin, xend = struct.unpack_from('<II', raw, 4)
            mapped = rva_map.get(start_rva)
            ok = False
            if (mapped is not None and mapped + 12 <= len(out)
                    and out[mapped:mapped + 4] == b'\xff\xff\xff\xff'):
                obegin, oend = struct.unpack_from('<II', out, mapped + 4)
                if (obegin, oend) == (xbegin, xend):
                    ok = True
                elif self._scope_sentinel_matches_x86(out, mapped, start_rva):
                    ok = True
            if ok and self._valid_scope_sentinel(out, mapped):
                self._scope_table_old_rva[mapped] = start_rva
                if not any(s == mapped for s, _ in self._scope_table_out_ranges):
                    self._scope_table_out_ranges.append((mapped, size))
                # Still relocate begin/end — a prior copy may have left x86 VAs.
                fn_off = self._seh_scope_reg_fn.get(start_rva)
                self._patch_scope_table_entries(out, mapped, size, start_rva, fn_off)
                continue
            for r in range(start_rva, start_rva + size):
                rva_map.pop(r, None)
            pad = (4 - len(out) % 4) % 4
            if pad:
                out += b'\x00' * pad
            base = len(out)
            out += raw
            pad2 = (4 - len(out) % 4) % 4
            if pad2:
                out += b'\x00' * pad2
            for i in range(size):
                rva_map[start_rva + i] = base + i
            self._scope_table_out_ranges.append((base, size))
            self._scope_table_old_rva[base] = start_rva
            self._orphan_blob_out_ranges.append((base, size))
            fn_off = self._seh_scope_reg_fn.get(start_rva)
            self._patch_scope_table_entries(out, base, size, start_rva, fn_off)
            remat += 1
        return remat

    def _retarget_seh_pushes_from_anchors(self, out: bytearray,
                                          rva_map: Dict[int, int],
                                          text_rva: int) -> int:
        """Point each SEH ``push -1; movabs scope`` at its rematerialized table.

        Uses x86 ``push`` site RVAs from ``_seh_scope_anchors`` so we never
        scavenge UTF-16 ``FF FF FF FF`` false positives.
        """
        if not self._seh_scope_anchors:
            return 0
        fixed = 0
        for scope_old, push_x86 in self._seh_scope_anchors.items():
            base = self._materialized_scope_base(scope_old)
            if base is None or not self._valid_scope_sentinel(out, base):
                continue
            hint = rva_map.get(push_x86)
            if hint is None:
                # try nearby x86 bytes of the push
                for d in range(0, 8):
                    hint = rva_map.get(push_x86 + d)
                    if hint is not None:
                        break
            if hint is None:
                continue
            new_imm = self.new_base + text_rva + base
            for delta in range(-32, 64):
                i = hint + delta
                if i < 0 or i + 14 > len(out):
                    continue
                if not (out[i] == 0x6A and out[i + 1] == 0xFF
                        and out[i + 2] == 0x48 and out[i + 3] == 0xB8):
                    continue
                imm = struct.unpack_from('<Q', out, i + 4)[0]
                if imm != new_imm:
                    struct.pack_into('<Q', out, i + 4, new_imm)
                    fixed += 1
                self._record_seh_scope_reg_fn(out, scope_old, i)
                self._scope_table_old_rva[base] = scope_old
                break
        return fixed

    def _restore_materialized_scope_tables(self, out: bytearray,
                                           text_rva: int) -> int:
        """Re-copy x86 scope tables clobbered by init-tail stub neutralization."""
        if not self.win10_test_shim or not self._scope_table_old_rva:
            return 0
        sec = self.pe.section_for_rva(self.text_rva)
        if not sec:
            return 0
        text_data = self.pe.get_section_data(sec)
        restored = 0
        for base, old_rva in sorted(self._scope_table_old_rva.items()):
            if base + 16 > len(out):
                continue
            off = old_rva - self.text_rva
            if off < 0 or off + 4 > len(text_data):
                continue
            if text_data[off:off + 4] != b'\xff\xff\xff\xff':
                continue
            size = _msvc_scope_table_size(self.pe, text_data, self.text_rva, off)
            raw = text_data[off:off + size]
            if base + len(raw) > len(out):
                continue
            out[base:base + len(raw)] = raw
            fn_off = self._fn_blob_off_from_push(out, base)
            self._patch_scope_table_entries(out, base, len(raw), old_rva, fn_off)
            restored += 1
        return restored

    def _scope_va_to_pe64(self, va: int, scope_old_rva: Optional[int] = None,
                          fn_blob_off: Optional[int] = None) -> int:
        """Map x86 code VAs in SEH scope tables via the registering function."""
        va &= 0xFFFFFFFF
        img_end = self.old_base + self.pe.image_size
        if not (self.old_base <= va < img_end):
            return va
        old_rva = va - self.old_base
        if scope_old_rva is not None:
            fn_off = fn_blob_off
            if fn_off is None:
                fn_off = self._seh_scope_reg_fn.get(scope_old_rva)
            fn_rva = self._seh_scope_anchors.get(scope_old_rva)
            if fn_off is not None and fn_rva is not None:
                old_sec = self._rva_section.get(fn_rva, self.text_rva)
                new_sec = self._old_to_new_section.get(old_sec, old_sec)
                return (self.new_base + new_sec + fn_off
                        + (old_rva - fn_rva))
            if fn_rva is not None and fn_rva in self.rva_map:
                mapped_off = self.rva_map[fn_rva]
                old_sec = self._rva_section.get(fn_rva, self.text_rva)
                new_sec = self._old_to_new_section.get(old_sec, old_sec)
                return (self.new_base + new_sec + mapped_off
                        + (old_rva - fn_rva))
        fn_entries = self._fn_entry_rvas or set(self.rva_map.keys())
        candidates = [(self.rva_map[o], o) for o in fn_entries
                      if o <= old_rva and o in self.rva_map]
        if candidates:
            mapped_off, old_start = max(candidates, key=lambda x: x[1])
            old_sec = self._rva_section.get(old_start, self.text_rva)
            new_sec = self._old_to_new_section.get(old_sec, old_sec)
            return self.new_base + new_sec + mapped_off + (old_rva - old_start)
        return self._code_rva_to_pe64_va(va)

    def _scope_old_rva_for_blob_off(self, off: int) -> Optional[int]:
        """Resolve x86 scope-table RVA from a materialized blob offset."""
        if off in self._scope_table_old_rva:
            return self._scope_table_old_rva[off]
        for base, old_rva in self._scope_table_old_rva.items():
            if abs(base - off) <= 5:
                return old_rva
        for old_rva, mapped in self.rva_map.items():
            if mapped == off:
                return old_rva
        return None

    def _scope_sentinel_matches_x86(self, out: bytearray, off: int,
                                    scope_old: int) -> bool:
        """True when blob sentinel begin/end match the x86 scope table at scope_old."""
        if off + 12 > len(out) or out[off:off + 4] != b'\xff\xff\xff\xff':
            return False
        sec = self.pe.section_for_rva(scope_old)
        if not sec:
            return False
        xdata = self.pe.get_section_data(sec)
        xoff = scope_old - sec['vaddr']
        if xoff < 0 or xoff + 12 > len(xdata):
            return False
        xbegin, xend = struct.unpack_from('<II', xdata, xoff + 4)
        obegin, oend = struct.unpack_from('<II', out, off + 4)
        return obegin == xbegin and oend == xend

    def _record_seh_scope_reg_fn(self, out: bytearray, scope_old: int,
                                 push_off: int) -> None:
        """Record the PE64 blob offset of the SEH function that owns a scope table."""
        if not hasattr(self, '_call_target_offs') or self._call_target_offs is None:
            self._call_target_offs = self._call_target_offsets(out)
        fn_off = self._fn_blob_off_from_push(out, push_off)
        prev = self._seh_scope_reg_fn.get(scope_old)
        if fn_off in self._call_target_offs:
            if prev is None or prev not in self._call_target_offs or fn_off > prev:
                self._seh_scope_reg_fn[scope_old] = fn_off
        elif prev is None or prev not in self._call_target_offs:
            if prev is None or fn_off > prev:
                self._seh_scope_reg_fn[scope_old] = fn_off

    def _patch_scope_table_entries(self, out: bytearray, start: int, size: int,
                                   scope_old_rva: Optional[int] = None,
                                   fn_blob_off: Optional[int] = None) -> int:
        """Rewrite begin/end/filter/handler DWORDs in one materialized scope table."""
        if start + 4 > len(out) or out[start:start + 4] != b'\xff\xff\xff\xff':
            return 0
        if scope_old_rva is None:
            scope_old_rva = self._scope_old_rva_for_blob_off(start)
            if scope_old_rva is None:
                for old_rva, off in self.rva_map.items():
                    if off == start:
                        scope_old_rva = old_rva
                        break
        patched = 0
        pos = start + 4
        end = min(start + size, len(out) - 15)
        while pos + 16 <= end:
            begin, end_va, filt, handler = struct.unpack_from('<4I', out, pos)
            if not (self.old_base <= begin < self.old_base + self.pe.image_size
                    and self.old_base < end_va <= self.old_base + self.pe.image_size
                    and begin < end_va):
                break
            for idx, val in enumerate((begin, end_va, filt, handler)):
                if idx == 3:
                    new_val = self._scope_handler_dword(val)
                elif val == 0:
                    new_val = 0
                elif self.old_base <= val < self.old_base + self.pe.image_size:
                    new_val = (self._scope_va_to_pe64(val, scope_old_rva, fn_blob_off)
                               & 0xFFFFFFFF)
                else:
                    new_val = val
                off = pos + idx * 4
                struct.pack_into('<I', out, off, new_val)
                if new_val != val:
                    patched += 1
            pos += 16
        return patched

    def _inject_seh_before_naked_rets(self, out: bytearray,
                                      text_rva: Optional[int] = None) -> int:
        """Expand bare ``ret`` in SEH functions into GS-restore + leave + ret."""
        if not self.win10_test_shim or self._cmd_no_hacks:
            return 0
        if text_rva is None:
            text_rva = self.text_rva
        gs_set = bytes([0x65, 0x48, 0x89, 0x24, 0x25, 0, 0, 0, 0])
        seh_mark = bytes([0x6A, 0xFF, 0x48, 0xB8])
        restore = (
            bytes([0xC7, 0x45, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF])
            + bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0])
            + bytes([0x48, 0x85, 0xC0, 0x74, 0x0C])
            + bytes([0x48, 0x8B, 0x00])
            + bytes([0x65, 0x48, 0x89, 0x04, 0x25, 0, 0, 0, 0])
        )
        leave5 = bytes([0x48, 0x89, 0xEC, 0x5D, 0xC3])
        tail = restore + bytes([0x48, 0x89, 0xEC, 0x5D])
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        sites: List[int] = []
        pos = 0
        while pos < len(out) - len(gs_set):
            if out[pos:pos + len(gs_set)] != gs_set:
                pos += 1
                continue
            head = max(0, pos - 96)
            if seh_mark not in out[head:pos + 4]:
                pos += 1
                continue
            end = min(len(out), pos + 0x8000)
            nseh = out.find(seh_mark, pos + len(gs_set), end)
            if nseh > pos:
                end = nseh
            for ins in md.disasm(out[pos:end], self.new_base + text_rva + pos):
                if ins.mnemonic != 'ret' or ins.op_str:
                    continue
                i = ins.address - self.new_base - text_rva
                if i < pos or i >= end:
                    continue
                if i >= 5 and out[i - 5:i] == leave5:
                    continue
                window = out[max(pos, i - 96):i]
                if restore[:7] in window:
                    continue
                if bytes([0x48, 0x89, 0xEC, 0x5D]) in out[max(pos, i - 8):i]:
                    continue
                # Skip R13 stack-align call epilogue (not a function exit).
                if bytes([0x4C, 0x89, 0xEC]) in out[max(pos, i - 24):i]:
                    continue
                sites.append(i)
            pos += len(gs_set)
        if not sites:
            return 0
        patched = 0
        for i in sorted(set(sites), reverse=True):
            out[i:i + 1] = tail + b'\xC3'
            patched += 1
        return patched

    def _inject_seh_gs_restore_epilogues(self, out: bytearray) -> int:
        """Restore GS:[0] before return when MSVC SEH was registered but epilogue was omitted."""
        if self._cmd_no_hacks:
            return 0
        gs_set = bytes([0x65, 0x48, 0x89, 0x24, 0x25, 0, 0, 0, 0])
        seh_mark = bytes([0x6A, 0xFF, 0x48, 0xB8])
        epilog = bytes([0x5F, 0x5E, 0x5B, 0x48, 0x89, 0xEC, 0x5D, 0xC3])
        restore = (
            bytes([0xC7, 0x45, 0xF8, 0xFF, 0xFF, 0xFF, 0xFF])
            + bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0])
            + bytes([0x48, 0x85, 0xC0, 0x74, 0x0C])
            + bytes([0x48, 0x8B, 0x00])
            + bytes([0x65, 0x48, 0x89, 0x04, 0x25, 0, 0, 0, 0])
        )
        restore_head = restore[:7]
        sites: List[int] = []
        pos = 0
        while pos < len(out) - len(gs_set):
            if out[pos:pos + len(gs_set)] != gs_set:
                pos += 1
                continue
            head = max(0, pos - 96)
            if seh_mark not in out[head:pos + 4]:
                pos += 1
                continue
            end = min(len(out), pos + 0x8000)
            nseh = out.find(seh_mark, pos + len(gs_set), end)
            if nseh > pos:
                end = nseh
            scan = pos + len(gs_set)
            while scan < end - len(epilog):
                ep = out.find(epilog, scan, end)
                if ep < 0:
                    break
                ins = ep + 3
                if out[ins:ins + len(restore_head)] != restore_head:
                    sites.append(ins)
                scan = ep + len(epilog)
            pos += len(gs_set)
        if not sites:
            return 0
        patched = 0
        for ins in sorted(set(sites), reverse=True):
            out[ins:ins] = restore
            patched += 1
        return patched

