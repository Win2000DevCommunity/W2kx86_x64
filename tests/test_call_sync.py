"""Authoritative x86 CALL sync and mid-movabs landing repairs."""
import pathlib
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

PRO = bytes.fromhex("41554989e54883ec204883e4f0")
EPI = bytes.fromhex("4c89ec415d")


def _stub(rel32: int) -> bytes:
    return PRO + b"\xe8" + struct.pack("<i", rel32) + EPI


class TestAuthoritativeCallSync:
    def test_sync_retargets_stub_to_find_sane_entry(self):
        pytest.importorskip("capstone")
        pytest.importorskip("keystone")
        from x86x64.pe import PE32Image
        from x86x64.translator import Win2000Translator

        cand = pathlib.Path(
            r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
        if not cand.exists():
            pytest.skip("Win2000 cmd.exe not present")
        pe = PE32Image(cand.read_bytes())
        t = Win2000Translator(pe, win10_test_shim=True)
        t._cmd_no_hacks = True
        t._is_alloca_probe_rva = lambda r: False
        t._old_to_new_section = {s["vaddr"]: s["vaddr"] for s in pe.sections}

        entry = 0x100
        out = bytearray(0x200)
        out[entry:entry + 8] = bytes.fromhex("554889e54883ec20")
        out[0x180] = 0xC3
        stub = 0x20
        out[stub:stub + len(_stub(0))] = _stub(0x180 - (stub + len(PRO) + 5))

        text = bytearray(0x20)
        # Function at 0x1000: one direct call to 0x2000
        text[0] = 0xE8
        struct.pack_into("<i", text, 1, 0x2000 - (0x1000 + 5))
        text[5] = 0xC3
        t._pure_find_sane_entry_for_x86 = (
            lambda out, tgt, rva_map, td, tr: {0x2000: entry}.get(tgt))
        t._pure_resolve_x86_call_target = lambda *a, **k: None
        # Map the *function entry* to the align-stub prologue, not the E8.
        rva_map = {0x1000: stub, 0x2000: entry}
        t.rva_map = dict(rva_map)
        t._fn_entry_rvas = {0x1000, 0x2000}
        n = t._pure_authoritative_x86_call_sync(out, rva_map, bytes(text), 0x1000)
        assert n >= 1
        e8 = stub + len(PRO)
        tgt = e8 + 5 + struct.unpack_from("<i", out, e8 + 1)[0]
        assert tgt == entry, hex(tgt)

    def test_sync_skips_chkstk_so_later_stubs_stay_aligned(self):
        """``call __chkstk`` must not consume an align-stub slot in the zip."""
        pytest.importorskip("capstone")
        pytest.importorskip("keystone")
        from x86x64.pe import PE32Image
        from x86x64.translator import Win2000Translator

        cand = pathlib.Path(
            r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
        if not cand.exists():
            pytest.skip("Win2000 cmd.exe not present")
        pe = PE32Image(cand.read_bytes())
        t = Win2000Translator(pe, win10_test_shim=True)
        t._cmd_no_hacks = True
        t._is_alloca_probe_rva = lambda r: r == 0x3000
        t._old_to_new_section = {s["vaddr"]: s["vaddr"] for s in pe.sections}

        real = 0x100
        wrong = 0x140
        out = bytearray(0x300)
        out[real:real + 4] = bytes.fromhex("4883f900")  # cmp rcx, 0
        out[wrong:wrong + 4] = bytes.fromhex("554889e5")
        stub = 0x40
        # Currently points at the wrong entry (simulates chkstk collision).
        out[stub:stub + len(_stub(0))] = _stub(wrong - (stub + len(PRO) + 5))

        text = bytearray(0x20)
        # mov eax,imm; call chkstk; call real
        text[0] = 0xB8
        struct.pack_into("<I", text, 1, 0x100)
        text[5] = 0xE8
        struct.pack_into("<i", text, 6, 0x3000 - (0x1000 + 10))
        text[10] = 0xE8
        struct.pack_into("<i", text, 11, 0x2000 - (0x1000 + 15))
        text[15] = 0xC3

        t._pure_find_sane_entry_for_x86 = (
            lambda out, tgt, rva_map, td, tr: {0x2000: real, 0x3000: wrong}.get(tgt))
        t._pure_resolve_x86_call_target = lambda *a, **k: None
        rva_map = {0x1000: stub, 0x2000: real, 0x3000: wrong}
        t.rva_map = dict(rva_map)
        t._fn_entry_rvas = {0x1000, 0x2000}
        n = t._pure_authoritative_x86_call_sync(out, rva_map, bytes(text), 0x1000)
        assert n >= 1
        e8 = stub + len(PRO)
        tgt = e8 + 5 + struct.unpack_from("<i", out, e8 + 1)[0]
        assert tgt == real, hex(tgt)


class TestMidMovabsCallSnap:
    def test_snap_call_out_of_movabs_imm_to_outer_align(self):
        pytest.importorskip("capstone")
        pytest.importorskip("keystone")
        from x86x64.pe import PE32Image
        from x86x64.translator import Win2000Translator

        cand = pathlib.Path(
            r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
        if not cand.exists():
            pytest.skip("Win2000 cmd.exe not present")
        pe = PE32Image(cand.read_bytes())
        t = Win2000Translator(pe, win10_test_shim=True)

        # align + movabs rax, imm64 + mov rax,[rax] + call rax + epi
        body = (PRO
                + bytes.fromhex("48b8d0a5088000000000")  # movabs
                + bytes.fromhex("488b00ffd0")
                + EPI + b"\xc3")
        out = bytearray(0x100)
        out[0x10:0x10 + len(body)] = body
        movabs = 0x10 + len(PRO)
        mid_imm = movabs + 8  # high half of imm
        call_at = 0x80
        out[call_at] = 0xE8
        struct.pack_into("<i", out, call_at + 1, mid_imm - (call_at + 5))
        n = t._fix_calls_into_movabs_imm(out)
        assert n == 1
        tgt = call_at + 5 + struct.unpack_from("<i", out, call_at + 1)[0]
        assert tgt == 0x10, hex(tgt)  # outer push r13
