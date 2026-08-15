"""_normalize_x64_asm must not turn valid 32-bit moves into INT3."""

import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

os.environ.setdefault("PURE", "1")

from x86x64.pe import PE32Image  # noqa: E402
from x86x64.translator import Win2000Translator  # noqa: E402

SRC = pathlib.Path(
    r"C:\Users\win2000\Downloads"
    r"\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")


@pytest.fixture(scope="module")
def tr():
    if not SRC.exists():
        pytest.skip("cmd.exe source not present")
    pe = PE32Image(SRC.read_bytes())
    t = Win2000Translator(pe, win10_test_shim=True, source_path=str(SRC))
    t._cmd_no_hacks = True
    t.new_base = 0x80000000
    t.text_rva = 0x1000
    return t


class TestNormalizeAsm:
    def test_mov_ecx_ebp_stays_valid(self, tr):
        assert tr._normalize_x64_asm("mov ecx, ebp") == "mov ecx, ebp"
        assert tr._asm("mov ecx, ebp") == bytes.fromhex("89e9")

    def test_mov_rcx_rbp_is_preferred_arg_move(self, tr):
        assert tr._asm("mov rcx, rbp") == bytes.fromhex("4889e9")

    def test_push_ebp_still_widens(self, tr):
        assert tr._normalize_x64_asm("push ebp") == "push rbp"

    def test_mem_operand_ebp_widens(self, tr):
        assert "rbp" in tr._normalize_x64_asm("mov eax, dword ptr [ebp+8]")

    def test_emit_mov32_to_arg_uses_full_width(self, tr):
        try:
            from capstone.x86 import X86_REG_EBP as EBP
        except ImportError:
            from x86x64.translator.runtime import X86_REG_EBP as EBP
        out = bytearray()
        tr._emit_mov32_to_w64_reg(out, "rcx", EBP)
        assert bytes(out) == bytes.fromhex("4889e9")

    def test_byte_store_via_image_base_keeps_bl(self, tr):
        """mov [eax+image], bl must not become INT3 (Keystone size mismatch)."""
        try:
            from capstone.x86 import X86_REG_BL as BL, X86_OP_REG
        except ImportError:
            pytest.skip("capstone x86 regs unavailable")

        class _Op:
            type = X86_OP_REG
            reg = BL
            size = 1

        assert tr._ebp_slot_reg_asm(
            _Op(), "byte ptr [eax + 0x4ad1f9e0], bl", "byte") == "bl"
        enc = (tr._asm("mov r11, 0x800609e0")
               + tr._asm("mov byte ptr [r11 + rax], bl"))
        assert b"\xcc" not in enc
        assert enc[:2] in (b"\x49\xbb", b"\x48\xbb")
