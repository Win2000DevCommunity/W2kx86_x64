"""Section layout and the tail-call guard on the shared-epilogue rewrite."""

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from x86x64.translator._analysis import AnalysisMixin  # noqa: E402
from x86x64.translator._image import (  # noqa: E402
    next_prologue_after_shared_epilogue,
    reaches_ret_without_branching,
)

RET = b'\xc3'
POP_R13 = b'\x41\x5d'
MOV_RSP_R13 = b'\x4c\x89\xec'
MOV_RSP_RBP = b'\x48\x89\xec'
MOVABS_R11 = bytes.fromhex('49bb002b068000000000')  # movabs r11, imm64
PUSH_RBX = b'\x53'


class TestReachesRet:
    """Only a call in tail position may be rewritten as a jump.

    The rewrite exists to balance the stack when a call lands mid-epilogue.
    Applied to a call that has work after it, it strands the caller: the
    callee's ``ret`` consumes a frame that was never pushed for it. That is
    what sent cmd.exe to RIP=1 during ``getenv("PATH")``.
    """

    @pytest.mark.parametrize('tail', [
        RET,
        b'\xc2\x04\x00',                        # ret 4
        POP_R13 + RET,
        MOV_RSP_R13 + POP_R13 + RET,
        MOV_RSP_RBP + b'\x5d' + RET,            # mov rsp,rbp; pop rbp; ret
        MOV_RSP_R13 + POP_R13 + b'\x5b\x5f\x5e' + RET,
        b'\x48\x83\xc4\x20' + RET,              # add rsp,0x20; ret
        b'\x90\x90' + RET,
    ])
    def test_returns_are_tail_positions(self, tail):
        assert reaches_ret_without_branching(tail, 0)

    @pytest.mark.parametrize('tail', [
        b'\x48\xbf\x98\xc6\xd1\x4a\x00\x00\x00\x00',   # movabs rdi, imm64
        b'\xe8\x00\x00\x00\x00',                        # another call
        b'\xe9\x00\x00\x00\x00',                        # jmp
        b'\x85\xc0\x75\x0b',                            # test eax,eax; jne
        b'\x89\xc6',                                    # mov esi, eax
        b'',
    ])
    def test_real_work_is_not_a_tail_position(self, tail):
        assert not reaches_ret_without_branching(tail, 0)

    def test_the_cmd_getenv_site_is_rejected(self):
        """The exact bytes that followed the miscompiled call in cmd.exe.

        x86 ``call 0x6581`` at 0xab64 is followed by ``mov edi, <str>``, so the
        call must survive as a call.
        """
        after_call = bytes.fromhex('48bfa8c6d14a00000000')   # movabs rdi, ...
        assert not reaches_ret_without_branching(after_call, 0)

    def test_scan_stops_at_the_limit(self):
        """A ret beyond the window is not credited."""
        assert not reaches_ret_without_branching(b'\x90' * 40 + RET, 0, limit=8)
        assert reaches_ret_without_branching(b'\x90' * 4 + RET, 0, limit=8)

    def test_offset_is_respected(self):
        blob = b'\xe8\x00\x00\x00\x00' + MOV_RSP_R13 + POP_R13 + RET
        assert not reaches_ret_without_branching(blob, 0)
        assert reaches_ret_without_branching(blob, 5)

    def test_truncated_input_does_not_raise(self):
        for n in range(6):
            reaches_ret_without_branching(b'\x41' * n, 0)


class TestNextPrologueAfterSharedEpilogue:
    """Non-tail calls into a shared epilogue must retarget the next entry.

    The getenv PATH site in cmd.exe landed on ``mov rsp,r13`` of the previous
    function. Forward-snapping past ``ret`` reaches the real ``movabs r11``
    prologue; leaving the call on the epilogue returns to RIP=1.
    """

    def test_finds_movabs_r11_after_pops(self):
        epi = MOV_RSP_R13 + POP_R13 + b'\x5b\x5f\x5e' + RET
        blob = epi + MOVABS_R11 + PUSH_RBX
        nxt = next_prologue_after_shared_epilogue(
            blob, 0, AnalysisMixin._x64_entry_prologue_ok)
        assert nxt == len(epi)

    def test_rejects_garbage_after_incomplete_epilogue(self):
        blob = MOV_RSP_R13 + b'\x90\x90' + MOVABS_R11  # no ret
        assert next_prologue_after_shared_epilogue(
            blob, 0, AnalysisMixin._x64_entry_prologue_ok) is None

    def test_skips_bare_ret_padding(self):
        epi = MOV_RSP_R13 + POP_R13 + RET
        blob = epi + RET + RET + MOVABS_R11
        nxt = next_prologue_after_shared_epilogue(
            blob, 0, AnalysisMixin._x64_entry_prologue_ok)
        assert nxt == len(epi) + 2


class TestSectionHeadroom:
    """Reserved space after the code must live inside .text's VirtualSize."""

    def test_headroom_is_folded_into_the_previous_section(self):
        from x86x64.pe import validate_pe
        from tools.regress import heal_section_gaps

        exe = REPO / 'build_out225' / 'cmd_pure.exe'
        if not exe.exists():
            pytest.skip('build_out225 not present')
        blob = exe.read_bytes()
        assert not validate_pe(blob).ok
        healed, closed = heal_section_gaps(blob)
        assert closed == 1
        assert validate_pe(healed).ok
        assert len(healed) == len(blob), 'closing a hole must not add file bytes'
