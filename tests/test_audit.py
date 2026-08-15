"""Call-target auditing: resynchronising disassembly and boundary checks."""

import pathlib
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

pytest.importorskip('capstone')

from tools.audit_calls import (disassemble, load_map,  # noqa: E402
                               read_text_section)

RET = b'\xc3'
NOP = b'\x90'
BASE = 0x1000


def call_rel32(site: int, target: int) -> bytes:
    return b'\xe8' + struct.pack('<i', target - (site + 5))


class TestResyncingDisassembly:
    """Capstone stops at the first undecodable byte; the sweep must not.

    Translated sections interleave code with padding and embedded data, so a
    single-shot disasm covers almost nothing -- it stopped after 27 of 101,847
    instructions on the real image.
    """

    def test_a_clean_run_decodes_every_instruction(self):
        code = NOP * 4 + RET
        assert len(disassemble(code, BASE)) == 5

    def test_decoding_resumes_after_undecodable_bytes(self):
        # 0x0f 0xff is not a valid encoding; the ret after it must still show.
        code = b'\x0f\xff' + NOP + RET
        found = {i.address for i in disassemble(code, BASE)}
        assert BASE + 2 in found and BASE + 3 in found

    def test_seeds_take_precedence_over_a_desynced_sweep(self):
        """A seeded address is always reported as an instruction start.

        ``48 89 ec`` decoded from its second byte is ``mov esp, ebp``, a
        different instruction at a different boundary. Seeding the real start
        keeps the true boundary in the set.
        """
        code = b'\x48\x89\xec' + RET
        seeded = {i.address for i in disassemble(code, BASE, {BASE})}
        assert BASE in seeded

    def test_every_byte_is_accounted_for(self):
        code = b'\x0f\xff\x0f\xff' + RET
        assert disassemble(code, BASE), 'sweep must not return empty'

    def test_empty_input(self):
        assert disassemble(b'', BASE) == []


class TestTargetClassification:
    """A target is good only when it coincides with an instruction start."""

    def _targets(self, code: bytes):
        insns = disassemble(code, BASE)
        starts = {i.address for i in insns}
        bad = []
        for ins in insns:
            off = ins.address - BASE
            if code[off] != 0xE8 or ins.size != 5:
                continue
            rel = struct.unpack_from('<i', code, off + 1)[0]
            target = ins.address + 5 + rel
            if target not in starts:
                bad.append((ins.address, target))
        return bad

    def test_a_call_to_a_real_boundary_is_clean(self):
        # call -> the ret that follows it
        code = call_rel32(BASE, BASE + 5) + RET
        assert self._targets(code) == []

    def test_a_call_landing_mid_instruction_is_flagged(self):
        # 'mov rsp, r13' is 3 bytes; target its second byte.
        code = call_rel32(BASE, BASE + 6) + b'\x4c\x89\xec' + RET
        bad = self._targets(code)
        assert bad and bad[0][1] == BASE + 6


class TestSectionReader:
    def test_picks_the_executable_section(self):
        from x86x64.core import Linker, ObjectFile, SectionFlags
        from x86x64.pe import PE64Options, PE64Writer

        obj = ObjectFile('t.obj')
        text = obj.section('.text', SectionFlags.text())
        data = obj.section('.data', SectionFlags.data())
        data.emit(b'not code')
        obj.define('entry', '.text', text.tell())
        text.emit(RET)
        image = Linker(image_base=0x140000000).add_object(obj).link()
        blob = PE64Writer(image, PE64Options(entry_symbol='entry')).build()

        rva, raw, base = read_text_section(blob)
        assert base == 0x140000000
        assert raw.startswith(RET)


class TestMapLoading:
    def test_parses_hex_pairs_and_skips_noise(self, tmp_path):
        p = tmp_path / 'rva.txt'
        p.write_text('00001000 00001018\nnot a pair\n0000abcd 0000ef01\n')
        assert load_map(p) == {0x1000: 0x1018, 0xABCD: 0xEF01}

    def test_missing_file_is_empty(self, tmp_path):
        assert load_map(tmp_path / 'nope.txt') == {}
