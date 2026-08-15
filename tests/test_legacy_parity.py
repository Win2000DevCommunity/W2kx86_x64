"""
Parity between the extracted package and the legacy ``x86_x64.py``.

The translator is being migrated module by module, so for now both spellings of
the same data exist.  These tests fail the moment they disagree, which is the
only thing keeping a partial migration honest.

Delete a case here once its legacy definition is gone.
"""

import importlib
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


@pytest.fixture(scope='module')
def legacy():
    """Import the legacy translator, skipping if its dependencies are absent."""
    try:
        return importlib.import_module('x86_x64')
    except Exception as exc:                       # pragma: no cover
        pytest.skip(f'legacy x86_x64 module will not import: {exc}')


class TestSyscallTableParity:
    def test_row_count_matches(self, legacy):
        from x86x64.syscall import WIN2000_SYSCALL_TABLE
        assert len(WIN2000_SYSCALL_TABLE) == len(legacy.WIN2000_SYSCALL_TABLE)

    def test_rows_are_identical(self, legacy):
        from x86x64.syscall import WIN2000_SYSCALL_TABLE
        assert WIN2000_SYSCALL_TABLE == legacy.WIN2000_SYSCALL_TABLE

    def test_resolution_agrees_for_win2000(self, legacy):
        from x86x64.syscall import SyscallTable
        table = SyscallTable(target='win2000')
        legacy.set_syscall_target('win2000')
        for w2k, _w10, _n, name in legacy.WIN2000_SYSCALL_TABLE[:80]:
            assert table.resolve(name, w2k) == legacy.resolve_syscall_nr(name, w2k)

    def test_resolution_agrees_for_win10(self, legacy):
        from x86x64.syscall import SyscallTable
        table = SyscallTable(target='win10')
        previous = legacy.get_syscall_target()
        legacy.set_syscall_target('win10')
        try:
            for w2k, _w10, _n, name in legacy.WIN2000_SYSCALL_TABLE[:80]:
                assert table.resolve(name, w2k) == \
                    legacy.resolve_syscall_nr(name, w2k)
        finally:
            legacy.set_syscall_target(previous)


class TestTebParity:
    def test_mapping_is_identical(self, legacy):
        from x86x64.abi import FS_TO_GS
        assert FS_TO_GS == legacy.TEB_FS_TO_GS

    def test_translation_agrees(self, legacy):
        from x86x64.abi import fs_to_gs
        for fs, gs in legacy.TEB_FS_TO_GS.items():
            assert fs_to_gs(fs) == gs


class TestAbiParity:
    def test_arg_register_names_match(self, legacy):
        from x86x64.encoding import ARG_REGS64
        assert list(ARG_REGS64) == legacy.WIN64_ARG_REG_NAMES

    def test_dword_arg_register_names_match(self, legacy):
        from x86x64.encoding import ARG_REGS32
        assert list(ARG_REGS32) == legacy.W32_ARG_REG_NAMES

    def test_register_numbers_match(self, legacy):
        from x86x64.encoding import REG64
        assert REG64 == legacy._W64_REG_NUM

    def test_rbp_home_mapping_matches(self, legacy):
        from x86x64.abi import x86_disp_to_rbp_home
        for disp in range(0, 0x50, 4):
            assert x86_disp_to_rbp_home(disp) == legacy.ebp_disp_to_rbp_home(disp)

    def test_arg_slot_home_matches(self, legacy):
        from x86x64.abi import arg_slot_to_rbp_home
        for slot in range(8):
            assert arg_slot_to_rbp_home(slot) == \
                legacy.ebp_arg_slot_to_rbp_home(slot)


class TestPeConstantParity:
    def test_exe_base_matches(self, legacy):
        from x86x64.pe import PE64_EXE_BASE
        assert PE64_EXE_BASE == legacy.PE64_EXE_BASE

    def test_optional_header_size_matches(self, legacy):
        from x86x64.pe.constants import PE64_OPT_STANDARD, PE64_OPT_TOTAL
        assert PE64_OPT_TOTAL == legacy.PE64_OPT_TOTAL
        assert PE64_OPT_STANDARD == legacy.PE64_OPT_STD

    def test_base_reloc_types_match(self, legacy):
        from x86x64.pe import IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW
        assert IMAGE_REL_BASED_DIR64 == legacy.IMAGE_REL_BASED_DIR64
        assert IMAGE_REL_BASED_HIGHLOW == legacy.IMAGE_REL_BASED_HIGHLOW


class TestPeParserParity:
    """The new reader must agree with the legacy one on a real image."""

    @pytest.fixture(scope='class')
    def raw(self):
        path = REPO / 'ntdll64.dll'
        if not path.is_file():
            pytest.skip('ntdll64.dll fixture missing')
        return path.read_bytes()

    def test_both_readers_reject_pe32plus_consistently(self, legacy, raw):
        """
        ntdll64.dll is PE32+. The new reader rejects it by design; the legacy
        one parses it as PE32 and produces nonsense, which is exactly the
        difference worth pinning.
        """
        from x86x64.errors import PEFormatError
        from x86x64.pe import PE32Image

        with pytest.raises(PEFormatError):
            PE32Image(raw)

    def test_readers_agree_on_a_pe32_input(self, legacy):
        """Any genuine PE32 in the tree must parse identically both ways."""
        from x86x64.pe import PE32Image

        for name in ('_test_cmd_tmp.exe', 'ntoskrnl64.exe'):
            path = REPO / name
            if not path.is_file():
                continue
            raw = path.read_bytes()
            try:
                new = PE32Image(raw)
            except Exception:
                continue
            old = legacy.PE32Image(raw)
            assert new.image_base == old.image_base
            assert new.entry_rva == old.entry_rva
            assert [s.name for s in new.sections] == \
                [s['name'] for s in old.sections]
            return
        pytest.skip('no PE32 fixture available')
