"""PE32 parsing and PE64 emission, plus an end-to-end obj -> link -> PE run."""

import pathlib
import struct

import pytest

from x86x64.core import Linker, ObjectFile, RelocKind, SectionFlags
from x86x64.errors import PEFormatError
from x86x64.pe import PE32Image, PE64Options, PE64Writer, constants as C

REPO = pathlib.Path(__file__).resolve().parent.parent
BASE = 0x8000_0000


# -- PE32 reading ---------------------------------------------------------
class TestPE32Validation:
    def test_missing_mz_is_rejected(self):
        with pytest.raises(PEFormatError, match='bad MZ signature'):
            PE32Image(b'XX' + bytes(0x100))

    def test_missing_pe_signature_is_rejected(self):
        data = bytearray(b'MZ' + bytes(0x100))
        struct.pack_into('<I', data, 0x3C, 0x80)
        with pytest.raises(PEFormatError, match='PE signature not found'):
            PE32Image(bytes(data))

    def test_pe32plus_input_is_rejected(self):
        """The reader models PE32; a PE32+ input is a caller error."""
        data = bytearray(bytes(0x400))
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3C, 0x80)
        data[0x80:0x84] = b'PE\x00\x00'
        struct.pack_into('<H', data, 0x84, C.IMAGE_FILE_MACHINE_AMD64)
        struct.pack_into('<H', data, 0x94, 240)
        struct.pack_into('<H', data, 0x98, C.PE32PLUS_MAGIC)
        with pytest.raises(PEFormatError, match='expected a PE32 image'):
            PE32Image(bytes(data))


class TestPESection:
    def _section(self):
        from x86x64.pe import PESection
        return PESection(name='.text', vsize=0x1000, vaddr=0x1000,
                         raw_sz=0x1000, raw_ptr=0x400,
                         flags=C.IMAGE_SCN_MEM_EXECUTE | C.IMAGE_SCN_CNT_CODE)

    def test_dict_access_still_works(self):
        """Legacy call sites index these by key."""
        s = self._section()
        assert s['vaddr'] == 0x1000 and s['name'] == '.text'

    def test_attribute_access_works(self):
        assert self._section().vaddr == 0x1000

    def test_unknown_key_raises(self):
        with pytest.raises(KeyError):
            self._section()['nope']

    def test_range_helpers(self):
        s = self._section()
        assert s.end_rva == 0x2000
        assert s.contains_rva(0x1500)
        assert not s.contains_rva(0x2000)

    def test_flag_helpers(self):
        s = self._section()
        assert s.is_executable and s.is_code and not s.is_writable


class TestValidator:
    """Structural checks that catch loader-rejected images at build time."""

    def test_our_own_output_validates(self):
        from x86x64.pe import validate_pe
        report = validate_pe(PE64Writer(build_image(),
                                        PE64Options(entry_symbol='entry')).build())
        assert report.ok, str(report)

    def test_garbage_is_rejected(self):
        from x86x64.pe import validate_pe
        report = validate_pe(b'not a pe at all')
        assert not report.ok
        assert report.errors[0].code == 'dos-signature'

    def test_inconsistent_optional_header_size_is_caught(self):
        """The exact defect that makes the shipped ntdll64.dll unloadable."""
        from x86x64.pe import validate_pe
        blob = bytearray(PE64Writer(build_image()).build())
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        struct.pack_into('<H', blob, pe_off + 20, 368)   # claim 368, wrote 240
        report = validate_pe(bytes(blob))
        assert not report.ok
        assert any(f.code == 'opt-header-size' for f in report.errors)

    def test_overlapping_sections_are_caught(self):
        from x86x64.pe import validate_pe
        blob = bytearray(PE64Writer(build_image()).build())
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        opt_sz = struct.unpack_from('<H', blob, pe_off + 20)[0]
        hdr = pe_off + 24 + opt_sz
        first_rva = struct.unpack_from('<I', blob, hdr + 12)[0]
        struct.pack_into('<I', blob, hdr + 40 + 12, first_rva)  # collide
        assert any(f.code == 'section-overlap'
                   for f in validate_pe(bytes(blob)).errors)

    def test_entry_point_outside_any_section_is_caught(self):
        from x86x64.pe import validate_pe
        blob = bytearray(PE64Writer(build_image()).build())
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        struct.pack_into('<I', blob, pe_off + 24 + 16, 0x7F00_0000)
        assert any(f.code == 'entry-point'
                   for f in validate_pe(bytes(blob)).errors)

    def test_report_is_falsy_when_broken(self):
        from x86x64.pe import validate_pe
        assert not validate_pe(b'nope')


@pytest.mark.skipif(not (REPO / '_test_cmd_tmp.exe').is_file(),
                    reason='_test_cmd_tmp.exe fixture missing')
def test_legacy_exe_output_is_structurally_sound():
    """A recent legacy build should already satisfy the invariants."""
    from x86x64.pe import validate_file
    report = validate_file(str(REPO / '_test_cmd_tmp.exe'))
    assert report.ok, str(report)


@pytest.mark.skipif(not (REPO / 'ntdll64.dll').is_file(),
                    reason='ntdll64.dll fixture missing')
def test_stale_ntdll_artifact_is_known_broken():
    """
    Pins the defect in the checked-in ntdll64.dll.

    It was built before the SizeOfOptionalHeader fix, so it still claims 368
    bytes. Rebuilding it should make this test fail -- which is the signal to
    delete this test, not to loosen the validator.
    """
    from x86x64.pe import validate_file
    report = validate_file(str(REPO / 'ntdll64.dll'))
    assert any(f.code == 'opt-header-size' for f in report.errors)


class TestSectionGap:
    """A hole between two sections is ERROR_BAD_EXE_FORMAT at load time.

    Ground truth for these cases came from launching the build corpus: every
    build through 220 starts, 225 is refused by the loader, and the only
    structural difference is 0xf000 of unmapped space after ``.text``.
    """

    @staticmethod
    def _move_last_section(blob: bytes, delta: int) -> bytes:
        """Push the highest-RVA section up, leaving a hole behind it.

        Moving the last one keeps the sections in the same relative order, so
        the resulting image differs from a good one by exactly one gap.
        """
        data = bytearray(blob)
        pe = struct.unpack_from('<I', data, 0x3C)[0]
        n_sections = struct.unpack_from('<H', data, pe + 6)[0]
        opt_sz = struct.unpack_from('<H', data, pe + 20)[0]
        last = pe + 24 + opt_sz + (n_sections - 1) * 40
        vaddr = struct.unpack_from('<I', data, last + 12)[0]
        struct.pack_into('<I', data, last + 12, vaddr + delta)
        image_size = struct.unpack_from('<I', data, pe + 24 + 56)[0]
        struct.pack_into('<I', data, pe + 24 + 56, image_size + delta)
        return bytes(data)

    def test_contiguous_sections_are_accepted(self):
        from x86x64.pe import validate_pe
        blob = PE64Writer(build_image(), PE64Options(entry_symbol='entry')).build()
        assert not [f for f in validate_pe(blob).errors if f.code == 'section-gap']

    def test_a_hole_between_sections_is_an_error(self):
        from x86x64.pe import validate_pe
        blob = PE64Writer(build_image(), PE64Options(entry_symbol='entry')).build()
        holed = self._move_last_section(blob, 0xF000)
        gaps = [f for f in validate_pe(holed).errors if f.code == 'section-gap']
        assert gaps, 'a 0xf000 hole between sections must be reported'
        assert '0xf000 bytes unmapped' in gaps[0].message

    def test_the_message_says_which_section_to_grow(self):
        from x86x64.pe import validate_pe
        blob = PE64Writer(build_image(), PE64Options(entry_symbol='entry')).build()
        gap = [f for f in validate_pe(self._move_last_section(blob, 0x1000)).errors
               if f.code == 'section-gap'][0]
        assert 'VirtualSize' in gap.message

    @pytest.mark.parametrize('build,loads', [('build_out220', True),
                                             ('build_out225', False)])
    def test_corpus_verdict_matches_the_loader(self, build, loads):
        from x86x64.pe import validate_file
        exe = REPO / build / 'cmd_pure.exe'
        if not exe.exists():
            pytest.skip(f'{build} not present')
        report = validate_file(str(exe))
        assert report.ok is loads, str(report)


# -- PE64 writing ---------------------------------------------------------
def build_image(*, code=b'\xc3', with_data=True, with_import=False):
    """A minimal object exercising code, data, relocations, and imports."""
    obj = ObjectFile('t.obj')
    text = obj.section('.text', SectionFlags.text())

    if with_data:
        data = obj.section('.data', SectionFlags.data())
        data.emit(b'hello\x00')
        obj.define('msg', '.data', 0)
        text.emit(b'\x48\xba')
        text.emit_reloc(RelocKind.ABS64, 'msg')

    if with_import:
        ref = obj.declare_import('kernel32.dll', 'ExitProcess')
        text.emit(b'\xff\x15')
        text.reloc(text.tell() - 2 + 2, RelocKind.REL32, ref.name) \
            if False else None
        off = text.emit(bytes(4))
        text.reloc(off, RelocKind.REL32, ref.name)

    obj.define('entry', '.text', text.tell())
    text.emit(code)
    return Linker(image_base=BASE).add_object(obj).link()


class TestPE64Headers:
    @pytest.fixture(scope='class')
    def blob(self):
        return PE64Writer(build_image(),
                          PE64Options(entry_symbol='entry')).build()

    def test_dos_and_pe_signatures(self, blob):
        assert blob[:2] == b'MZ'
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        assert blob[pe_off:pe_off + 4] == b'PE\x00\x00'

    def test_machine_is_amd64(self, blob):
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        assert struct.unpack_from('<H', blob, pe_off + 4)[0] == \
            C.IMAGE_FILE_MACHINE_AMD64

    def test_optional_header_is_pe32plus(self, blob):
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        assert struct.unpack_from('<H', blob, pe_off + 24)[0] == C.PE32PLUS_MAGIC

    def test_image_base_is_a_qword(self, blob):
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        assert struct.unpack_from('<Q', blob, pe_off + 24 + 24)[0] == BASE

    def test_entry_point_matches_the_symbol(self, blob):
        result = build_image()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        entry = struct.unpack_from('<I', blob, pe_off + 24 + 16)[0]
        assert entry == result.rva_of('entry')

    def test_large_address_aware_is_set(self, blob):
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        chars = struct.unpack_from('<H', blob, pe_off + 22)[0]
        assert chars & C.IMAGE_FILE_LARGE_ADDRESS_AWARE

    def test_sixteen_data_directories(self, blob):
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        n = struct.unpack_from('<I', blob, pe_off + 24 + 108)[0]
        assert n == 16


class TestPE64Sections:
    def test_written_image_reparses(self):
        """Round-trip through our own reader would fail (it is PE32-only),
        so validate the section table directly."""
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        n = struct.unpack_from('<H', blob, pe_off + 6)[0]
        assert n >= 2

    def test_section_raw_data_is_present(self):
        blob = PE64Writer(build_image()).build()
        assert b'hello\x00' in blob

    def test_file_offsets_are_aligned(self):
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        n = struct.unpack_from('<H', blob, pe_off + 6)[0]
        opt_sz = struct.unpack_from('<H', blob, pe_off + 20)[0]
        hdr = pe_off + 24 + opt_sz
        for i in range(n):
            foff = struct.unpack_from('<I', blob, hdr + i * 40 + 20)[0]
            assert foff % 0x200 == 0

    def test_sections_do_not_overlap_in_memory(self):
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        n = struct.unpack_from('<H', blob, pe_off + 6)[0]
        opt_sz = struct.unpack_from('<H', blob, pe_off + 20)[0]
        hdr = pe_off + 24 + opt_sz
        spans = []
        for i in range(n):
            sh = hdr + i * 40
            vsize, vaddr = struct.unpack_from('<II', blob, sh + 8)
            spans.append((vaddr, vaddr + max(vsize, 1)))
        spans.sort()
        for a, b in zip(spans, spans[1:]):
            assert a[1] <= b[0]

    def test_image_size_covers_all_sections(self):
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        image_size = struct.unpack_from('<I', blob, pe_off + 24 + 56)[0]
        n = struct.unpack_from('<H', blob, pe_off + 6)[0]
        opt_sz = struct.unpack_from('<H', blob, pe_off + 20)[0]
        hdr = pe_off + 24 + opt_sz
        for i in range(n):
            sh = hdr + i * 40
            vsize, vaddr = struct.unpack_from('<II', blob, sh + 8)
            assert vaddr + vsize <= image_size

    def test_headers_size_covers_the_headers(self):
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        headers = struct.unpack_from('<I', blob, pe_off + 24 + 60)[0]
        n = struct.unpack_from('<H', blob, pe_off + 6)[0]
        opt_sz = struct.unpack_from('<H', blob, pe_off + 20)[0]
        assert headers >= pe_off + 24 + opt_sz + n * 40


class TestPE64Relocations:
    def test_reloc_directory_is_populated(self):
        result = build_image()
        assert result.base_relocs
        blob = PE64Writer(result).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        dd = pe_off + 24 + 112
        rva, size = struct.unpack_from('<II', blob, dd + C.DIR_BASERELOC * 8)
        assert rva and size

    def test_reloc_section_appears_in_the_table(self):
        blob = PE64Writer(build_image()).build()
        assert b'.reloc' in blob

    def test_image_without_relocs_has_an_empty_directory(self):
        obj = ObjectFile('bare.obj')
        obj.section('.text', SectionFlags.text()).emit(b'\xc3')
        result = Linker(image_base=BASE).add_object(obj).link()
        blob = PE64Writer(result).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        dd = pe_off + 24 + 112
        assert struct.unpack_from('<II', blob, dd + C.DIR_BASERELOC * 8) == (0, 0)


class TestPE64Options:
    def test_dll_flag_sets_the_characteristic(self):
        blob = PE64Writer(build_image(), PE64Options(is_dll=True)).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        chars = struct.unpack_from('<H', blob, pe_off + 22)[0]
        assert chars & C.IMAGE_FILE_DLL

    def test_subsystem_is_configurable(self):
        opts = PE64Options(subsystem=C.IMAGE_SUBSYSTEM_WINDOWS_GUI)
        blob = PE64Writer(build_image(), opts).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        assert struct.unpack_from('<H', blob, pe_off + 24 + 68)[0] == \
            C.IMAGE_SUBSYSTEM_WINDOWS_GUI

    def test_aslr_is_off_by_default(self):
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        dllchars = struct.unpack_from('<H', blob, pe_off + 24 + 70)[0]
        assert not dllchars & C.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

    def test_nx_compat_is_on_by_default(self):
        blob = PE64Writer(build_image()).build()
        pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
        dllchars = struct.unpack_from('<H', blob, pe_off + 24 + 70)[0]
        assert dllchars & C.IMAGE_DLLCHARACTERISTICS_NX_COMPAT


class TestEndToEnd:
    """obj -> link -> PE, the pipeline the shift pass used to sit inside."""

    def test_writes_to_disk(self, tmp_path):
        from x86x64.pe import write_pe64
        out = tmp_path / 'out.exe'
        size = write_pe64(build_image(), str(out),
                          PE64Options(entry_symbol='entry'))
        assert out.stat().st_size == size > 0

    def test_growing_code_keeps_data_pointers_correct(self):
        """The end-to-end version of the shift regression."""
        for padding in (0, 0x2000, 0x9000):
            obj = ObjectFile('t.obj')
            text = obj.section('.text', SectionFlags.text())
            data = obj.section('.data', SectionFlags.data())
            data.emit(b'PAYLOAD\x00')
            obj.define('msg', '.data', 0)

            text.emit(b'\x90' * padding)
            obj.define('site', '.text', text.tell())
            text.emit(b'\x48\xba')
            text.emit_reloc(RelocKind.ABS64, 'msg')
            text.emit(b'\xc3')

            result = Linker(image_base=BASE).add_object(obj).link()
            PE64Writer(result, PE64Options(entry_symbol='site')).build()

            off = result.rva_of('site') - result.layout.rva_of('.text') + 2
            pointer = struct.unpack_from('<Q', result.section_bytes('.text'),
                                         off)[0]
            assert pointer == result.address_of('msg')

    def test_syscall_stub_image_links_and_writes(self):
        """A translated ntdll stub, from emitter through to a PE."""
        from x86x64.syscall import SyscallTable, emit_x64_stub

        table = SyscallTable()
        obj = ObjectFile('ntdll.obj')
        text = obj.section('.text', SectionFlags.text())
        for name in ('NtClose', 'NtAllocateVirtualMemory', 'NtCreateFile'):
            entry = table.require(name)
            obj.define_here(name, text)
            text.emit(emit_x64_stub(entry.win2000_nr))
            text.align_to(16, fill=0xCC)

        result = Linker(image_base=BASE).add_object(obj).link()
        blob = PE64Writer(result, PE64Options(is_dll=True,
                                              entry_symbol='NtClose')).build()
        assert blob[:2] == b'MZ'

        off = result.rva_of('NtClose') - result.layout.rva_of('.text')
        code = result.section_bytes('.text')[off:off + 11]
        assert code == emit_x64_stub(table.require('NtClose').win2000_nr)
