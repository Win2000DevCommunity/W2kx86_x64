"""Kernel service table construction and emission."""

import struct

import pytest

from x86x64.core import Linker, RelocKind
from x86x64.kernel import (
    ARGUMENT_TABLE_SYMBOL,
    DESCRIPTOR_SYMBOL,
    SERVICE_TABLE_SYMBOL,
    ServiceEntry,
    ServiceTable,
)
from x86x64.syscall import SyscallTable

BASE = 0x1_4000_0000


class TestServiceEntry:
    def test_argument_bytes_are_eight_per_arg(self):
        assert ServiceEntry(0, 'NtCreateFile', 11, 'NtCreateFile').argument_bytes == 88

    def test_entry_without_handler_is_unimplemented(self):
        assert not ServiceEntry(0, 'NtX', 2).is_implemented

    def test_entry_with_handler_is_implemented(self):
        assert ServiceEntry(0, 'NtX', 2, 'NtX').is_implemented


class TestServiceTable:
    def test_built_from_the_syscall_table(self):
        table = ServiceTable.from_syscall_table(SyscallTable())
        assert len(table) > 200

    def test_indices_match_the_ssdt(self):
        table = ServiceTable.from_syscall_table(SyscallTable())
        entry = table.get(0x10)
        assert entry.name == 'NtAllocateVirtualMemory'

    def test_index_beyond_limit_is_rejected(self):
        table = ServiceTable(limit=4)
        with pytest.raises(IndexError, match='outside table limit'):
            table.add(ServiceEntry(9, 'NtX', 0, 'NtX'))

    def test_coverage_reports_implemented_slots(self):
        table = ServiceTable(limit=8)
        table.add(ServiceEntry(0, 'NtA', 1, 'NtA'))
        table.add(ServiceEntry(1, 'NtB', 1))
        assert table.coverage() == (1, 8)

    def test_iteration_is_ordered_by_index(self):
        table = ServiceTable(limit=8)
        table.add(ServiceEntry(3, 'NtC', 0, 'NtC'))
        table.add(ServiceEntry(1, 'NtA', 0, 'NtA'))
        assert [e.index for e in table] == [1, 3]


class TestArgumentTable:
    def test_one_byte_per_slot(self):
        table = ServiceTable(limit=16)
        obj = table.build_object()
        data = obj.get_section('.data')
        assert data.raw_size >= 16

    def test_byte_records_stack_argument_size(self):
        from x86x64.core import ObjectFile, SectionFlags
        table = ServiceTable(limit=4)
        table.add(ServiceEntry(2, 'NtCreateFile', 11, 'NtCreateFile'))
        obj = ObjectFile('t.obj')
        sec = obj.section('.data', SectionFlags.data())
        start = table.emit_argument_table(sec)
        assert sec.data[start + 2] == 88

    def test_empty_slots_are_zero(self):
        from x86x64.core import ObjectFile, SectionFlags
        table = ServiceTable(limit=4)
        obj = ObjectFile('t.obj')
        sec = obj.section('.data', SectionFlags.data())
        start = table.emit_argument_table(sec)
        assert sec.data[start:start + 4] == bytes(4)


class TestServiceTableEmission:
    def _small_table(self):
        table = ServiceTable(limit=4)
        table.add(ServiceEntry(0, 'NtA', 1, 'NtA'))
        table.add(ServiceEntry(2, 'NtC', 2, 'NtC'))
        return table

    def test_every_slot_gets_a_relocation(self):
        obj = self._small_table().build_object()
        data = obj.get_section('.data')
        abs_relocs = [r for r in data.relocations if r.kind is RelocKind.ABS64]
        # four service slots plus two descriptor pointers
        assert len(abs_relocs) == 6

    def test_unimplemented_slots_point_at_the_trap(self):
        obj = self._small_table().build_object()
        data = obj.get_section('.data')
        targets = [r.symbol for r in data.relocations[:4]]
        assert targets[1] == 'KiServiceNotImplemented'
        assert targets[3] == 'KiServiceNotImplemented'

    def test_implemented_slots_point_at_their_handler(self):
        obj = self._small_table().build_object()
        data = obj.get_section('.data')
        targets = [r.symbol for r in data.relocations[:4]]
        assert targets[0] == 'NtA' and targets[2] == 'NtC'

    def test_object_defines_the_three_kernel_symbols(self):
        obj = self._small_table().build_object()
        for name in (SERVICE_TABLE_SYMBOL, ARGUMENT_TABLE_SYMBOL,
                     DESCRIPTOR_SYMBOL):
            assert obj.symbols.get(name) is not None

    def test_links_once_handlers_are_supplied(self):
        table = self._small_table()
        obj = table.build_object()
        lk = Linker(image_base=BASE).add_object(obj)
        for handler in ('NtA', 'NtC', 'KiServiceNotImplemented'):
            lk.define_absolute(handler, 0x1_4000_9000)
        result = lk.link()
        assert result.address_of(SERVICE_TABLE_SYMBOL) > 0

    def test_missing_handler_is_reported_by_name(self):
        from x86x64.errors import UndefinedSymbolError
        obj = self._small_table().build_object()
        lk = Linker(image_base=BASE).add_object(obj)
        lk.define_absolute('KiServiceNotImplemented', 0x1_4000_9000)
        lk.define_absolute('NtA', 0x1_4000_9100)
        with pytest.raises(UndefinedSymbolError, match='NtC'):
            lk.link()

    def test_descriptor_records_the_limit(self):
        table = self._small_table()
        obj = table.build_object()
        lk = Linker(image_base=BASE).add_object(obj)
        for handler in ('NtA', 'NtC', 'KiServiceNotImplemented'):
            lk.define_absolute(handler, 0x1_4000_9000)
        result = lk.link()
        off = (result.rva_of(DESCRIPTOR_SYMBOL)
               - result.layout.rva_of('.data'))
        limit = struct.unpack_from('<Q', result.section_bytes('.data'), off + 16)[0]
        assert limit == table.limit

    def test_service_pointers_resolve_to_handler_addresses(self):
        table = self._small_table()
        obj = table.build_object()
        lk = Linker(image_base=BASE).add_object(obj)
        lk.define_absolute('NtA', 0x1_4000_A000)
        lk.define_absolute('NtC', 0x1_4000_B000)
        lk.define_absolute('KiServiceNotImplemented', 0x1_4000_C000)
        result = lk.link()

        off = result.rva_of(SERVICE_TABLE_SYMBOL) - result.layout.rva_of('.data')
        blob = result.section_bytes('.data')
        slots = [struct.unpack_from('<Q', blob, off + i * 8)[0] for i in range(4)]
        assert slots == [0x1_4000_A000, 0x1_4000_C000,
                         0x1_4000_B000, 0x1_4000_C000]
