"""x86-64 encoders, checked against capstone where it is available."""

import struct

import pytest

from x86x64.encoding import emit, regs
from x86x64.errors import EncodingError

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    _MD = Cs(CS_ARCH_X86, CS_MODE_64)
    HAS_CAPSTONE = True
except ImportError:                                   # pragma: no cover
    HAS_CAPSTONE = False

needs_capstone = pytest.mark.skipif(not HAS_CAPSTONE, reason='capstone missing')


def disasm(blob: bytes, addr: int = 0x1000) -> str:
    insn = next(_MD.disasm(blob, addr))
    return f'{insn.mnemonic} {insn.op_str}'.strip()


def disasm_all(blob: bytes, addr: int = 0x1000):
    return [f'{i.mnemonic} {i.op_str}'.strip() for i in _MD.disasm(blob, addr)]


class TestRegisters:
    @pytest.mark.parametrize('name,num', [
        ('rax', 0), ('rcx', 1), ('rsp', 4), ('rdi', 7), ('r8', 8), ('r15', 15),
    ])
    def test_reg_num(self, name, num):
        assert regs.reg_num(name) == num

    def test_32bit_views_share_numbers(self):
        assert regs.reg_num('eax') == regs.reg_num('rax')
        assert regs.reg_num('r8d') == regs.reg_num('r8')

    def test_unknown_register_raises(self):
        with pytest.raises(EncodingError, match='unknown register'):
            regs.reg_num('xmm0')

    @pytest.mark.parametrize('name,expected', [
        ('eax', 'rax'), ('ebp', 'rbp'), ('esi', 'rsi'), ('rax', 'rax'),
    ])
    def test_widen(self, name, expected):
        assert regs.widen(name) == expected

    def test_narrow_round_trips(self):
        for name in ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'):
            assert regs.narrow(regs.widen(name)) == name

    def test_extended_registers_are_flagged(self):
        assert regs.is_extended('r8') and not regs.is_extended('rdi')

    def test_argument_registers_in_order(self):
        assert [regs.arg_reg(i) for i in range(4)] == ['rcx', 'rdx', 'r8', 'r9']

    def test_fifth_argument_has_no_register(self):
        with pytest.raises(EncodingError, match='passed on the stack'):
            regs.arg_reg(4)

    def test_volatility_split_is_disjoint(self):
        assert not (regs.VOLATILE & regs.NONVOLATILE)

    def test_argument_registers_are_volatile(self):
        assert all(regs.is_volatile(r) for r in regs.ARG_REGS64)


class TestModRM:
    def test_low_three_bits_are_used(self):
        assert emit.modrm(0b11, 8, 9) == emit.modrm(0b11, 0, 1)

    def test_out_of_range_is_rejected(self):
        with pytest.raises(EncodingError, match='reg/rm out of range'):
            emit.modrm(0, 16, 0)

    def test_bad_mod_is_rejected(self):
        with pytest.raises(EncodingError, match='mod field'):
            emit.modrm(4, 0, 0)

    def test_rex_bits(self):
        assert emit.rex() == 0x40
        assert emit.rex(w=True) == 0x48
        assert emit.rex(w=True, r=True, b=True) == 0x4D


class TestMovabs:
    def test_length_and_immediate_offset(self):
        blob = emit.mov_reg_imm64('rax', 0x8004_4538)
        assert len(blob) == emit.MOVABS_SIZE
        assert struct.unpack_from('<Q', blob, emit.MOVABS_IMM_OFFSET)[0] == 0x8004_4538

    def test_extended_register_sets_rex_b(self):
        assert emit.mov_reg_imm64('r10', 0)[0] == 0x49

    def test_reloc_form_leaves_the_field_zero(self):
        assert emit.mov_reg_imm64_reloc('rdx')[2:] == bytes(8)

    @needs_capstone
    @pytest.mark.parametrize('reg', ['rax', 'rcx', 'rdx', 'rbx', 'rsi',
                                     'rdi', 'r8', 'r12', 'r15'])
    def test_round_trips(self, reg):
        blob = emit.mov_reg_imm64(reg, 0x8004_4538)
        assert disasm(blob) == f'movabs {reg}, 0x80044538'


class TestSegmentAccess:
    def test_gs_load_shape(self):
        blob = emit.mov_reg_gs('rax', 0x60)
        assert blob[0] == emit.PREFIX_GS
        assert struct.unpack_from('<I', blob, 5)[0] == 0x60

    @needs_capstone
    def test_gs_load_round_trips(self):
        assert disasm(emit.mov_reg_gs('rax', 0x60)) == 'mov rax, qword ptr gs:[0x60]'

    @needs_capstone
    def test_gs_store_round_trips(self):
        assert disasm(emit.mov_gs_reg('rdx', 0x30)) == 'mov qword ptr gs:[0x30], rdx'

    @needs_capstone
    @pytest.mark.parametrize('reg', ['r8', 'r9', 'r12', 'r15'])
    def test_extended_registers_do_not_corrupt_modrm(self, reg):
        """The legacy encoder folded reg>=8 into ModRM and broke the mode."""
        assert disasm(emit.mov_reg_gs(reg, 0x60)) == \
            f'mov {reg}, qword ptr gs:[0x60]'

    def test_extended_register_sets_rex_r(self):
        assert emit.mov_reg_gs('r8', 0x60)[1] == 0x4C

    def test_addressing_mode_is_identical_across_registers(self):
        """Only the REX.R bit and ModRM.reg may differ, never the mode."""
        low = emit.mov_reg_gs('rax', 0x60)
        high = emit.mov_reg_gs('r8', 0x60)
        assert len(low) == len(high)
        assert low[3] & 0xC7 == high[3] & 0xC7   # same mod and rm fields
        assert low[4] == high[4]                 # same SIB byte


class TestControlFlow:
    def test_call_rel32_layout(self):
        blob = emit.call_rel32(0x20)
        assert blob[0] == 0xE8 and len(blob) == 5
        assert struct.unpack_from('<i', blob, 1)[0] == 0x20

    @needs_capstone
    def test_call_rel32_target(self):
        assert disasm(emit.call_rel32(0x20), 0x1000) == 'call 0x1025'

    @needs_capstone
    def test_negative_displacement(self):
        assert disasm(emit.jmp_rel32(-0x10), 0x1000) == 'jmp 0xff5'

    @needs_capstone
    def test_rip_relative_call_is_the_iat_form(self):
        assert disasm(emit.call_mem_rip(0x30), 0x1000) == 'call qword ptr [rip + 0x30]'

    @needs_capstone
    def test_rip_relative_jmp_is_the_thunk_form(self):
        assert disasm(emit.jmp_mem_rip(0x30), 0x1000) == 'jmp qword ptr [rip + 0x30]'

    def test_rip_call_displacement_offset(self):
        assert struct.unpack_from('<i', emit.call_mem_rip(0x1234), 2)[0] == 0x1234

    @needs_capstone
    @pytest.mark.parametrize('reg', ['rax', 'r11'])
    def test_indirect_register_call(self, reg):
        assert disasm(emit.call_reg(reg)) == f'call {reg}'

    def test_jcc_condition_is_validated(self):
        with pytest.raises(EncodingError, match='condition code'):
            emit.jcc_rel32(0x10)

    @needs_capstone
    def test_je_encodes_as_condition_four(self):
        assert disasm(emit.jcc_rel32(0x4, 0x10), 0x1000) == 'je 0x1016'

    def test_ret_imm16_range(self):
        assert emit.ret_imm16(0x18) == b'\xc2\x18\x00'
        with pytest.raises(EncodingError, match='imm16'):
            emit.ret_imm16(0x1_0000)


class TestStack:
    @needs_capstone
    @pytest.mark.parametrize('reg', ['rbp', 'r13'])
    def test_push_pop_round_trip(self, reg):
        assert disasm(emit.push_reg(reg)) == f'push {reg}'
        assert disasm(emit.pop_reg(reg)) == f'pop {reg}'

    def test_extended_push_carries_rex_b(self):
        assert emit.push_reg('r13')[0] == 0x41

    @needs_capstone
    def test_small_sub_uses_imm8(self):
        blob = emit.sub_rsp(0x20)
        assert len(blob) == 4
        assert disasm(blob) == 'sub rsp, 0x20'

    @needs_capstone
    def test_large_sub_uses_imm32(self):
        blob = emit.sub_rsp(0x2000)
        assert len(blob) == 7
        assert disasm(blob) == 'sub rsp, 0x2000'

    @needs_capstone
    def test_alignment_idiom(self):
        # capstone renders the sign-extended imm8 as a full 64-bit value
        assert disasm(emit.and_rsp(-16)) == 'and rsp, 0xfffffffffffffff0'

    def test_alignment_idiom_encodes_as_imm8(self):
        assert emit.and_rsp(-16) == b'\x48\x83\xe4\xf0'


class TestMisc:
    @needs_capstone
    def test_lea_rip_relative(self):
        assert disasm(emit.lea_reg_mem_rip('rcx', 0x40), 0x1000) == \
            'lea rcx, [rip + 0x40]'

    @needs_capstone
    @pytest.mark.parametrize('base', ['rax', 'rbp', 'rsp', 'r12', 'r13'])
    def test_dereference_handles_special_base_registers(self, base):
        """rbp/r13 need a disp form and rsp/r12 need a SIB byte."""
        assert disasm(emit.load_qword_at('rdx', base)).startswith('mov rdx, qword ptr')

    @needs_capstone
    def test_zero_reg_is_the_xor_idiom(self):
        assert disasm(emit.zero_reg('eax')) == 'xor eax, eax'

    @needs_capstone
    def test_mov_reg32_imm32_zero_extends(self):
        assert disasm(emit.mov_reg32_imm32('eax', 0x18)) == 'mov eax, 0x18'

    @pytest.mark.parametrize('count', list(range(0, 20)))
    def test_nop_run_has_the_requested_length(self, count):
        assert len(emit.nops(count)) == count

    @needs_capstone
    def test_nop_run_decodes_entirely_as_nops(self):
        blob = emit.nops(15)
        assert all(i.startswith('nop') for i in disasm_all(blob))

    def test_negative_nop_run_is_rejected(self):
        with pytest.raises(EncodingError, match='cannot be negative'):
            emit.nops(-1)
