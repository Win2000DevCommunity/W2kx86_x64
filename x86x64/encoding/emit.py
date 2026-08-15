"""
Hand-rolled x86-64 instruction encoders.

These exist because the emitters need byte-exact, dependency-free output whose
length is known before it is written -- an assembler round-trip cannot promise
either.  Every helper returns ``bytes``; nothing here knows about addresses, so
anything address-shaped is emitted as a zero field for a relocation to fill.

REX handling is explicit.  The legacy encoders folded the register number
straight into the ModRM byte, which silently corrupted the addressing mode for
``r8``-``r15`` (``8 << 3`` overflows into the mod field); :func:`modrm` rejects
that instead.
"""

from __future__ import annotations

import struct
from typing import Optional

from ..errors import EncodingError
from .regs import reg_num

# -- prefixes and shared fields ------------------------------------------
PREFIX_GS = 0x65
PREFIX_FS = 0x64
PREFIX_OPSIZE = 0x66

REX_BASE = 0x40
REX_W = 0x08
REX_R = 0x04
REX_X = 0x02
REX_B = 0x01

MOD_INDIRECT = 0b00
MOD_DISP8 = 0b01
MOD_DISP32 = 0b10
MOD_REGISTER = 0b11

RM_SIB = 0b100
RM_DISP32 = 0b101
SIB_NO_INDEX_DISP32 = 0x25   # scale=1, index=none, base=none -> disp32


def rex(*, w: bool = False, r: bool = False, x: bool = False,
        b: bool = False) -> int:
    """Build a REX prefix byte."""
    return (REX_BASE | (REX_W if w else 0) | (REX_R if r else 0)
            | (REX_X if x else 0) | (REX_B if b else 0))


def modrm(mod: int, reg: int, rm: int) -> int:
    """Build a ModRM byte from the low three bits of *reg* and *rm*."""
    if not 0 <= mod <= 3:
        raise EncodingError(f'ModRM mod field {mod} out of range')
    if not 0 <= reg <= 15 or not 0 <= rm <= 15:
        raise EncodingError(f'ModRM reg/rm out of range: reg={reg} rm={rm}')
    return (mod << 6) | ((reg & 7) << 3) | (rm & 7)


def sib(scale: int, index: int, base: int) -> int:
    shift = {1: 0, 2: 1, 4: 2, 8: 3}.get(scale)
    if shift is None:
        raise EncodingError(f'SIB scale must be 1, 2, 4, or 8; got {scale}')
    return (shift << 6) | ((index & 7) << 3) | (base & 7)


# -- data movement --------------------------------------------------------
def mov_reg_imm64(dst: str, imm: int) -> bytes:
    """``movabs dst, imm64`` -- 10 bytes, immediate at offset 2."""
    n = reg_num(dst)
    return (bytes([rex(w=True, b=n >= 8), 0xB8 | (n & 7)])
            + struct.pack('<Q', imm & 0xFFFF_FFFF_FFFF_FFFF))


#: Byte offset of the immediate inside :func:`mov_reg_imm64` output.
MOVABS_IMM_OFFSET = 2
MOVABS_SIZE = 10


def mov_reg_imm64_reloc(dst: str) -> bytes:
    """``movabs dst, 0`` with the immediate left for a relocation to fill."""
    return mov_reg_imm64(dst, 0)


def mov_reg32_imm32(dst: str, imm: int) -> bytes:
    """``mov dst32, imm32`` -- zero-extends into the full 64-bit register."""
    n = reg_num(dst)
    out = bytearray()
    if n >= 8:
        out.append(rex(b=True))
    out.append(0xB8 | (n & 7))
    out += struct.pack('<I', imm & 0xFFFF_FFFF)
    return bytes(out)


def mov_reg_reg(dst: str, src: str) -> bytes:
    """``mov dst64, src64``."""
    d, s = reg_num(dst), reg_num(src)
    return bytes([rex(w=True, r=s >= 8, b=d >= 8), 0x89, modrm(MOD_REGISTER, s, d)])


def _seg_abs(prefix: int, opcode: int, reg: str, disp: int) -> bytes:
    """``mov`` between *reg* and ``seg:[disp32]`` using the no-base SIB form."""
    n = reg_num(reg)
    return (bytes([prefix, rex(w=True, r=n >= 8), opcode,
                   modrm(MOD_INDIRECT, n, RM_SIB), SIB_NO_INDEX_DISP32])
            + struct.pack('<I', disp & 0xFFFF_FFFF))


def mov_reg_gs(dst: str, disp: int) -> bytes:
    """``mov dst64, qword gs:[disp32]`` -- a translated ``fs:`` TEB read."""
    return _seg_abs(PREFIX_GS, 0x8B, dst, disp)


def mov_gs_reg(src: str, disp: int) -> bytes:
    """``mov qword gs:[disp32], src64`` -- a translated ``fs:`` TEB write."""
    return _seg_abs(PREFIX_GS, 0x89, src, disp)


def mov_reg_mem_rip(dst: str, disp: int = 0) -> bytes:
    """``mov dst64, qword [rip+disp32]`` -- displacement at offset 3."""
    n = reg_num(dst)
    return (bytes([rex(w=True, r=n >= 8), 0x8B, modrm(MOD_INDIRECT, n, RM_DISP32)])
            + struct.pack('<i', disp))


#: Byte offset of the displacement inside the RIP-relative helpers.
RIP_DISP_OFFSET = 3


def mov_mem_rip_reg(src: str, disp: int = 0) -> bytes:
    """``mov qword [rip+disp32], src64``."""
    n = reg_num(src)
    return (bytes([rex(w=True, r=n >= 8), 0x89, modrm(MOD_INDIRECT, n, RM_DISP32)])
            + struct.pack('<i', disp))


def load_qword_at(dst: str, base: str) -> bytes:
    """``mov dst64, qword [base64]`` -- dereference a pointer already in *base*."""
    d, b = reg_num(dst), reg_num(base)
    out = bytearray([rex(w=True, r=d >= 8, b=b >= 8), 0x8B])
    # rbp/r13 have no mod=00 form, and rsp/r12 need a SIB byte.
    if (b & 7) == 5:
        out += bytes([modrm(MOD_DISP8, d, b), 0x00])
    elif (b & 7) == 4:
        out += bytes([modrm(MOD_INDIRECT, d, RM_SIB), sib(1, 4, b)])
    else:
        out.append(modrm(MOD_INDIRECT, d, b))
    return bytes(out)


# -- stack ----------------------------------------------------------------
def push_reg(reg: str) -> bytes:
    n = reg_num(reg)
    return bytes([rex(b=True), 0x50 | (n & 7)]) if n >= 8 else bytes([0x50 | n])


def pop_reg(reg: str) -> bytes:
    n = reg_num(reg)
    return bytes([rex(b=True), 0x58 | (n & 7)]) if n >= 8 else bytes([0x58 | n])


def _rsp_imm(op_ext: int, amount: int) -> bytes:
    """``add``/``sub rsp, imm`` picking the imm8 form when it fits."""
    if -128 <= amount <= 127:
        return bytes([rex(w=True), 0x83, modrm(MOD_REGISTER, op_ext, 4),
                      amount & 0xFF])
    return (bytes([rex(w=True), 0x81, modrm(MOD_REGISTER, op_ext, 4)])
            + struct.pack('<i', amount))


def sub_rsp(amount: int) -> bytes:
    return _rsp_imm(5, amount)


def add_rsp(amount: int) -> bytes:
    return _rsp_imm(0, amount)


def and_rsp(mask: int) -> bytes:
    """``and rsp, imm8`` -- the 16-byte alignment idiom uses ``-16``."""
    if not -128 <= mask <= 127:
        raise EncodingError(f'and rsp, {mask} needs an imm8')
    return bytes([rex(w=True), 0x83, modrm(MOD_REGISTER, 4, 4), mask & 0xFF])


# -- control flow ---------------------------------------------------------
CALL_REL32 = 0xE8
JMP_REL32 = 0xE9
JCC_REL32_PREFIX = 0x0F


def call_rel32(disp: int = 0) -> bytes:
    """``call rel32`` -- displacement at offset 1."""
    return bytes([CALL_REL32]) + struct.pack('<i', disp)


def jmp_rel32(disp: int = 0) -> bytes:
    return bytes([JMP_REL32]) + struct.pack('<i', disp)


def jcc_rel32(condition: int, disp: int = 0) -> bytes:
    """Near conditional jump; *condition* is the low nibble (0x84 == je)."""
    if not 0 <= condition <= 0xF:
        raise EncodingError(f'condition code {condition:#x} out of range')
    return bytes([JCC_REL32_PREFIX, 0x80 | condition]) + struct.pack('<i', disp)


def call_mem_rip(disp: int = 0) -> bytes:
    """``call qword [rip+disp32]`` -- the IAT dispatch form, disp at offset 2."""
    return bytes([0xFF, modrm(MOD_INDIRECT, 2, RM_DISP32)]) + struct.pack('<i', disp)


def jmp_mem_rip(disp: int = 0) -> bytes:
    """``jmp qword [rip+disp32]`` -- an import thunk's tail jump."""
    return bytes([0xFF, modrm(MOD_INDIRECT, 4, RM_DISP32)]) + struct.pack('<i', disp)


def call_reg(reg: str) -> bytes:
    n = reg_num(reg)
    out = bytearray()
    if n >= 8:
        out.append(rex(b=True))
    out += bytes([0xFF, modrm(MOD_REGISTER, 2, n)])
    return bytes(out)


def jmp_reg(reg: str) -> bytes:
    n = reg_num(reg)
    out = bytearray()
    if n >= 8:
        out.append(rex(b=True))
    out += bytes([0xFF, modrm(MOD_REGISTER, 4, n)])
    return bytes(out)


RET = b'\xc3'
INT3 = b'\xcc'
NOP = b'\x90'
LEAVE = b'\xc9'


def ret() -> bytes:
    return RET


def ret_imm16(pop: int) -> bytes:
    """``ret imm16`` -- a stdcall callee cleaning its own arguments."""
    if not 0 <= pop <= 0xFFFF:
        raise EncodingError(f'ret {pop} does not fit in imm16')
    return b'\xc2' + struct.pack('<H', pop)


def nops(count: int) -> bytes:
    """*count* bytes of padding using the multi-byte NOP forms."""
    if count < 0:
        raise EncodingError('nop run cannot be negative')
    forms = {
        1: b'\x90',
        2: b'\x66\x90',
        3: b'\x0f\x1f\x00',
        4: b'\x0f\x1f\x40\x00',
        5: b'\x0f\x1f\x44\x00\x00',
        6: b'\x66\x0f\x1f\x44\x00\x00',
        7: b'\x0f\x1f\x80\x00\x00\x00\x00',
        8: b'\x0f\x1f\x84\x00\x00\x00\x00\x00',
        9: b'\x66\x0f\x1f\x84\x00\x00\x00\x00\x00',
    }
    out = bytearray()
    while count >= 9:
        out += forms[9]
        count -= 9
    if count:
        out += forms[count]
    return bytes(out)


# -- arithmetic -----------------------------------------------------------
def lea_reg_mem_rip(dst: str, disp: int = 0) -> bytes:
    """``lea dst64, [rip+disp32]`` -- displacement at offset 3."""
    n = reg_num(dst)
    return (bytes([rex(w=True, r=n >= 8), 0x8D, modrm(MOD_INDIRECT, n, RM_DISP32)])
            + struct.pack('<i', disp))


def lea_reg_base_disp(dst: str, base: str, disp: int) -> bytes:
    """``lea dst64, [base64+disp]``."""
    d, b = reg_num(dst), reg_num(base)
    out = bytearray([rex(w=True, r=d >= 8, b=b >= 8), 0x8D])
    mod = MOD_DISP8 if -128 <= disp <= 127 else MOD_DISP32
    if (b & 7) == 4:
        out += bytes([modrm(mod, d, RM_SIB), sib(1, 4, b)])
    else:
        out.append(modrm(mod, d, b))
    out += (bytes([disp & 0xFF]) if mod == MOD_DISP8 else struct.pack('<i', disp))
    return bytes(out)


def xor_reg_reg(dst: str, src: str) -> bytes:
    d, s = reg_num(dst), reg_num(src)
    return bytes([rex(w=True, r=s >= 8, b=d >= 8), 0x31, modrm(MOD_REGISTER, s, d)])


def zero_reg(reg: str) -> bytes:
    """``xor r32, r32`` -- shorter than the 64-bit form and clears the top half."""
    n = reg_num(reg)
    out = bytearray()
    if n >= 8:
        out.append(rex(r=True, b=True))
    out += bytes([0x31, modrm(MOD_REGISTER, n, n)])
    return bytes(out)
