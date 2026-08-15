"""x86-64 register names, encodings, and 32->64 bit widening."""

from __future__ import annotations

from typing import Dict, Optional

from ..errors import EncodingError

#: Encoded register number. Values >= 8 require a REX extension bit.
REG64: Dict[str, int] = {
    'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
    'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
    'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
    'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
}

REG32: Dict[str, int] = {
    'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3,
    'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7,
    'r8d': 8, 'r9d': 9, 'r10d': 10, 'r11d': 11,
    'r12d': 12, 'r13d': 13, 'r14d': 14, 'r15d': 15,
}

#: The x86 register a translated x64 register stands in for.
WIDEN: Dict[str, str] = {
    'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx',
    'esp': 'rsp', 'ebp': 'rbp', 'esi': 'rsi', 'edi': 'rdi',
}
NARROW: Dict[str, str] = {v: k for k, v in WIDEN.items()}

#: Microsoft x64 integer argument registers, in order.
ARG_REGS64 = ('rcx', 'rdx', 'r8', 'r9')
ARG_REGS32 = ('ecx', 'edx', 'r8d', 'r9d')

#: Registers a callee may clobber under the Microsoft x64 ABI.
VOLATILE = frozenset({'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'})
#: Registers a callee must preserve.
NONVOLATILE = frozenset({'rbx', 'rbp', 'rdi', 'rsi', 'rsp',
                         'r12', 'r13', 'r14', 'r15'})

#: Bytes of shadow ("home") space the caller reserves for RCX/RDX/R8/R9.
SHADOW_SPACE = 32
#: Required stack alignment at the point a ``call`` executes.
STACK_ALIGN = 16


def reg_num(name: str) -> int:
    """Encoding number for a 64- or 32-bit register name."""
    key = name.lower().lstrip('%')
    if key in REG64:
        return REG64[key]
    if key in REG32:
        return REG32[key]
    raise EncodingError(f'unknown register {name!r}')


def is_extended(name: str) -> bool:
    """True for r8-r15 (and their 32-bit views), which need a REX bit."""
    return reg_num(name) >= 8


def widen(name: str) -> str:
    """The 64-bit register a 32-bit x86 register maps to."""
    key = name.lower()
    if key in WIDEN:
        return WIDEN[key]
    if key in REG64:
        return key
    if key in REG32:
        return 'r' + key[1:-1] if key.endswith('d') else key
    raise EncodingError(f'cannot widen {name!r}')


def narrow(name: str) -> str:
    """The 32-bit view of a 64-bit register."""
    key = name.lower()
    if key in NARROW:
        return NARROW[key]
    if key in REG64:
        return key + 'd'
    if key in REG32:
        return key
    raise EncodingError(f'cannot narrow {name!r}')


def arg_reg(index: int, *, width: int = 64) -> str:
    """The *index*-th integer argument register, 0-based."""
    regs = ARG_REGS64 if width == 64 else ARG_REGS32
    if not 0 <= index < len(regs):
        raise EncodingError(
            f'argument {index} is passed on the stack, not in a register')
    return regs[index]


def is_volatile(name: str) -> bool:
    return widen(name) in VOLATILE
