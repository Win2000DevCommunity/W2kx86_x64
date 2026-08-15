"""
Calling-convention translation: Win32 stdcall/cdecl to Microsoft x64.

Win32 pushes arguments right-to-left onto the stack; the callee pops them under
stdcall, the caller under cdecl.  Microsoft x64 puts the first four integer
arguments in RCX/RDX/R8/R9, the rest on the stack starting at ``[rsp+0x20]``,
always reserves 32 bytes of shadow space, requires 16-byte stack alignment at
the ``call``, and makes the caller responsible for cleanup in every case.

The helpers here answer "where does argument *n* live" and "how big is the
frame" so the emitters do not each re-derive the layout.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..encoding.regs import ARG_REGS32, ARG_REGS64, SHADOW_SPACE, STACK_ALIGN


class CallConv(enum.Enum):
    """The 32-bit convention a translated function was compiled with."""

    STDCALL = 'stdcall'
    CDECL = 'cdecl'
    FASTCALL = 'fastcall'
    THISCALL = 'thiscall'

    @property
    def callee_cleans_stack(self) -> bool:
        return self in (CallConv.STDCALL, CallConv.FASTCALL, CallConv.THISCALL)

    @property
    def register_args(self) -> Tuple[str, ...]:
        """32-bit registers the convention passes arguments in, in order."""
        if self is CallConv.FASTCALL:
            return ('ecx', 'edx')
        if self is CallConv.THISCALL:
            return ('ecx',)
        return ()


#: First stack argument offset from RSP at the callee's entry, past the shadow
#: space. The return address sits at [rsp+0] on entry, so the caller writes
#: argument five at [rsp+0x20] and the callee reads it at [rsp+0x28].
FIRST_STACK_ARG_CALLER = SHADOW_SPACE          # 0x20
FIRST_STACK_ARG_CALLEE = SHADOW_SPACE + 8      # 0x28

#: Offset of the first incoming argument from a standard x86 [ebp+disp] frame,
#: past the saved EBP and the return address.
X86_FIRST_ARG_DISP = 8

#: Where argument N is homed relative to RBP in an MSVC x64 frame that has
#: pushed RBP: [rbp+0x10] is argument one's home slot.
RBP_HOME_BASE = 0x10


@dataclass(frozen=True)
class ArgLocation:
    """Where one argument lives after translation."""

    index: int
    register: Optional[str] = None
    stack_offset: Optional[int] = None

    @property
    def in_register(self) -> bool:
        return self.register is not None

    def __str__(self) -> str:
        if self.register:
            return f'arg{self.index}={self.register}'
        return f'arg{self.index}=[rsp+0x{self.stack_offset:x}]'


def arg_location(index: int, *, width: int = 64,
                 caller_side: bool = True) -> ArgLocation:
    """
    Where the *index*-th argument (0-based) lives under the x64 ABI.

    ``caller_side`` selects the offset used when writing arguments before a
    ``call``; the callee sees the same slots 8 bytes higher because of the
    pushed return address.
    """
    if index < 0:
        raise ValueError(f'argument index {index} is negative')
    regs = ARG_REGS64 if width == 64 else ARG_REGS32
    if index < len(regs):
        return ArgLocation(index, register=regs[index])
    base = FIRST_STACK_ARG_CALLER if caller_side else FIRST_STACK_ARG_CALLEE
    return ArgLocation(index, stack_offset=base + (index - 4) * 8)


def arg_locations(count: int, *, width: int = 64,
                  caller_side: bool = True) -> List[ArgLocation]:
    return [arg_location(i, width=width, caller_side=caller_side)
            for i in range(count)]


def stack_bytes_for_args(count: int) -> int:
    """
    Bytes of stack a call site must reserve for *count* arguments.

    Always at least the 32-byte shadow space, and always a multiple of 16 so
    RSP stays aligned when the ``call`` pushes its return address.
    """
    spill = max(0, count - len(ARG_REGS64)) * 8
    total = SHADOW_SPACE + spill
    return (total + STACK_ALIGN - 1) & ~(STACK_ALIGN - 1)


def x86_arg_index(ebp_disp: int) -> Optional[int]:
    """
    Argument index for an x86 ``[ebp+disp]`` reference, or ``None``.

    Arguments start at ``[ebp+8]``; anything below that is the saved frame
    pointer or a local.
    """
    if ebp_disp < X86_FIRST_ARG_DISP or (ebp_disp - X86_FIRST_ARG_DISP) % 4:
        return None
    return (ebp_disp - X86_FIRST_ARG_DISP) // 4


def x86_disp_to_rbp_home(ebp_disp: int, *, max_disp: int = 0x40) -> Optional[int]:
    """
    Map an x86 ``[ebp+disp]`` argument slot to its x64 ``[rbp+off]`` home.

    The four register arguments are homed at ``[rbp+0x10]`` through
    ``[rbp+0x28]``; stack arguments continue at ``[rbp+0x30]``.
    """
    index = x86_arg_index(ebp_disp)
    if index is None or ebp_disp > max_disp:
        return None
    if index < len(ARG_REGS64):
        return RBP_HOME_BASE + index * 8
    return RBP_HOME_BASE + SHADOW_SPACE + (index - len(ARG_REGS64)) * 8


def arg_slot_to_rbp_home(slot: int) -> int:
    """``[rbp+off]`` home for argument *slot*, counting from zero."""
    home = x86_disp_to_rbp_home(X86_FIRST_ARG_DISP + slot * 4)
    return home if home is not None else RBP_HOME_BASE + slot * 8


def x86_disp_to_rbp_local(ebp_disp: int) -> Optional[int]:
    """
    Byte offset from RBP for raw x86 ``[ebp+disp]`` stack bytes.

    Used when a reference lands inside an argument block rather than on a
    slot boundary -- struct copies, for instance.
    """
    if X86_FIRST_ARG_DISP <= ebp_disp < 0x80:
        return RBP_HOME_BASE + (ebp_disp - X86_FIRST_ARG_DISP)
    return None


def ret_pop_to_arg_count(ret_pop: int) -> int:
    """Argument count implied by a stdcall ``ret n``."""
    return ret_pop // 4


def is_aligned(rsp_value: int) -> bool:
    """Whether *rsp_value* satisfies the ABI's 16-byte call alignment."""
    return rsp_value % STACK_ALIGN == 0
