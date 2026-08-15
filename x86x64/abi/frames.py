"""EBP-relative frame arithmetic for translating stack access to the x64 ABI.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403


def ebp_disp_to_win64_arg(disp: int) -> Optional[str]:
    """Map 32-bit [EBP+disp] stack slot to Win64 register or stack home."""
    if disp >= 8 and (disp - 8) % 4 == 0 and disp <= 0x40:
        idx = (disp - 8) // 4
        if idx < 4:
            return WIN64_ARG_REG_NAMES[idx]
        return f'[rsp+0x{0x28 + (idx - 4) * 8:x}]'
    return None
def ebp_disp_to_rbp_home(disp: int) -> Optional[int]:
    """Map x86 [EBP+disp] arg slot to x64 [RBP+off] MSVC home (past saved RBP + retaddr)."""
    if disp >= 8 and (disp - 8) % 4 == 0 and disp <= 0x40:
        idx = (disp - 8) // 4
        if idx < 4:
            return 0x10 + idx * 8
        # Register homes end at [RBP+0x28] (R9); stack args start at [RBP+0x30].
        return 0x30 + (idx - 4) * 8
    return None
def ebp_arg_slot_to_rbp_home(slot: int) -> int:
    """Map ebp_arg slot ``(disp-8)//4`` to MSVC ``[RBP+off]`` home."""
    home = ebp_disp_to_rbp_home(8 + slot * 4)
    return home if home is not None else (0x10 + slot * 8)
def ebp_disp_to_rbp_stack_off(disp: int) -> Optional[int]:
    """Byte offset from RBP for x86 [EBP+disp] stack bytes (args homed at +0x10)."""
    if disp >= 8 and disp < 0x80:
        return 0x10 + (disp - 8)
    return None
