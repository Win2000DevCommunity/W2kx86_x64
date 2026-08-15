"""System-call layer: the SSDT table, number resolution, and stub translation.

Win2000 enters the kernel with ``int 0x2e`` (EAX = index, EDX = pointer to the
stacked arguments).  x64 uses the ``syscall`` instruction with arguments
already in RCX/RDX/R8/R9, so a translated stub only has to park argument one
in R10, load the index, and trap.
"""

from .stubs import (
    STUB_SIZE,
    X64_MOV_R10_RCX,
    X64_RET,
    X64_SYSCALL,
    StubInfo,
    StubMechanism,
    StubTranslation,
    decode_stub,
    emit_unmapped_stub,
    emit_x64_stub,
    extract_stubs,
    translate_stub,
    translate_stubs,
)
from .table import (
    WIN2000_SYSCALL_TABLE,
    SyscallEntry,
    SyscallTable,
    SyscallTarget,
    default_table,
    reset_default_table,
)

__all__ = [
    'STUB_SIZE', 'WIN2000_SYSCALL_TABLE', 'X64_MOV_R10_RCX', 'X64_RET',
    'X64_SYSCALL', 'StubInfo', 'StubMechanism', 'StubTranslation',
    'SyscallEntry', 'SyscallTable', 'SyscallTarget', 'decode_stub',
    'default_table', 'emit_unmapped_stub', 'emit_x64_stub', 'extract_stubs',
    'reset_default_table', 'translate_stub', 'translate_stubs',
]
