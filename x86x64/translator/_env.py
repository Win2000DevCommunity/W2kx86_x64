"""Shared module scope for the translator.

Imports, feature flags, and the constant tables the translation
passes read. This module deliberately contains no logic and no
imports from the rest of :mod:`x86x64` beyond leaf data tables, so
every other module can depend on it without creating a cycle.
"""

from __future__ import annotations
import argparse, json, os, struct, sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Windows console UTF-8
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def _pure_translator_mode() -> bool:
    """Universal pure translator (no address-pinned _fix_cmd_* hacks)."""
    return bool(os.environ.get('CMD_NO_HACKS')
                or os.environ.get('PURE')
                or os.environ.get('PURE_TRANSLATOR'))


# Data files and the optional analyzer checkout live beside the repo root, two
# levels above this module.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Optional heavy imports (graceful fallback) ─────────────────────────────────
# win2k_analyzer (UBRT reference engine) — optional sibling checkout
_WIN2K_ANALYZER_DIR = os.path.join(_REPO_ROOT, 'win2k_analyzer')
if os.path.isdir(_WIN2K_ANALYZER_DIR) and _WIN2K_ANALYZER_DIR not in sys.path:
    sys.path.insert(0, _WIN2K_ANALYZER_DIR)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CsError
    from capstone.x86 import (
        X86_OP_IMM, X86_OP_REG, X86_OP_MEM,
        X86_REG_AL, X86_REG_AH, X86_REG_CL, X86_REG_CH,
        X86_REG_DL, X86_REG_DH, X86_REG_BL, X86_REG_BH,
        X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_BX,
        X86_REG_SP, X86_REG_BP, X86_REG_SI, X86_REG_DI,
        X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_EBX,
        X86_REG_ESP, X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
        X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
        X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
        X86_REG_R8,  X86_REG_R9,  X86_REG_R10, X86_REG_R11,
        X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
        X86_REG_RIP, X86_REG_FS,  X86_REG_GS,
    )
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("[!] capstone not installed  →  pip install capstone", file=sys.stderr)

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
    HAS_KEYSTONE = True
except ImportError:
    HAS_KEYSTONE = False
    print("[!] keystone not installed  →  pip install keystone-engine", file=sys.stderr)

try:
    from nt_analyzer.ubrt_engine import PEReferenceFinder, RefType, UBRTEngine
    HAS_UBRT = True
except ImportError:
    HAS_UBRT = False
    PEReferenceFinder = None  # type: ignore
    RefType = None  # type: ignore
    UBRTEngine = None  # type: ignore

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
    from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_BLOCK, UC_HOOK_MEM_INVALID, UC_HOOK_CODE
    from unicorn.x86_const import (
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
        UC_X86_REG_EIP,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False
    print("[!] unicorn not installed   →  pip install unicorn", file=sys.stderr)


# ══════════════════════════════════════════════════════════════════════════════
#  1.  SYSCALL TABLES
#      Source: extracted live from ntdll.dll (2000SP4OFFical2005v2.zip)
#      Win10 x64 numbers: from published direct-syscall security research
#      (builds 18362-22621 / 1903 – 22H2 / Win10 + Win11)
# ══════════════════════════════════════════════════════════════════════════════

#  (win2000_nr, win10_x64_nr, n_args, name)
#  n_args = bytes_popped_by_RET / 4 as observed in ntdll stubs
#  win10_x64_nr = 0x0000 means no direct equivalent yet mapped

# The Win2000 SSDT now lives in ``x86x64.syscall.table_data`` so the package
# and this module cannot drift apart. See tests/test_legacy_parity.py.
from x86x64.syscall.table_data import WIN2000_SYSCALL_TABLE

# Pre-built lookup maps
_W2K_NR_TO_INFO: Dict[int, Tuple[int,int,str]] = {}    # nr → (win10, n_args, name)
_W2K_NAME_TO_NR: Dict[str, int] = {}                   # name → win2000_nr
_WIN10_NAME_TO_NR: Dict[str, int] = {}                 # name → win10_nr

for (_w2k, _w10, _nargs, _name) in WIN2000_SYSCALL_TABLE:
    _W2K_NR_TO_INFO[_w2k] = (_w10, _nargs, _name)
    _W2K_NAME_TO_NR[_name] = _w2k
    if _w10:
        _WIN10_NAME_TO_NR[_name] = _w10

# TEB field remapping: FS:[32-bit offset] -> GS:[64-bit offset].
# Authoritative table lives in ``x86x64.abi.teb``.
from x86x64.abi.teb import FS_TO_GS as TEB_FS_TO_GS

# Win64 PE constants
IMAGE_REL_BASED_DIR64 = 10
IMAGE_REL_BASED_HIGHLOW = 3
PE64_DEFAULT_BASE = 0x180000000
# EXEs are rebased into the 2-4 GiB window. Two constraints meet here:
#   • base < 4 GiB  → image pointers stored in 32-bit .data slots (Win2000
#     binaries keep pointers 4 bytes wide) keep a zero high dword, so a 32-bit
#     `mov ecx,[global]` zero-extends to the correct 64-bit pointer. At
#     0x180000000 the high dword (0x1) was truncated and faulted.
#   • base > 2 GiB  → every image VA exceeds INT32_MAX, which forces the
#     RIP-relative emit helpers (_emit_iat_call/_jmp, abs mov) onto their
#     movabs fallback. Their rel32 fast-path mixes a build-time buffer offset
#     with an absolute VA and is incorrect; the high base keeps it unused.
PE64_EXE_BASE = 0x80000000
PE64_OPT_STD = 112          # optional header fields before data directories
PE64_OPT_TOTAL = 240        # PE32+ optional header including 16 data dirs
WIN64_ARG_REG_NAMES = ['rcx', 'rdx', 'r8', 'r9']
W32_ARG_REG_NAMES = ['ecx', 'edx', 'r8d', 'r9d']  # 32-bit views of the arg regs

# Canonical chkstk arg-spill prologue emitted between ``mov rax,imm`` and
# ``call __chkstk`` for large-frame functions: spill RCX/RDX/R8/R9 into the
# caller-provided shadow space and anchor R15 at entry_rsp+4 so the body's deep
# [esp+disp] incoming-parameter reads resolve to [r15+4+slot*8] == shadow slot.
# (mov [rsp+8],rcx; mov [rsp+0x10],rdx; mov [rsp+0x18],r8; mov [rsp+0x20],r9;
#  lea r15,[rsp+4]) — the entry detection skips exactly these bytes.
_CHKSTK_ARG_SPILL = bytes.fromhex(
    '48894c2408' '4889542410' '4c89442418' '4c894c2420' '4c8d7c2404')

# Frameless Win64 shadow-arg homes prepended before stdcall bodies that
# reload args via ``push [esp+N]`` after nested calls (``_home_frameless_
# win64_shadow_args``).  Callers must land on this block — not the first
# translated x86 insn — or RCX/RDX never reach the shadow slots.
_FRAMELESS_SHADOW_HOMES = bytes.fromhex(
    '48894c2408' '4889542410' '4c89442418' '4c894c2420')

# Syscall target for translated ntdll stubs:
#   win2000 — preserve Win2000 SSDT index (for our x64 NT 5.0 kernel)
#   win10   — map to Win10 x64 numbers (shim on modern Windows)
_SYSCALL_TARGET = 'win2000'




























_WIN10_SYSCALL_NAMES: Set[str] = set()


































_EMBEDDED_SPAN_MERGE_GAP = 64


























# ══════════════════════════════════════════════════════════════════════════════
#  Win10 DEV-ONLY import shim (--win10-test-shim)
#  Routes missing Win10 x64 System32 symbols to w2kshim64.dll for smoke tests.
#  Real Win2000 x64 uses translated kernel32/msvcrt with native Win2000 exports.
# ══════════════════════════════════════════════════════════════════════════════

W2KSHIM_DLL_NAME = 'w2kshim64.dll'
W2KSHIM_IMAGE_BASE = 0x1_8001_00000
W2KSHIM_EXCEPT_HANDLER3_RVA = 0x10C0   # updated by build_w2kshim64_dll()


def w2kshim_except_handler3_va() -> int:
    """Absolute VA of shim ``_except_handler3`` (reads live RVA after DLL build)."""
    return (W2KSHIM_IMAGE_BASE + W2KSHIM_EXCEPT_HANDLER3_RVA) & 0xFFFFFFFFFFFFFFFF

# Rewrite import to a different symbol/DLL that exists on Win10 x64.
IMPORT_ALIASES: Dict[Tuple[str, str], Tuple[str, str]] = {
    # _setjmp3 MUST NOT alias to MSVCRT!_setjmp — x64 jmp_buf layout differs from
    # VC6 x86 and corrupts longjmp / NtContinue (stack RIP).  Routed to w2kshim64.
}

# Symbols implemented inside w2kshim64.dll (export name → stub kind).
IMPORT_SHIM_EXPORTS: Dict[Tuple[str, str], str] = {
    ('kernel32.dll', 'InterlockedExchange'): 'InterlockedExchange',
    ('kernel32.dll', 'VirtualQuery'): 'VirtualQuery',
    # Win32 CRITICAL_SECTION is 0x18; Win64 is 0x28.  Native Init/Enter/Leave
    # on guest .data overflows adjacent state.  Shim maps guest VA → host CS.
    ('kernel32.dll', 'InitializeCriticalSection'): 'InitializeCriticalSection',
    ('kernel32.dll', 'EnterCriticalSection'): 'EnterCriticalSection',
    ('kernel32.dll', 'LeaveCriticalSection'): 'LeaveCriticalSection',
    ('kernel32.dll', 'DeleteCriticalSection'): 'DeleteCriticalSection',
    # Win10 returns 0 from the native export; cmd's ANSI→OEM path converter
    # then skips and leaves garbage cwd state.  Shim returns a tiny fake list.
    ('kernel32.dll', 'GetVDMCurrentDirectories'): 'GetVDMCurrentDirectories',
    ('msvcrt.dll', '_setjmp3'): '_setjmp3',
    ('msvcrt.dll', 'longjmp'): 'longjmp',
    ('msvcrt.dll', '_except_handler3'): '_except_handler3',
    ('msvcrt.dll', '_seh_longjmp_unwind'): '_seh_longjmp_unwind',
    ('msvcrt.dll', '__p___initenv'): '__p___initenv',
    ('msvcrt.dll', '_adjust_fdiv'): '_adjust_fdiv',
    ('msvcrt.dll', '__p__commode'): '__p__commode',
    ('msvcrt.dll', '__p__fmode'): '__p__fmode',
    ('msvcrt.dll', 'towupper'): 'towupper',
    ('msvcrt.dll', 'towlower'): 'towlower',
    # Win10 msvcrt leaves __pioinfo null for Win2000 CRT startups; route
    # std fds through GetStdHandle instead of the crashing native export.
    ('msvcrt.dll', '_get_osfhandle'): '_get_osfhandle',
}

# In-place renames: replace function name within the SAME DLL.
# Used for x64-incompatible exports like _controlfp that need a
# same-DLL replacement to preserve IAT slot layout.
IMPORT_RENAMES: Dict[Tuple[str, str], str] = {
    # _controlfp: x64 msvcrt dropped this.  abs() exists on x64,
    # has a compatible (int)->int signature, and is harmless.
    ('msvcrt.dll', '_controlfp'): 'rand',
}


















# ══════════════════════════════════════════════════════════════════════════════
#  2.  PE32 IMAGE PARSER
# ══════════════════════════════════════════════════════════════════════════════



# ══════════════════════════════════════════════════════════════════════════════
#  3.  NTDLL STUB DETECTOR
#      Finds the exact byte pattern used by all 247 Win2000 stubs
# ══════════════════════════════════════════════════════════════════════════════







# ══════════════════════════════════════════════════════════════════════════════
#  4.  DYNAMIC POINTER SCANNER  (Unicorn Engine)
#      Emulates the 32-bit binary to discover runtime-computed pointers
#      that static analysis cannot see (e.g. switch tables, computed jumps)
# ══════════════════════════════════════════════════════════════════════════════



# ══════════════════════════════════════════════════════════════════════════════
#  5.  CODE TRANSLATOR  (Capstone → Keystone)
# ══════════════════════════════════════════════════════════════════════════════

# Linux syscall ABI register mapping kept for ELF compatibility
LINUX_SYSCALL_REGMAP = {
    X86_REG_EAX: X86_REG_RAX,
    X86_REG_EBX: X86_REG_RDI,
    X86_REG_ECX: X86_REG_RSI,
    X86_REG_EDX: X86_REG_RDX,
    X86_REG_ESI: X86_REG_R10,
    X86_REG_EDI: X86_REG_R8,
    X86_REG_EBP: X86_REG_R9,
} if HAS_CAPSTONE else {}

# Windows x64 ABI: argument slot → 64-bit register name (see module-level WIN64_ARG_REG_NAMES)

# Win32 register name → Win64 equivalent (same family, wider)
W32_TO_W64_REG: Dict[int,str] = {} if not HAS_CAPSTONE else {
    X86_REG_EAX: 'rax',  X86_REG_ECX: 'rcx',
    X86_REG_EDX: 'rdx',  X86_REG_EBX: 'rbx',
    X86_REG_ESP: 'rsp',  X86_REG_EBP: 'rbp',
    X86_REG_ESI: 'rsi',  X86_REG_EDI: 'rdi',
    X86_REG_AX: 'rax',  X86_REG_CX: 'rcx',
    X86_REG_DX: 'rdx',  X86_REG_BX: 'rbx',
    X86_REG_SP: 'rsp',  X86_REG_BP: 'rbp',
    X86_REG_SI: 'rsi',  X86_REG_DI: 'rdi',
}

# x86 ESI/EDI are callee-saved; Win64 RSI/RDI are caller-saved. Import fn ptrs
# loaded once and reused across calls must live in x64 callee-saved regs.
_IAT_FN_HOLDER_W64: Dict[int, str] = {} if not HAS_CAPSTONE else {
    X86_REG_ESI: 'r14',
    X86_REG_EDI: 'r15',
}

W32_REG_ASM: Dict[int, str] = {} if not HAS_CAPSTONE else {
    X86_REG_EAX: 'eax',  X86_REG_ECX: 'ecx',
    X86_REG_EDX: 'edx',  X86_REG_EBX: 'ebx',
    X86_REG_ESP: 'esp',  X86_REG_EBP: 'ebp',
    X86_REG_ESI: 'esi',  X86_REG_EDI: 'edi',
    X86_REG_AX: 'ax',  X86_REG_CX: 'cx',
    X86_REG_DX: 'dx',  X86_REG_BX: 'bx',
    X86_REG_SP: 'sp',  X86_REG_BP: 'bp',
    X86_REG_SI: 'si',  X86_REG_DI: 'di',
}

W32_WORD_REG_ASM: Dict[int, str] = {} if not HAS_CAPSTONE else {
    X86_REG_EAX: 'ax',  X86_REG_ECX: 'cx',
    X86_REG_EDX: 'dx',  X86_REG_EBX: 'bx',
    X86_REG_ESI: 'si',  X86_REG_EDI: 'di',
    X86_REG_EBP: 'bp',  X86_REG_ESP: 'sp',
    X86_REG_AX: 'ax',  X86_REG_CX: 'cx',
    X86_REG_DX: 'dx',  X86_REG_BX: 'bx',
    X86_REG_SP: 'sp',  X86_REG_BP: 'bp',
    X86_REG_SI: 'si',  X86_REG_DI: 'di',
}

W32_BYTE_REG_ASM: Dict[int, str] = {} if not HAS_CAPSTONE else {
    X86_REG_AL: 'al',  X86_REG_AH: 'ah',
    X86_REG_CL: 'cl',  X86_REG_CH: 'ch',
    X86_REG_DL: 'dl',  X86_REG_DH: 'dh',
    X86_REG_BL: 'bl',  X86_REG_BH: 'bh',
}

W32_TO_BYTE_REG: Dict[int, str] = {} if not HAS_CAPSTONE else {
    X86_REG_EAX: 'al',  X86_REG_ECX: 'cl',
    X86_REG_EDX: 'dl',  X86_REG_EBX: 'bl',
    X86_REG_ESI: 'sil', X86_REG_EDI: 'dil',
    X86_REG_EBP: 'bpl', X86_REG_ESP: 'spl',
}

_W64_REG_NUM: Dict[str, int] = {
    'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4, 'rbp': 5,
    'rsi': 6, 'rdi': 7, 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
    'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
}

_UBRT_BRANCH_TYPES = frozenset({
    'rel_call', 'rel_jump_near', 'rel_jump_short',
    'rel_cond_near', 'rel_cond_short',
})




# ══════════════════════════════════════════════════════════════════════════════
#  6.  BATCH PROCESSOR
#      Walk an entire Win2000 SP4 directory tree, translate every PE
# ══════════════════════════════════════════════════════════════════════════════



# Priority order for building the x64 system base (ntdll first — syscall table source)
CORE_SYSTEM_FILES = (
    'ntdll.dll', 'kernel32.dll', 'advapi32.dll', 'user32.dll', 'gdi32.dll',
    'rpcrt4.dll', 'ole32.dll', 'shell32.dll', 'shlwapi.dll', 'browseui.dll',
    'ntoskrnl.exe', 'winlogon.exe', 'lsass.exe', 'services.exe', 'cmd.exe',
    'csrsrv.dll', 'basesrv.dll', 'authz.dll', 'secur32.dll', 'msvcrt.dll',
)




# Computed rather than listed: several names here are bound inside ``try``
# blocks that probe for optional dependencies, and the underscore-prefixed
# constants have to travel through ``import *`` as well.
__all__ = [_n for _n in dir() if not _n.startswith('__')]
