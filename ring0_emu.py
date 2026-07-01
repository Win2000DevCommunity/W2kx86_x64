#!/usr/bin/env python3
"""
Ring-0 / Ring-3 x64 emulator for translated Win2000 PE64 binaries.

Uses Unicorn Engine (x86-64) with mock kernel APIs adapted from
win2k_analyzer's KernelEmulator / KernelEnvironment.

  UserMode64Emu   — ring-3 PE64 (cmd, ntdll stubs, SYSCALL hook)
  Ring0Environment64 — ring-0 kernel (ntoskrnl + import stubs + KPCR)

Usage:
  python ring0_emu.py --test ntdll NtClose
  python ring0_emu.py --test kernel NtClose
  python ring0_emu.py --test cmd-entry
  python ring0_emu.py --test cmd-gpa-trace     # GPA RBP/stack diagnostic
  python ring0_emu.py --test cmd-entry --trace --strict
  python ring0_emu.py --test all
"""

from __future__ import annotations

import argparse
import glob
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

try:
    import pefile
except ImportError:
    pefile = None  # type: ignore

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_IMM
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    from unicorn import (
        Uc, UC_ARCH_X86, UC_MODE_64,
        UC_HOOK_CODE,
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_INTR,
        UC_HOOK_MEM_WRITE,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
        UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_RBX,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_RIP, UC_X86_REG_RFLAGS, UC_X86_REG_GS_BASE, UC_X86_REG_R12,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

# win2k_analyzer kernel mocks (x86 stdcall — we adapt arg reading for x64)
_ANALYZER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'win2k_analyzer')
if os.path.isdir(_ANALYZER) and _ANALYZER not in sys.path:
    sys.path.insert(0, _ANALYZER)

try:
    from nt_analyzer.emulator import (
        KernelMocks, EmulationException,
        STATUS_SUCCESS, STATUS_ACCESS_VIOLATION, ntstatus_name,
    )
    HAS_KMOCKS = True
except ImportError:
    HAS_KMOCKS = False
    KernelMocks = None  # type: ignore

# ── Layout constants ───────────────────────────────────────────────────────

_PAGE = 0x1000
_STACK_SIZE = 0x0020_0000
_HEAP_SIZE = 0x0100_0000
_STUB_SIZE = 0x0010_0000
_OBJ_POOL = 0x0040_0000
_RET_SLED = b'\xCC' * 0x1000

KPCR_X64 = 0xFFFFF78000000000
TEB_X64 = 0x0000000000110000
PEB_X64 = 0x0000000000120000
KUSER_SHARED = 0x000000007FFE0000

_MAX_INSN = 2_000_000
_SPIN_THRESH = 400

STATUS_NOT_IMPLEMENTED = 0xC0000002


# ── Helpers ──────────────────────────────────────────────────────────────────

def _align_up(n: int, a: int = _PAGE) -> int:
    return (n + a - 1) & ~(a - 1)


def _u64(uc: Uc, addr: int) -> int:
    return struct.unpack('<Q', bytes(uc.mem_read(addr, 8)))[0]


def _write_u64(uc: Uc, addr: int, val: int) -> None:
    uc.mem_write(addr, struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF))


def _write_u32(uc: Uc, addr: int, val: int) -> None:
    uc.mem_write(addr, struct.pack('<I', val & 0xFFFFFFFF))


def _safe_map(uc: Uc, base: int, size: int, perms=7) -> int:
    """Map memory; try canonical high address, fall back lower on failure."""
    size = _align_up(size)
    try:
        uc.mem_map(base & ~(_PAGE - 1), size, perms)
        return base & ~(_PAGE - 1)
    except Exception:
        alt = 0x70000000
        uc.mem_map(alt, size, perms)
        return alt


def read_win64_args(uc: Uc, n: int = 4) -> List[int]:
    """Read first N args using Microsoft x64 calling convention."""
    regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    args = [uc.reg_read(r) for r in regs[:min(n, 4)]]
    if n <= 4:
        return args
    rsp = uc.reg_read(UC_X86_REG_RSP)
    for i in range(4, n):
        try:
            args.append(_u64(uc, rsp + 0x28 + (i - 4) * 8))
        except Exception:
            args.append(0)
    return args


@dataclass
class TraceEntry:
    rip: int = 0
    text: str = ''
    module: str = ''


@dataclass
class GpaStackEvent:
    """One snapshot while tracing the frameless GetProcAddress helper (cmd ~0xA0BA)."""
    label: str
    rip: int = 0
    rva: int = 0
    insn: str = ''
    regs: Dict[str, int] = field(default_factory=dict)
    stack: List[Tuple[int, int]] = field(default_factory=list)
    note: str = ''


# cmd_shim GPA helper landmarks (PE RVAs, .text base 0x1000) — refreshed at load.
_GPA_LANDMARK_RVAS: Dict[str, int] = {
    'caller_call_gpa': 0xE0B6,
    'caller_post_gpa': 0xE0BB,
    'caller_crash': 0xE0BF,
    'gpa_entry': 0x28330,
    'gpa_spills_done': 0x28348,
    'gpa_push_rbp': 0x28360,
    'gpa_pop_rbp': 0x288E0,
    'gpa_ret': 0x288E6,
}


def _scan_gpa_landmarks(pe_path: str) -> Dict[str, int]:
    """Locate GPA entry/push-rbp/pop-rbp RVAs from translated cmd_shim signature."""
    marks = dict(_GPA_LANDMARK_RVAS)
    if not pefile or not HAS_CAPSTONE:
        return marks
    try:
        pe = pefile.PE(pe_path, fast_load=True)
        pe.parse_data_directories()
        base = pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_memory_mapped_image()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for off in range(0x1000, min(len(data) - 8, 0x40000)):
            if data[off:off + 4] != b'\x48\x83\xec\x58':
                continue
            insns = list(md.disasm(data[off:off + 24], base + off))
            if len(insns) >= 2 and 'rsp + 4' in insns[1].op_str and 'rcx' in insns[1].op_str:
                marks['gpa_entry'] = off
                for insn in md.disasm(data[off:off + 0x600], base + off):
                    rva = insn.address - base
                    if insn.mnemonic == 'push' and insn.op_str == 'rbp':
                        marks['gpa_push_rbp'] = rva
                    elif insn.mnemonic == 'pop' and insn.op_str == 'rbp':
                        marks['gpa_pop_rbp'] = rva
                    elif insn.mnemonic == 'ret' and rva < off + 0x600:
                        marks['gpa_ret'] = rva
                        break
                break
        for off in range(0xDF00, min(len(data) - 5, 0xE200)):
            if data[off] != 0xE8:
                continue
            rel = struct.unpack_from('<i', data, off + 1)[0]
            tgt = off + 5 + rel
            if tgt == marks.get('gpa_entry'):
                marks['caller_call_gpa'] = off
                marks['caller_post_gpa'] = off + 5
                marks['caller_crash'] = off + 9
                break
        pe.close()
    except Exception:
        pass
    return marks


@dataclass
class EmuResult:
    name: str
    return_value: int = 0
    status: str = ''
    instructions: int = 0
    syscalls: List[Tuple[int, List[int]]] = field(default_factory=list)
    api_calls: List[Tuple[str, int]] = field(default_factory=list)
    exception: Optional[str] = None
    stop_reason: Optional[str] = None
    elapsed: float = 0.0
    last_rip: int = 0
    registers: Dict[str, int] = field(default_factory=dict)
    trace_tail: List[TraceEntry] = field(default_factory=list)
    crash_report: str = ''


# APIs routed to UserModeApiMocks instead of generic STATUS_SUCCESS.
_USERMODE_MOCK_DLLS = frozenset({
    'kernel32.dll', 'msvcrt.dll', 'user32.dll', 'advapi32.dll',
    'ntdll.dll', 'api-ms-win-core-*.dll',
})

_WIN10_SYS32 = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')

# Broken translated copies in win2000_x64 that collide with cmd at 0x180000000.
_SKIP_TREE_DLLS = frozenset({'ntdll.dll', 'kernel32.dll', 'msvcrt.dll'})


class UserModeApiMocks:
    """Ring-3 Win32 / MSVCRT stubs for cmd.exe CRT startup under Unicorn."""

    STDIN = -10
    STDOUT = -11
    STDERR = -12

    def __init__(self, emu: 'X64EmulatorCore'):
        self.emu = emu
        self._fake_heap = emu._heap_alloc(0x10000)
        self._last_error = 0
        self._cmdline_w = self._alloc_wstr('cmd64.exe /c echo EMU_OK')
        self._cmdline_a = self._alloc_astr('cmd64.exe /c echo EMU_OK')
        self._argv_a = self._build_argv_a(['cmd64.exe', '/c', 'echo EMU_OK'])
        self._argv_w = self._build_argv_w(['cmd64.exe', '/c', 'echo EMU_OK'])
        self._argc_ptr = self._store_u32(3)
        self._envp = self._store_u64(0)
        self._envp_w = self._build_envp_w(['PATH=C:\\Windows', 'COMSPEC=C:\\Windows\\System32\\cmd.exe'])
        self._env_strings_w = self._alloc_wstr('PATH=C:\\Windows\0COMSPEC=C:\\Windows\\System32\\cmd.exe\0\0')

    def _store_u32(self, val: int) -> int:
        ptr = self.emu._heap_alloc(8)
        self.emu._write_u32(ptr, val)
        return ptr

    def _store_u64(self, val: int) -> int:
        ptr = self.emu._heap_alloc(8)
        self.emu._write_u64(ptr, val)
        return ptr

    def _alloc_wstr(self, text: str) -> int:
        raw = (text + '\0').encode('utf-16-le')
        ptr = self.emu._heap_alloc(len(raw) + 2)
        self.emu.uc.mem_write(ptr, raw)
        return ptr

    def _alloc_astr(self, text: str) -> int:
        raw = (text + '\0').encode('ascii')
        ptr = self.emu._heap_alloc(len(raw) + 1)
        self.emu.uc.mem_write(ptr, raw)
        return ptr

    def _build_argv_a(self, args: List[str]) -> int:
        strings = [self._alloc_astr(a) for a in args]
        table = self.emu._heap_alloc(8 * (len(strings) + 1))
        for i, sp in enumerate(strings):
            self.emu._write_u64(table + i * 8, sp)
        self.emu._write_u64(table + len(strings) * 8, 0)
        return table

    def _build_argv_w(self, args: List[str]) -> int:
        strings = [self._alloc_wstr(a) for a in args]
        table = self.emu._heap_alloc(8 * (len(strings) + 1))
        for i, sp in enumerate(strings):
            self.emu._write_u64(table + i * 8, sp)
        self.emu._write_u64(table + len(strings) * 8, 0)
        return table

    def _build_envp_w(self, entries: List[str]) -> int:
        strings = [self._alloc_wstr(e) for e in entries]
        table = self.emu._heap_alloc(8 * (len(strings) + 1))
        for i, sp in enumerate(strings):
            self.emu._write_u64(table + i * 8, sp)
        self.emu._write_u64(table + len(strings) * 8, 0)
        return table

    def dispatch(self, dll: str, func: str, args: List[int]) -> int:
        key = func.replace('@', '_')
        handler = getattr(self, f'api_{key}', None)
        if handler is None:
            handler = getattr(self, f'api_{func}', None)
        if handler is None:
            return self.api_default(dll, func, args)
        return handler(args)

    def api_default(self, dll: str, func: str, args: List[int]) -> int:
        return 0

    # ── MSVCRT (CRT startup path) ─────────────────────────────────────────────

    def api___set_app_type(self, args: List[int]) -> int:
        return 0

    def api___setusermatherr(self, args: List[int]) -> int:
        return 0

    def api__controlfp(self, args: List[int]) -> int:
        return 0x0009001F

    def api__XcptFilter(self, args: List[int]) -> int:
        return 1

    def api__initterm(self, args: List[int]) -> int:
        return 0

    def api___getmainargs(self, args: List[int]) -> int:
        """Win64: argc*, argv**, env**, dowildcard, newmode*."""
        if len(args) >= 3 and args[0]:
            self.emu._write_u32(args[0], 3)
        if len(args) >= 3 and args[1]:
            argv_ptr = self.emu._heap_alloc(8)
            self.emu._write_u64(argv_ptr, self._argv_a)
            self.emu._write_u64(args[1], argv_ptr)
        if len(args) >= 3 and args[2]:
            env_ptr = self.emu._heap_alloc(8)
            self.emu._write_u64(env_ptr, self._envp)
            self.emu._write_u64(args[2], env_ptr)
        return 0

    def api___wgetmainargs(self, args: List[int]) -> int:
        """Wide-char variant used by translated cmd CRT startup."""
        if len(args) >= 3 and args[0]:
            self.emu._write_u32(args[0], 3)
        if len(args) >= 3 and args[1]:
            argv_ptr = self.emu._heap_alloc(8)
            self.emu._write_u64(argv_ptr, self._argv_w)
            self.emu._write_u64(args[1], argv_ptr)
        if len(args) >= 3 and args[2]:
            env_ptr = self.emu._heap_alloc(8)
            self.emu._write_u64(env_ptr, self._envp_w)
            self.emu._write_u64(args[2], env_ptr)
        return 0

    def api_malloc(self, args: List[int]) -> int:
        size = args[0] if args else 0
        return self.emu._heap_alloc(max(size, 16)) if size else 0

    def api_free(self, args: List[int]) -> int:
        return 0

    def api_calloc(self, args: List[int]) -> int:
        n, sz = (args + [0, 0])[:2]
        total = n * sz
        ptr = self.emu._heap_alloc(max(total, 16))
        self.emu.uc.mem_write(ptr, b'\x00' * total)
        return ptr

    def api_realloc(self, args: List[int]) -> int:
        return self.api_malloc([args[1] if len(args) > 1 else 0x100])

    def api_exit(self, args: List[int]) -> int:
        code = args[0] if args else 0
        self.emu._stop_reason = f'exit({code})'
        self.emu.uc.emu_stop()
        return 0

    def api__exit(self, args: List[int]) -> int:
        return self.api_exit(args)

    # ── kernel32 ────────────────────────────────────────────────────────────

    def api_GetCommandLineW(self, args: List[int]) -> int:
        return self._cmdline_w

    def api_GetCommandLineA(self, args: List[int]) -> int:
        return self._cmdline_a

    def api_GetModuleHandleW(self, args: List[int]) -> int:
        main = self.emu.modules.get('cmd_shim.exe') or self.emu.modules.get('cmd.exe')
        return main.image_base if main else 0x180000000

    def api_GetStdHandle(self, args: List[int]) -> int:
        n = args[0] if args else self.STDOUT
        return {self.STDIN: 0x100, self.STDOUT: 0x101, self.STDERR: 0x102}.get(n, 0x101)

    def api_GetProcessHeap(self, args: List[int]) -> int:
        return self._fake_heap

    def api_HeapAlloc(self, args: List[int]) -> int:
        size = args[2] if len(args) > 2 else 0x40
        if size <= 0 or size > 0x100000:
            size = 8
        return self.emu._heap_alloc(size)

    def api_HeapFree(self, args: List[int]) -> int:
        return 1

    def api_GetLastError(self, args: List[int]) -> int:
        return self._last_error

    def api_SetLastError(self, args: List[int]) -> int:
        if args:
            self._last_error = args[0] & 0xFFFFFFFF
        return 0

    def api_SetErrorMode(self, args: List[int]) -> int:
        return 0

    def api_GetFileType(self, args: List[int]) -> int:
        return 0x0002  # FILE_TYPE_CHAR

    def api_WriteFile(self, args: List[int]) -> int:
        if len(args) >= 5:
            nwritten = self.emu._heap_alloc(4)
            self.emu._write_u32(nwritten, args[2] & 0xFFFFFFFF if len(args) > 2 else 0)
            self.emu._write_u32(args[4], 1)
        return 1

    def api_WriteConsoleW(self, args: List[int]) -> int:
        return self.api_WriteFile(args)

    def api_InitializeCriticalSection(self, args: List[int]) -> int:
        return 0

    def api_EnterCriticalSection(self, args: List[int]) -> int:
        return 0

    def api_LeaveCriticalSection(self, args: List[int]) -> int:
        return 0

    def api_GetVersion(self, args: List[int]) -> int:
        return 0x00000005  # Win2000-ish

    def api_GetConsoleMode(self, args: List[int]) -> int:
        if len(args) >= 2 and args[1]:
            self.emu._write_u32(args[1], 0x3)  # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL
        return 1

    def api_SetConsoleMode(self, args: List[int]) -> int:
        return 1

    def api__get_osfhandle(self, args: List[int]) -> int:
        fd = args[0] if args else 0
        if fd < 0:
            return -1
        return 0x100 + fd

    def api_time(self, args: List[int]) -> int:
        return 0x5F000000

    def api_srand(self, args: List[int]) -> int:
        return 0

    def api_wcscpy(self, args: List[int]) -> int:
        dst, src = (args + [0, 0])[:2]
        if dst and src:
            try:
                raw = bytes(self.emu.uc.mem_read(src, 512))
                end = raw.find(b'\x00\x00')
                if end < 0:
                    end = len(raw)
                self.emu.uc.mem_write(dst, raw[:end + 2])
            except Exception:
                pass
            return dst
        return 0

    def api_wcslen(self, args: List[int]) -> int:
        src = args[0] if args else 0
        if not src:
            return 0
        try:
            n = 0
            while n < 4096:
                if bytes(self.emu.uc.mem_read(src + n * 2, 2)) == b'\x00\x00':
                    return n
                n += 1
        except Exception:
            pass
        return 0

    def api_wcschr(self, args: List[int]) -> int:
        s, ch = (args + [0, 0])[:2]
        if not s:
            return 0
        ch &= 0xFFFF
        try:
            off = 0
            while off < 8192:
                w = int.from_bytes(self.emu.uc.mem_read(s + off, 2), 'little')
                if w == 0:
                    return 0
                if w == ch:
                    return s + off
                off += 2
        except Exception:
            pass
        return 0

    def api_wcsncpy(self, args: List[int]) -> int:
        dst, src, n = (args + [0, 0, 0])[:3]
        if dst and src and n > 0:
            try:
                raw = bytes(self.emu.uc.mem_read(src, n * 2))
                self.emu.uc.mem_write(dst, raw)
            except Exception:
                pass
            return dst
        return 0

    def api_towupper(self, args: List[int]) -> int:
        c = (args[0] if args else 0) & 0xFFFFFFFFFFFFFFFF
        if c > 0xFFFF:
            try:
                c = struct.unpack('<H', bytes(self.emu.uc.mem_read(c, 2)))[0]
            except Exception:
                return 0
        c &= 0xFFFF
        if 0x61 <= c <= 0x7A:
            return c - 0x20
        return c

    def api_GetEnvironmentVariableW(self, args: List[int]) -> int:
        """Not set in emulator — return 0 (var missing)."""
        if len(args) >= 4 and args[3]:
            self.emu._write_u32(args[3], 0)
        return 0

    def api_GetEnvironmentStringsW(self, args: List[int]) -> int:
        return self._env_strings_w

    def api_FreeEnvironmentStringsW(self, args: List[int]) -> int:
        return 1

    def api_GetCPInfo(self, args: List[int]) -> int:
        if len(args) >= 2 and args[1]:
            lp = args[1]
            self.emu._write_u32(lp, 1)  # MaxCharSize — SBCS code page
            # DefaultChar[2]=0x3F,0 + LeadByte[12]=0 (no DBCS lead bytes)
            self.emu.uc.mem_write(lp + 4, b'\x3f\x00' + b'\x00' * 12)
        self.emu._seed_cmd_locale_tables()
        return 1

    def api_GetThreadLocale(self, args: List[int]) -> int:
        return 0

    def api_SetThreadLocale(self, args: List[int]) -> int:
        self.emu._seed_cmd_locale_tables()
        return 1

    def api_GetConsoleOutputCP(self, args: List[int]) -> int:
        return 437

    def api_GetConsoleScreenBufferInfo(self, args: List[int]) -> int:
        """Win64: hConsoleOutput, lpConsoleScreenBufferInfo."""
        if len(args) >= 2 and args[1]:
            lp = args[1]
            # CONSOLE_SCREEN_BUFFER_INFO: 22 bytes of fields + window rects
            self.emu.uc.mem_write(lp, struct.pack(
                '<HHHHHHHHHHH',
                80, 25,     # dwSize.X/Y
                0, 0,       # dwCursorPosition
                0x0007,     # wAttributes
                0, 0, 79, 24,  # srWindow
                80, 25))    # dwMaximumWindowSize
        return 1

    def api_FormatMessageW(self, args: List[int]) -> int:
        """Win64: flags, source, msgId, langId, buf, size, args."""
        buf = args[4] if len(args) > 4 else 0
        size = args[5] if len(args) > 5 else 0
        if buf and size:
            text = 'Error\r\n'
            raw = text.encode('utf-16-le') + b'\x00\x00'
            n = min(len(raw), max(0, size * 2))
            if n:
                self.emu.uc.mem_write(buf, raw[:n])
            return len(text)
        return 0

    def api_MultiByteToWideChar(self, args: List[int]) -> int:
        """Win64: CodePage, flags, src, srclen, dst, dstlen."""
        cp, fl, src = (args + [0] * 6)[:3]
        srclen = args[3] if len(args) > 3 else 0
        dst, dstlen = (args + [0] * 6)[4], (args + [0] * 6)[5]
        if not src or srclen <= 0:
            return 0
        if srclen < 0:
            srclen = 256
        try:
            raw = bytes(self.emu.uc.mem_read(src, min(srclen, 512)))
        except Exception:
            return 0
        if b'\x00' in raw:
            raw = raw[:raw.index(b'\x00')]
        wide = raw.decode('cp437', errors='replace').encode('utf-16-le')
        need = len(wide) // 2 + 1
        if not dst or dstlen == 0:
            return need
        n = min(len(wide), max(0, (dstlen - 1) * 2))
        if n:
            self.emu.uc.mem_write(dst, wide[:n] + b'\x00\x00')
        return n // 2

    def api__ultoa(self, args: List[int]) -> int:
        """Win64: value, buffer, radix."""
        val, buf, radix = (args + [0, 0, 10])[:3]
        if not buf:
            return 0
        try:
            s = str(val & 0xFFFFFFFF)
            if radix == 16:
                s = f'{val & 0xFFFFFFFF:x}'
            raw = (s + '\0').encode('ascii')
            self.emu.uc.mem_write(buf, raw)
            return buf
        except Exception:
            return 0

    def api_SetConsoleCtrlHandler(self, args: List[int]) -> int:
        return 1

    def api_GetProcessWindowStation(self, args: List[int]) -> int:
        return 0

    def api_RegOpenKeyExW(self, args: List[int]) -> int:
        """Win64: hKey, lpSubKey, ulOptions, samDesired, phkResult."""
        if len(args) >= 5 and args[4]:
            self.emu._write_u64(args[4], 0xBEEF0001)
        return 0

    def api_RegOpenKeyW(self, args: List[int]) -> int:
        """Win64: hKey, lpSubKey, phkResult."""
        if len(args) >= 3 and args[2]:
            self.emu._write_u64(args[2], 0xBEEF0002)
        return 0

    def api_RegQueryValueExW(self, args: List[int]) -> int:
        """Win64: hKey, lpValueName, lpReserved, lpType, lpData, lpcbData."""
        try:
            if len(args) >= 6 and args[5]:
                self.emu._write_u32(args[5], 4)
            if len(args) >= 5 and args[4]:
                self.emu._write_u32(args[4], 0)
            if len(args) >= 4 and args[3]:
                self.emu._write_u32(args[3], 4)  # REG_DWORD
        except Exception:
            pass
        return 0

    def api_RegQueryValueW(self, args: List[int]) -> int:
        """Win64: hKey, lpSubKey, lpValue, lpcbValue."""
        try:
            if len(args) >= 4 and args[3]:
                self.emu._write_u32(args[3], 4)
            if len(args) >= 3 and args[2]:
                self.emu._write_u32(args[2], 0)
        except Exception:
            pass
        return 0

    def api_RegCloseKey(self, args: List[int]) -> int:
        return 0


# ── PE64 loader ─────────────────────────────────────────────────────────────

class LoadedPE64:
    def __init__(self, path: str, force_name: Optional[str] = None):
        if pefile is None:
            raise RuntimeError('pefile required: pip install pefile')
        self.path = path
        self.name = (force_name or os.path.basename(path)).lower()
        self.pe = pefile.PE(path, fast_load=False)
        if self.pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError(f'{self.name}: not AMD64 (machine=0x{self.pe.FILE_HEADER.Machine:04X})')
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.entry_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.exports: Dict[str, int] = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for sym in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name:
                    self.exports[sym.name.decode('ascii', errors='replace')] = sym.address

    def close(self) -> None:
        if self.pe:
            self.pe.close()
            self.pe = None


def apply_pe64_relocations(uc: Uc, pe: pefile.PE, old_base: int, new_base: int) -> None:
    delta = new_base - old_base
    if delta == 0 or not hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        return
    img_end = new_base + pe.OPTIONAL_HEADER.SizeOfImage
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            rva = entry.rva
            addr = new_base + rva
            if addr + 8 > img_end:
                continue
            try:
                if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                    val = _u64(uc, addr)
                    _write_u64(uc, addr, val + delta)
                elif entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                    val = struct.unpack('<I', bytes(uc.mem_read(addr, 4)))[0]
                    _write_u32(uc, addr, (val + delta) & 0xFFFFFFFF)
            except Exception:
                continue


def map_pe64(uc: Uc, loaded: LoadedPE64, base: Optional[int] = None,
             occupied: Optional[List[Tuple[int, int]]] = None) -> int:
    """Map PE64 sections into Unicorn; return actual base."""
    pe = loaded.pe
    preferred = base if base is not None else pe.OPTIONAL_HEADER.ImageBase
    size = _align_up(pe.OPTIONAL_HEADER.SizeOfImage)
    ib = preferred
    if occupied is not None:
        # Relocate if preferred range conflicts with prior mappings
        end = ib + size
        if any(ib < oe and end > ob for ob, oe in occupied):
            ib = preferred
            for _ in range(4096):
                end = ib + size
                if not any(ib < oe and end > ob for ob, oe in occupied):
                    break
                ib = _align_up(max(oe for ob, oe in occupied if ib < oe) + 0x10000, 0x10000)
            else:
                raise RuntimeError('cannot place PE image')
    ib = ib & ~(_PAGE - 1)
    uc.mem_map(ib, size)
    if occupied is not None:
        occupied.append((ib, ib + size))
    for sec in pe.sections:
        data = sec.get_data()
        if not data:
            continue
        va = ib + sec.VirtualAddress
        uc.mem_write(va, data)
    if ib != pe.OPTIONAL_HEADER.ImageBase:
        apply_pe64_relocations(uc, pe, pe.OPTIONAL_HEADER.ImageBase, ib)
    loaded.image_base = ib
    return ib


# ── Core emulator ─────────────────────────────────────────────────────────────

class X64EmulatorCore:
    """Shared Unicorn x64 engine: memory, stubs, hooks, kernel mocks."""

    def __init__(self):
        if not HAS_UNICORN:
            raise RuntimeError('unicorn required: pip install unicorn')
        self.uc: Optional[Uc] = None
        self.modules: Dict[str, LoadedPE64] = {}
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64) if HAS_CAPSTONE else None
        self.cs.detail = True

        self._stack_base = 0
        self._stack_top = 0
        self._heap_base = 0
        self._heap_ptr = 0
        self._stub_base = 0
        self._stub_ptr = 0
        self._ret_addr = 0
        self._obj_pool = 0
        self._occupied: List[Tuple[int, int]] = []

        self._stub_hooks: Dict[int, Tuple[str, str]] = {}
        self._hooks: List[int] = []

        self.mocks = None
        self._syscall_log: List[Tuple[int, List[int]]] = []
        self._api_log: List[Tuple[str, int]] = []
        self._insn_count = 0
        self._block_hits: Dict[int, int] = {}
        self._stop_reason: Optional[str] = None
        self._ring0 = False
        self._max_insn = _MAX_INSN

        self.on_syscall: Optional[Callable[[Uc, int, List[int]], int]] = None

        self._strict_mem = False
        self._trace_enabled = False
        self._trace_last_n = 64
        self._trace_buf: List[TraceEntry] = []
        self.user_mocks: Optional[UserModeApiMocks] = None
        self._fault_access = 0
        self._fault_addr = 0

        # GPA / GetProcAddress frameless helper diagnostics
        self._gpa_trace = False
        self._gpa_events: List[GpaStackEvent] = []
        self._gpa_marks: Dict[str, int] = dict(_GPA_LANDMARK_RVAS)
        self._gpa_image_base = 0
        self._gpa_frame_rsp = 0
        self._gpa_rbp_save_va = 0
        self._gpa_watch_lo = 0
        self._gpa_watch_hi = 0
        self._gpa_inside = False
        self._gpa_mem_hook: Optional[int] = None
        self._gpa_rbp_saved_val = 0
        self._gpa_watching_rbp = False

    def _record_map(self, base: int, size: int) -> None:
        self._occupied.append((base, base + size))

    def _find_free_base(self, size: int, preferred: int) -> int:
        size = _align_up(size, 0x10000)
        candidate = _align_up(preferred, 0x10000)
        for _ in range(4096):
            end = candidate + size
            if any(candidate < oe and end > ob for ob, oe in self._occupied):
                candidate = _align_up(max(oe for ob, oe in self._occupied if candidate < oe) + 0x10000, 0x10000)
                continue
            return candidate
        raise RuntimeError(f'no free VA for {size:#x} bytes')

    def _map_region(self, base: int, size: int) -> int:
        size = _align_up(size)
        base = base & ~(_PAGE - 1)
        self.uc.mem_map(base, size)
        self._record_map(base, size)
        return base

    def _write_u32(self, address: int, value: int) -> None:
        _write_u32(self.uc, address, value)

    def _write_u64(self, address: int, value: int) -> None:
        _write_u64(self.uc, address, value)

    def _record_alloc(self, ptr: int, size: int) -> None:
        pass

    def _init_uc(self) -> Uc:
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        return self.uc

    def _alloc_env(self, stack_top_hint: int = 0x0000000040000000) -> None:
        uc = self.uc
        self._stack_base = stack_top_hint
        self._map_region(self._stack_base, _STACK_SIZE)
        self._stack_top = self._stack_base + _STACK_SIZE

        self._heap_base = self._stack_base + _STACK_SIZE + _PAGE
        self._map_region(self._heap_base, _HEAP_SIZE)
        self._heap_ptr = self._heap_base
        self._heap_mapped_end = self._heap_base + _HEAP_SIZE

        self._stub_base = self._heap_base + _HEAP_SIZE + _PAGE
        self._map_region(self._stub_base, _STUB_SIZE)
        self._stub_ptr = self._stub_base + 0x100

        self._ret_addr = self._stub_base + _STUB_SIZE - len(_RET_SLED)
        uc.mem_write(self._ret_addr, _RET_SLED)

        self._obj_pool = self._stub_base + _STUB_SIZE + _PAGE
        self._map_region(self._obj_pool, _OBJ_POOL)

        if HAS_KMOCKS:
            self.mocks = KernelMocks(self)  # type: ignore[arg-type]
            self.mocks._heap_ptr = self._heap_ptr

    def _heap_alloc(self, size: int) -> int:
        size = _align_up(max(size, 16), 16)
        ptr = self._heap_ptr
        end = ptr + size
        mapped_end = getattr(self, '_heap_mapped_end', self._heap_base + _HEAP_SIZE)
        if end > mapped_end:
            grow = _align_up(end - mapped_end + _PAGE, _PAGE)
            self._map_region(mapped_end, grow)
            self._heap_mapped_end = mapped_end + grow
        self.uc.mem_write(ptr, b'\x00' * min(size, 0x10000))
        self._heap_ptr = end
        return ptr

    def _alloc_stub(self, dll: str, func: str) -> int:
        va = self._stub_ptr
        self._stub_ptr += 32
        # stub: int3 (triggers hook) ; ret
        self.uc.mem_write(va, b'\xCC\xC3')
        self._stub_hooks[va] = (dll.lower(), func)
        return va

    # ── PE load ──────────────────────────────────────────────────────────────

    def load_module(self, path: str, force_name: Optional[str] = None,
                    base: Optional[int] = None) -> LoadedPE64:
        mod = LoadedPE64(path, force_name)
        ib = map_pe64(self.uc, mod, base, self._occupied)
        self.modules[mod.name] = mod
        self._resolve_imports(mod)
        return mod

    def _resolve_imports(self, mod: LoadedPE64) -> None:
        pe = mod.pe
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return
        ib = mod.image_base
        pe_base = pe.OPTIONAL_HEADER.ImageBase
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace').lower()
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode('ascii', errors='replace')
                elif imp.ordinal:
                    fname = f'ord_{imp.ordinal}'
                else:
                    continue
                stub = self._resolve_import(dll, fname)
                if stub:
                    addr = imp.address
                    if addr >= pe_base:
                        addr = ib + (addr - pe_base)
                    else:
                        addr = ib + addr
                    self.uc.mem_write(addr, struct.pack('<Q', stub))

    def resolve_all_imports(self) -> None:
        for mod in self.modules.values():
            self._resolve_imports(mod)

    def _locate_va(self, va: int) -> str:
        for name, mod in self.modules.items():
            start = mod.image_base
            end = start + mod.image_size
            if start <= va < end:
                return f'{name}+0x{va - start:X}'
        if self._stub_base <= va < self._stub_ptr:
            hook = self._stub_hooks.get(va)
            if hook:
                return f'stub:{hook[0]}!{hook[1]}'
            return f'stub+0x{va - self._stub_base:X}'
        if self._heap_base <= va < self._heap_ptr:
            return f'heap+0x{va - self._heap_base:X}'
        return f'0x{va:X}'

    def _disasm_at(self, va: int, count: int = 1, before: int = 0) -> List[str]:
        if not self.cs:
            return []
        lines: List[str] = []
        start = max(va - before * 8, 0)
        try:
            raw = bytes(self.uc.mem_read(start, count * 16 + before * 8))
        except Exception:
            return [f'  0x{va:X}: <unreadable>']
        for insn in self.cs.disasm(raw, start, count=count + before):
            mark = '>>>' if insn.address == va else '   '
            loc = self._locate_va(insn.address)
            lines.append(f'{mark} 0x{insn.address:X} ({loc})  {insn.mnemonic} {insn.op_str}')
        return lines

    def _read_regs(self) -> Dict[str, int]:
        uc = self.uc
        names = [
            ('RAX', UC_X86_REG_RAX), ('RCX', UC_X86_REG_RCX), ('RDX', UC_X86_REG_RDX),
            ('RBX', UC_X86_REG_RBX), ('RSP', UC_X86_REG_RSP), ('RBP', UC_X86_REG_RBP),
            ('RSI', UC_X86_REG_RSI), ('RDI', UC_X86_REG_RDI), ('R8', UC_X86_REG_R8),
            ('R9', UC_X86_REG_R9), ('R10', UC_X86_REG_R10), ('R11', UC_X86_REG_R11),
            ('RIP', UC_X86_REG_RIP),
        ]
        return {n: uc.reg_read(r) for n, r in names}

    def enable_gpa_stack_trace(self, image_base: int,
                               marks: Optional[Dict[str, int]] = None) -> None:
        """Turn on targeted GPA RBP/stack snapshots (cmd GetProcAddress helper)."""
        self._gpa_trace = True
        self._gpa_events.clear()
        self._gpa_image_base = image_base
        self._gpa_marks = dict(marks or _GPA_LANDMARK_RVAS)
        self._gpa_frame_rsp = 0
        self._gpa_rbp_save_va = 0
        self._gpa_watch_lo = 0
        self._gpa_watch_hi = 0
        self._gpa_inside = False
        self._gpa_rbp_saved_val = 0
        self._gpa_watching_rbp = False

    @staticmethod
    def _gpa_write_overlaps(addr: int, size: int, target: int,
                            target_size: int = 8) -> bool:
        end = addr + size
        t_end = target + target_size
        return addr < t_end and end > target

    def _gpa_insn_text(self, rip: int) -> str:
        if not self.cs:
            return ''
        try:
            raw = bytes(self.uc.mem_read(rip, 15))
            for insn in self.cs.disasm(raw, rip, count=1):
                return f'{insn.mnemonic} {insn.op_str}'
        except Exception:
            return ''

    def _gpa_stack_snapshot(self, rsp: int, lo: int = -0x20,
                            count: int = 24) -> List[Tuple[int, int]]:
        out: List[Tuple[int, int]] = []
        for i in range(count):
            off = lo + i * 8
            addr = (rsp + off) & 0xFFFFFFFFFFFFFFFF
            try:
                out.append((off, _u64(self.uc, addr)))
            except Exception:
                out.append((off, 0))
        return out

    def _gpa_record(self, label: str, rip: int, note: str = '') -> None:
        uc = self.uc
        rsp = uc.reg_read(UC_X86_REG_RSP)
        rbp = uc.reg_read(UC_X86_REG_RBP)
        ev = GpaStackEvent(
            label=label,
            rip=rip,
            rva=(rip - self._gpa_image_base) if self._gpa_image_base else rip,
            insn=self._gpa_insn_text(rip),
            regs={
                'RSP': rsp, 'RBP': rbp,
                'RAX': uc.reg_read(UC_X86_REG_RAX),
                'RCX': uc.reg_read(UC_X86_REG_RCX),
                'RDX': uc.reg_read(UC_X86_REG_RDX),
                'RBX': uc.reg_read(UC_X86_REG_RBX),
                'RSI': uc.reg_read(UC_X86_REG_RSI),
                'RDI': uc.reg_read(UC_X86_REG_RDI),
                'R12': uc.reg_read(UC_X86_REG_R12),
            },
            stack=self._gpa_stack_snapshot(rsp),
            note=note,
        )
        self._gpa_events.append(ev)

    def _gpa_set_watch_window(self) -> None:
        """Watch stack frame region for writes that could clobber saved RBP."""
        if not self._gpa_frame_rsp:
            return
        self._gpa_watch_lo = self._gpa_frame_rsp
        self._gpa_watch_hi = self._gpa_frame_rsp + 0x80

    def _gpa_trace_step(self, address: int) -> None:
        if not self._gpa_trace or not self._gpa_image_base:
            return
        base = self._gpa_image_base
        rva = address - base
        marks = self._gpa_marks
        uc = self.uc

        if rva == marks.get('caller_call_gpa'):
            self._gpa_record('caller:before_gpa_call', address,
                             f'RBP should stay valid across GPA (expect ~0x401FF770)')

        elif rva == marks.get('gpa_entry'):
            self._gpa_inside = True
            rsp = uc.reg_read(UC_X86_REG_RSP)
            self._gpa_frame_rsp = (rsp - 0x58) & 0xFFFFFFFFFFFFFFFF
            self._gpa_set_watch_window()
            self._gpa_record('gpa:entry_sub_rsp_58', address,
                             f'frame base (post-sub) ~= 0x{self._gpa_frame_rsp:x}')

        elif rva == marks.get('gpa_spills_done'):
            note = 'arg homes at frame+4/+c/+14/+1c'
            if self._gpa_frame_rsp:
                try:
                    s4 = _u64(uc, self._gpa_frame_rsp + 4)
                    sc = _u64(uc, self._gpa_frame_rsp + 0xC)
                    note += f'; spilled RCX=0x{s4:x} RDX=0x{sc:x}'
                except Exception:
                    pass
            self._gpa_record('gpa:arg_spills_done', address, note)

        elif rva == marks.get('gpa_push_rbp'):
            rsp = uc.reg_read(UC_X86_REG_RSP)
            rbp = uc.reg_read(UC_X86_REG_RBP)
            self._gpa_rbp_save_va = (rsp - 8) & 0xFFFFFFFFFFFFFFFF
            self._gpa_rbp_saved_val = 0
            self._gpa_watching_rbp = False
            self._gpa_record('gpa:push_rbp_before', address,
                             f'about to push RBP=0x{rbp:x} -> [0x{self._gpa_rbp_save_va:x}]')

        elif (marks.get('gpa_push_rbp') is not None
              and marks.get('gpa_pop_rbp') is not None
              and marks['gpa_push_rbp'] < rva < marks['gpa_pop_rbp']):
            if self._gpa_rbp_save_va and not self._gpa_watching_rbp:
                try:
                    self._gpa_rbp_saved_val = _u64(uc, self._gpa_rbp_save_va)
                    self._gpa_watching_rbp = True
                    self._gpa_record('gpa:rbp_slot_armed', address,
                                     f'saved RBP slot [0x{self._gpa_rbp_save_va:x}]'
                                     f'=0x{self._gpa_rbp_saved_val:x}')
                except Exception:
                    pass
            elif self._gpa_watching_rbp and self._gpa_rbp_save_va:
                try:
                    cur = _u64(uc, self._gpa_rbp_save_va)
                    if cur != self._gpa_rbp_saved_val:
                        self._gpa_record('gpa:rbp_slot_corrupt', address,
                                         f'slot=0x{cur:x} expected 0x{self._gpa_rbp_saved_val:x} '
                                         f'before {self._gpa_insn_text(address)}')
                        self._gpa_rbp_saved_val = cur
                except Exception:
                    pass

        elif rva == marks.get('gpa_pop_rbp'):
            rsp = uc.reg_read(UC_X86_REG_RSP)
            try:
                pop_val = _u64(uc, rsp)
                cur_rbp = uc.reg_read(UC_X86_REG_RBP)
                self._gpa_record('gpa:pop_rbp_before', address,
                                 f'[RSP]=0x{pop_val:x} -> RBP (was 0x{cur_rbp:x}); '
                                 f'save slot [0x{self._gpa_rbp_save_va:x}]'
                                 f'={_u64(uc, self._gpa_rbp_save_va) if self._gpa_rbp_save_va else 0:x}')
            except Exception:
                self._gpa_record('gpa:pop_rbp_before', address)

        elif rva == marks.get('gpa_ret'):
            self._gpa_record('gpa:ret', address,
                             f'RBP after pop should equal caller frame base')
            self._gpa_inside = False
            self._gpa_watching_rbp = False

        elif rva == marks.get('caller_post_gpa'):
            rbp = uc.reg_read(UC_X86_REG_RBP)
            self._gpa_record('caller:after_gpa_ret', address,
                             f'RBP=0x{rbp:x} (bad if not ~caller stack frame)')

        elif rva == marks.get('caller_crash'):
            self._gpa_record('caller:crash_site', address,
                             'mov [rbp-0x28], eax — fault if RBP corrupt')

    def _hook_gpa_mem_write(self, uc, access, address, size, value, user_data):
        if not self._gpa_trace or not self._gpa_inside:
            return
        end = address + size
        rip = uc.reg_read(UC_X86_REG_RIP)
        val = value & ((1 << (size * 8)) - 1)
        marks = self._gpa_marks
        base = self._gpa_image_base
        rva = rip - base if base else rip

        hit = False
        tag = ''
        if (self._gpa_watching_rbp and self._gpa_rbp_save_va
                and self._gpa_write_overlaps(address, size,
                                             self._gpa_rbp_save_va)):
            hit = True
            tag = ' ** OVERWRITES SAVED RBP **'
            if (rva == marks.get('gpa_push_rbp')
                    and val == uc.reg_read(UC_X86_REG_RBP)):
                return
        elif self._gpa_rbp_save_va and not self._gpa_watching_rbp:
            if self._gpa_write_overlaps(address, size, self._gpa_rbp_save_va):
                hit, tag = True, ' ** initial RBP save **'
        elif self._gpa_frame_rsp:
            for off, lbl in ((4, 'RCX spill'), (0xC, 'RDX spill'),
                             (0x14, 'R8 spill'), (0x1C, 'R9 spill')):
                slot = self._gpa_frame_rsp + off
                if self._gpa_write_overlaps(address, size, slot):
                    hit, tag = True, f' ** touches {lbl} **'
                    break
            if (not hit and self._gpa_watching_rbp
                    and self._gpa_write_overlaps(
                        address, size, self._gpa_frame_rsp, 0x58)):
                hit, tag = True, ' ** frame local write **'
        if not hit:
            return
        self._gpa_events.append(GpaStackEvent(
            label='gpa:mem_write',
            rip=rip,
            rva=rva,
            insn=self._gpa_insn_text(rip),
            note=f'WRITE size={size} addr=0x{address:x} val=0x{val:x}{tag}',
        ))

    def format_gpa_trace_report(self) -> str:
        lines = ['=' * 60, '  GPA stack trace (GetProcAddress helper)', '=' * 60]
        if not self._gpa_events:
            lines.append('  (no GPA events captured)')
            return '\n'.join(lines)
        lines.append(f'  Landmarks: ' + ', '.join(
            f'{k}=0x{v:x}' for k, v in sorted(self._gpa_marks.items())))
        lines.append('')
        for ev in self._gpa_events:
            lines.append(f'--- {ev.label} @ cmd_shim+0x{ev.rva:x} ---')
            lines.append(f'  {ev.insn}')
            if ev.note:
                lines.append(f'  note: {ev.note}')
            if ev.regs:
                lines.append('  regs: ' + ' '.join(
                    f'{k}=0x{v:x}' for k, v in ev.regs.items()
                    if k in ('RSP', 'RBP', 'RCX', 'RDX', 'RAX', 'R12')))
            for off, val in ev.stack:
                mark = ''
                if self._gpa_rbp_save_va and ev.regs:
                    rsp = ev.regs.get('RSP', 0)
                    if rsp + off == self._gpa_rbp_save_va:
                        mark = ' <- saved RBP slot'
                    elif self._gpa_frame_rsp and rsp + off == self._gpa_frame_rsp + 4:
                        mark = ' <- RCX spill'
                lines.append(f'    [RSP{off:+4d}] = 0x{val:016x}{mark}')
            lines.append('')
        return '\n'.join(lines)

    def _trace_step(self, rip: int) -> None:
        if not self._trace_enabled:
            return
        text = ''
        if self.cs:
            try:
                raw = bytes(self.uc.mem_read(rip, 15))
                for insn in self.cs.disasm(raw, rip, count=1):
                    text = f'{insn.mnemonic} {insn.op_str}'
                    break
            except Exception:
                text = '<fetch err>'
        entry = TraceEntry(rip=rip, text=text, module=self._locate_va(rip))
        self._trace_buf.append(entry)
        if len(self._trace_buf) > self._trace_last_n:
            self._trace_buf.pop(0)

    def _simulate_ret(self, uc: Uc) -> None:
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret_va = _u64(uc, rsp)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret_va)

    def build_crash_report(self) -> str:
        uc = self.uc
        rip = uc.reg_read(UC_X86_REG_RIP)
        lines = ['=' * 60, '  Emulator crash / stop report', '=' * 60]
        if self._stop_reason:
            lines.append(f'  Reason   : {self._stop_reason}')
            if 'INT3' in self._stop_reason.upper():
                lines.append('  Hint     : INT3 in .text = untranslated x86 insn in x86_x64.py')
        if self._fault_addr:
            lines.append(f'  Fault VA : 0x{self._fault_addr:X} (access={self._fault_access})')
        lines.append(f'  RIP      : 0x{rip:X} ({self._locate_va(rip)})')
        lines.append(f'  Insns    : {self._insn_count:,}')
        lines.append('')
        lines.append('  Registers:')
        for name, val in self._read_regs().items():
            lines.append(f'    {name:3s} = 0x{val:016X}')
        rsp = uc.reg_read(UC_X86_REG_RSP)
        lines.append('')
        lines.append(f'  Stack @ RSP (0x{rsp:X}):')
        for i in range(8):
            try:
                val = _u64(uc, rsp + i * 8)
                lines.append(f'    [RSP+{i*8:02X}] = 0x{val:016X}  ({self._locate_va(val)})')
            except Exception:
                lines.append(f'    [RSP+{i*8:02X}] = <unmapped>')
        lines.append('')
        lines.append('  Disassembly near RIP:')
        lines.extend(self._disasm_at(rip, count=4, before=4))
        if self._api_log:
            lines.append('')
            lines.append(f'  Last API calls ({min(8, len(self._api_log))}):')
            for dllfunc, ret in self._api_log[-8:]:
                lines.append(f'    {dllfunc} -> 0x{ret:X}')
        if self._trace_buf:
            lines.append('')
            lines.append(f'  Trace tail ({len(self._trace_buf)}):')
            for t in self._trace_buf[-20:]:
                lines.append(f'    0x{t.rip:X} ({t.module})  {t.text}')
        lines.append('=' * 60)
        return '\n'.join(lines)

    def _resolve_import(self, dll: str, func: str) -> int:
        """Resolve import: exported module → VA; else → mock stub."""
        if dll in self.modules:
            exp = self.modules[dll].exports.get(func)
            if exp is not None:
                return self.modules[dll].image_base + exp
        return self._alloc_stub(dll, func)

    def export_va(self, module: str, name: str) -> Optional[int]:
        mod = self.modules.get(module.lower())
        if not mod:
            return None
        rva = mod.exports.get(name)
        if rva is None:
            alt = None
            if name.startswith('Nt'):
                alt = 'Zw' + name[2:]
            elif name.startswith('Zw'):
                alt = 'Nt' + name[2:]
            if alt:
                rva = mod.exports.get(alt)
        if rva is None:
            return None
        return mod.image_base + rva

    # ── TEB / PEB / KPCR (x64) ───────────────────────────────────────────────

    def setup_user_teb_peb(self) -> None:
        """Ring-3: GS → TEB, PEB at TEB+0x60."""
        uc = self.uc
        self._map_region(TEB_X64, _PAGE * 2)
        self._map_region(PEB_X64, _PAGE * 2)
        self._map_region(KUSER_SHARED, _PAGE)

        _write_u64(uc, TEB_X64 + 0x30, TEB_X64)       # Self
        _write_u64(uc, TEB_X64 + 0x60, PEB_X64)       # PEB
        _write_u32(uc, TEB_X64 + 0x68, 0)             # LastErrorValue
        _write_u64(uc, PEB_X64 + 0x10, 0x400000)      # ImageBaseAddress (placeholder)

        uc.reg_write(UC_X86_REG_GS_BASE, TEB_X64)

    def setup_kernel_kpcr(self) -> None:
        """Ring-0: GS → KPCR with CurrentThread / CurrentProcess placeholders."""
        uc = self.uc
        base = self._map_region(KPCR_X64, _PAGE * 4)
        self._kpcr_base = base

        idle_thread = self._heap_alloc(0x400)
        idle_process = self._heap_alloc(0x600)
        _write_u64(uc, base + 0x188, idle_thread)     # CurrentThread (Win10+ offset; ok for mock)
        _write_u64(uc, idle_thread + 0x220, idle_process)  # ETHREAD.Process (approx)
        _write_u64(uc, base + 0x180, idle_process)      # CurrentProcess (approx)

        uc.reg_write(UC_X86_REG_GS_BASE, base)
        self._ring0 = True

    # ── hooks ────────────────────────────────────────────────────────────────

    def _install_hooks(self) -> None:
        uc = self.uc
        self._hooks.append(uc.hook_add(UC_HOOK_CODE, self._hook_code))
        for ht in (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                   UC_HOOK_MEM_FETCH_UNMAPPED):
            self._hooks.append(uc.hook_add(ht, self._hook_unmapped))
        self._hooks.append(uc.hook_add(UC_HOOK_INTR, self._hook_intr))
        if self._gpa_trace:
            self._gpa_mem_hook = uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_gpa_mem_write)
            self._hooks.append(self._gpa_mem_hook)

    def _hook_code(self, uc, address, size, user_data):
        self._insn_count += 1
        self._trace_step(address)
        self._gpa_trace_step(address)
        if self._insn_count > self._max_insn:
            self._stop_reason = f'instruction limit ({self._max_insn})'
            uc.emu_stop()
            return
        # REP-prefixed string ops (F3/F2) re-enter the hook at the same address
        # for each iteration — that is not a spin loop. Skip the spin check for
        # them and let the global instruction limit bound runaway counts.
        is_rep = False
        try:
            pfx = uc.mem_read(address, 1)[0]
            is_rep = pfx in (0xF3, 0xF2)
        except Exception:
            pass
        mbcs_enter = getattr(self, '_cmd_mbcs_enter_va', 0)
        if mbcs_enter and address == mbcs_enter and not getattr(self, '_cmd_mbcs_seeded', False):
            self._seed_cmd_locale_tables()
            self._cmd_mbcs_seeded = True
        if not is_rep and address not in self._stub_hooks:
            hits = self._block_hits.get(address, 0) + 1
            self._block_hits[address] = hits
            if hits > _SPIN_THRESH:
                self._stop_reason = f'spin loop at 0x{address:X} ({self._locate_va(address)})'
                uc.emu_stop()
                return

        rip_after = uc.reg_read(UC_X86_REG_RIP)
        if rip_after == 0 and self._insn_count > 8:
            self._stop_reason = (
                f'RET to NULL at 0x{address:X} ({self._locate_va(address)}) '
                f'— likely missing push rbp / bad stack frame')
            uc.emu_stop()
            return

        # SYSCALL (0F 05)
        if size >= 2:
            try:
                b2 = bytes(uc.mem_read(address, 2))
            except Exception:
                b2 = b''
            if b2 == b'\x0f\x05':
                nr = uc.reg_read(UC_X86_REG_RAX)
                args = read_win64_args(uc, 4)
                self._syscall_log.append((nr, args))
                if self.on_syscall:
                    ret = self.on_syscall(uc, nr, args)
                else:
                    ret = STATUS_SUCCESS
                uc.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)
                uc.reg_write(UC_X86_REG_RIP, address + 2)
                return

        if address in self._stub_hooks:
            dll, func = self._stub_hooks[address]
            args = read_win64_args(uc, 6)
            ret = STATUS_SUCCESS
            if self.user_mocks and not self._ring0:
                ret = self.user_mocks.dispatch(dll, func, args)
            elif self.mocks:
                try:
                    self.mocks._heap_ptr = self._heap_ptr  # type: ignore[attr-defined]
                    ret = self.mocks.dispatch(func, args)
                except EmulationException as exc:
                    self._stop_reason = str(exc)
                    uc.emu_stop()
                    return
                except Exception:
                    ret = STATUS_SUCCESS
            uc.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)
            self._api_log.append((f'{dll}!{func}', ret))
            self._simulate_ret(uc)
            return

    def _hook_unmapped(self, uc, access, address, size, value, user_data):
        self._fault_access = access
        self._fault_addr = address
        if self._strict_mem:
            kind = {1: 'READ', 2: 'WRITE', 3: 'FETCH'}.get(access, str(access))
            self._stop_reason = (
                f'unmapped {kind} at 0x{address:X} '
                f'(RIP=0x{uc.reg_read(UC_X86_REG_RIP):X} {self._locate_va(uc.reg_read(UC_X86_REG_RIP))})')
            uc.emu_stop()
            return False
        page = address & ~(_PAGE - 1)
        try:
            uc.mem_map(page, _PAGE)
            uc.mem_write(page, b'\x00' * _PAGE)
            return True
        except Exception:
            self._stop_reason = f'unmapped 0x{address:X} (access={access})'
            uc.emu_stop()
            return False

    def _hook_intr(self, uc, intno, user_data):
        if intno == 3:
            rip = uc.reg_read(UC_X86_REG_RIP)
            if rip in self._stub_hooks:
                dll, func = self._stub_hooks[rip]
                args = read_win64_args(uc, 6)
                ret = STATUS_SUCCESS
                if self.mocks:
                    try:
                        ret = self.mocks.dispatch(func, args)
                    except Exception:
                        ret = STATUS_SUCCESS
                uc.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)
                self._api_log.append((f'{dll}!{func}', ret))
                uc.reg_write(UC_X86_REG_RIP, rip + 1)
                self._simulate_ret(uc)
                return
            if self._stop_reason is None:
                self._stop_reason = f'INT3 at 0x{rip:X} ({self._locate_va(rip)})'
            uc.emu_stop()
        else:
            self._stop_reason = f'interrupt {intno} at RIP=0x{uc.reg_read(UC_X86_REG_RIP):X}'
            uc.emu_stop()

    # ── run ──────────────────────────────────────────────────────────────────

    def run_va(self, va: int, args: Optional[List[int]] = None,
               name: str = '', max_insn: int = _MAX_INSN) -> EmuResult:
        uc = self.uc
        saved_max = self._max_insn
        self._max_insn = max_insn

        rsp = self._stack_top - 0x800
        uc.reg_write(UC_X86_REG_RSP, rsp)
        uc.reg_write(UC_X86_REG_RBP, rsp)
        _write_u64(uc, rsp, self._ret_addr)  # return address → ret sled / int3

        if args:
            reg_ids = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
            for i, val in enumerate(args[:4]):
                uc.reg_write(reg_ids[i], val & 0xFFFFFFFFFFFFFFFF)
            for i, val in enumerate(args[4:]):
                _write_u64(uc, rsp + 0x28 + i * 8, val)

        uc.reg_write(UC_X86_REG_RIP, va)
        self._insn_count = 0
        self._block_hits.clear()
        self._stop_reason = None
        self._syscall_log.clear()
        self._api_log.clear()
        if self.mocks and hasattr(self.mocks, 'reset_counters'):
            self.mocks.reset_counters()

        t0 = time.perf_counter()
        try:
            uc.emu_start(va, 0, timeout=30_000_000, count=0)
        except Exception as exc:
            err = str(exc)
            if 'Unhandled CPU exception' not in err and 'UC_ERR_OK' not in err:
                self._stop_reason = self._stop_reason or err
        elapsed = time.perf_counter() - t0
        self._max_insn = saved_max

        rax = uc.reg_read(UC_X86_REG_RAX)
        rip = uc.reg_read(UC_X86_REG_RIP)
        if rip == 0 and not self._stop_reason and self._insn_count > 8:
            self._stop_reason = 'RET to NULL (bad stack frame / return address)'
        crash = self.build_crash_report() if self._stop_reason else ''
        return EmuResult(
            name=name or f'0x{va:X}',
            return_value=rax,
            status=ntstatus_name(rax) if HAS_KMOCKS else hex(rax),
            instructions=self._insn_count,
            syscalls=list(self._syscall_log),
            api_calls=list(self._api_log),
            stop_reason=self._stop_reason,
            elapsed=elapsed,
            last_rip=rip,
            registers=self._read_regs(),
            trace_tail=list(self._trace_buf),
            crash_report=crash,
        )

    def close(self) -> None:
        if self.uc:
            for h in self._hooks:
                try:
                    self.uc.hook_del(h)
                except Exception:
                    pass
            self._hooks.clear()
            self.uc = None
        for mod in self.modules.values():
            mod.close()
        self.modules.clear()


# ── User-mode emulator ────────────────────────────────────────────────────────

class UserMode64Emu(X64EmulatorCore):
    """Ring-3 PE64: load cmd/ntdll + deps, hook SYSCALL → mock kernel."""

    def __init__(self, system_root: str):
        super().__init__()
        self.system_root = os.path.abspath(system_root)
        self._files: Dict[str, str] = {}

    def scan(self) -> None:
        self._files.clear()
        for ext in ('*.exe', '*.dll', '*.sys'):
            for fp in glob.glob(os.path.join(self.system_root, ext)):
                self._files[os.path.basename(fp).lower()] = fp

    def _dll_path(self, name: str) -> Optional[str]:
        """Resolve a DLL: tree copy first (except skip-list), else Win10 System32."""
        low = name.lower()
        if low in self._files and low not in _SKIP_TREE_DLLS:
            return self._files[low]
        sys32 = os.path.join(_WIN10_SYS32, low)
        if os.path.isfile(sys32):
            return sys32
        return self._files.get(low)

    def load(self, main_pe: str, extra: Optional[List[str]] = None, *,
             strict_mem: bool = False, trace: bool = False,
             trace_last: int = 64, isolated: bool = True,
             gpa_trace: bool = False) -> None:
        """
        Load a PE64 app for emulation.

        isolated=True (default): cmd at ImageBase 0x180000000, w2kshim64 at its
        base, skip broken tree ntdll/kernel32/msvcrt.  Win32/CRT APIs → mocks.
        """
        self.scan()
        self._strict_mem = strict_mem
        self._trace_enabled = trace
        self._trace_last_n = max(trace_last, 16)
        self._trace_buf.clear()
        self._init_uc()
        self._alloc_env()
        self.setup_user_teb_peb()
        self.user_mocks = UserModeApiMocks(self)

        main_path = self._files.get(os.path.basename(main_pe).lower(), main_pe)
        if not os.path.isfile(main_path):
            raise FileNotFoundError(main_path)
        main_pe_obj = pefile.PE(main_path, fast_load=True)
        main_base = main_pe_obj.OPTIONAL_HEADER.ImageBase
        main_name = os.path.basename(main_path).lower()
        main_pe_obj.close()

        if isolated:
            # w2kshim64 first at its preferred base (0x1800100000).
            shim_path = self._dll_path('w2kshim64.dll')
            if shim_path:
                shim_pe = pefile.PE(shim_path, fast_load=True)
                self.load_module(shim_path, base=shim_pe.OPTIONAL_HEADER.ImageBase)
                shim_pe.close()
            # Main exe at 0x180000000 — must not be relocated or IAT VAs break.
            self.load_module(main_path, force_name=main_name, base=main_base)
        else:
            preload = ['w2kshim64.dll', 'ntdll.dll', 'kernel32.dll']
            if extra:
                preload.extend(extra)
            for dll in preload:
                fp = self._dll_path(dll)
                if fp and dll.lower() not in self.modules:
                    self.load_module(fp)
            self.load_module(main_path, force_name=main_name)

        self.resolve_all_imports()

        # PEB.ImageBaseAddress → main module
        main_mod = self.modules.get(main_name)
        if main_mod:
            _write_u64(self.uc, PEB_X64 + 0x10, main_mod.image_base)
            if 'cmd' in main_name:
                self._cmd_image_base = main_mod.image_base
                self._cmd_mbcs_table_rva = 0
                self._scan_cmd_mbcs_sites(main_path)
                self._cmd_mbcs_seeded = False
                self._seed_cmd_locale_tables()
            if gpa_trace and 'cmd' in main_name:
                marks = _scan_gpa_landmarks(main_path)
                self.enable_gpa_stack_trace(main_mod.image_base, marks)

        self._install_hooks()

    def _seed_cmd_locale_tables(self) -> None:
        """Seed relocated MBCS globals so cmd's charmap walk terminates."""
        base = getattr(self, '_cmd_image_base', 0)
        if not base:
            return
        # Discover lead-byte table from movabs rdx, *867 in translated .text.
        table = getattr(self, '_cmd_mbcs_table_rva', 0)
        if not table:
            table = 0x3A867  # fallback if scan missed
        try:
            self.uc.mem_write(base + table - 1, b'\x01' * 34)
        except Exception:
            pass
        seeds = (
            (0x3BAA8, struct.pack('<I', 3)),
            (0x3A880, struct.pack('<I', 0)),
        )
        for off, blob in seeds:
            try:
                self.uc.mem_write(base + off, blob)
            except Exception:
                pass

    def _scan_cmd_mbcs_sites(self, path: str) -> None:
        """Find MBCS loop entry + table RVA from movabs rdx in cmd .text."""
        if pefile is None:
            return
        try:
            pe = pefile.PE(path, fast_load=True)
            img = pe.get_memory_mapped_image()
            base = pe.OPTIONAL_HEADER.ImageBase
            text_rva = 0
            text = b''
            for s in pe.sections:
                if b'.text' in s.Name:
                    text_rva = s.VirtualAddress
                    text = img[text_rva:text_rva + s.Misc_VirtualSize]
                    break
            if not text:
                pe.close()
                return
            for i in range(len(text) - 16):
                if text[i:i + 2] != b'\x48\xba':
                    continue
                imm = struct.unpack_from('<Q', text, i + 2)[0]
                if imm < base or (imm - base) & 0xFFF != 0x867:
                    continue
                self._cmd_mbcs_table_rva = imm - base
                self._cmd_mbcs_enter_va = base + text_rva + i
                break
            pe.close()
        except Exception:
            return

    def run_export(self, module: str, export: str,
                   args: Optional[List[int]] = None) -> EmuResult:
        va = self.export_va(module, export)
        if va is None:
            raise KeyError(f'{module}!{export} not found')
        return self.run_va(va, args, name=f'{module}!{export}')

    def run_entry(self, module: str, max_insn: int = 500_000) -> EmuResult:
        mod = self.modules.get(module.lower())
        if not mod:
            raise KeyError(module)
        va = mod.image_base + mod.entry_rva
        return self.run_va(va, name=f'{module}!entry', max_insn=max_insn)


# ── Ring-0 kernel environment ───────────────────────────────────────────────

class Ring0Environment64(X64EmulatorCore):
    """
    Ring-0 x64 kernel emulator for translated ntoskrnl / hal / drivers.
    Import stubs use KernelMocks from win2k_analyzer.
    """

    KERNEL_ALIASES = {
        'ntkrnlmp.exe': 'ntoskrnl.exe',
        'ntkrnlpa.exe': 'ntoskrnl.exe',
        'ntkrpamp.exe': 'ntoskrnl.exe',
    }

    def __init__(self, system_root: str):
        super().__init__()
        self.system_root = os.path.abspath(system_root)
        self._files: Dict[str, str] = {}

    def scan(self) -> None:
        self._files.clear()
        for ext in ('*.exe', '*.dll', '*.sys'):
            for fp in glob.glob(os.path.join(self.system_root, ext)):
                name = os.path.basename(fp).lower()
                self._files[name] = fp

    def load_core(self) -> None:
        self.scan()
        self._init_uc()
        self._map_region(KUSER_SHARED, _PAGE)
        self._alloc_env()
        self.setup_kernel_kpcr()

        kernel = None
        for name in ('ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrnlpa.exe', 'ntkrpamp.exe'):
            if name in self._files:
                kernel = self._files[name]
                break
        if not kernel:
            raise FileNotFoundError(f'no kernel in {self.system_root}')

        self.load_module(kernel, 'ntoskrnl.exe')
        hal = self._files.get('hal.dll')
        if hal:
            try:
                self.load_module(hal, 'hal.dll')
            except Exception:
                pass  # hal optional in rollup trees

        self._install_hooks()

    def run_export(self, name: str, args: Optional[List[int]] = None,
                   module: str = 'ntoskrnl.exe') -> EmuResult:
        va = self.export_va(module, name)
        if va is None:
            raise KeyError(f'{module}!{name}')
        return self.run_va(va, args, name=f'{module}!{name}')

    def run_entry(self, max_insn: int = 500_000) -> EmuResult:
        mod = self.modules.get('ntoskrnl.exe')
        if not mod:
            raise RuntimeError('kernel not loaded')
        return self.run_va(mod.image_base + mod.entry_rva,
                           name='ntoskrnl!entry', max_insn=max_insn)


# ── Test runners ──────────────────────────────────────────────────────────────

DEFAULT_X64 = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'win2000_x64')
DEFAULT_X64 = os.path.normpath(DEFAULT_X64)
DEFAULT_X86 = r'C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU'


def test_ntdll_stub(root: str = DEFAULT_X64) -> EmuResult:
    """Run NtClose syscall stub in translated ntdll64."""
    emu = UserMode64Emu(root)
    emu.load('ntdll.dll')
    emu.on_syscall = lambda uc, nr, args: STATUS_SUCCESS if nr == 0x18 else STATUS_NOT_IMPLEMENTED
    r = emu.run_export('ntdll.dll', 'NtClose', args=[0x1234])
    emu.close()
    return r


def test_ntdll_query(root: str = DEFAULT_X64) -> EmuResult:
    emu = UserMode64Emu(root)
    emu.load('ntdll.dll')
    buf = emu._heap_alloc(0x200)
    info = buf + 0x100
    emu.on_syscall = lambda uc, nr, args: STATUS_SUCCESS
    r = emu.run_export('ntdll.dll', 'NtQuerySystemInformation',
                       args=[0, buf, 0x100, info])
    emu.close()
    return r


def test_cmd_entry(root: str = DEFAULT_X64, max_insn: int = 200_000,
                   trace: bool = False, strict: bool = False) -> EmuResult:
    """Run translated cmd.exe entry until stop / limit."""
    main = 'cmd_shim.exe' if os.path.isfile(os.path.join(root, 'cmd_shim.exe')) else 'cmd.exe'
    emu = UserMode64Emu(root)
    emu.load(main, strict_mem=strict, trace=trace, isolated=True)
    emu.on_syscall = lambda uc, nr, args: STATUS_SUCCESS
    r = emu.run_entry(main, max_insn=max_insn)
    emu.close()
    return r


def test_cmd_gpa_trace(root: str = DEFAULT_X64, max_insn: int = 500_000) -> EmuResult:
    """Run cmd entry with GPA RBP/stack snapshots at GetProcAddress helper landmarks."""
    main = 'cmd_shim.exe' if os.path.isfile(os.path.join(root, 'cmd_shim.exe')) else 'cmd.exe'
    emu = UserMode64Emu(root)
    emu.load(main, strict_mem=True, trace=False, gpa_trace=True, isolated=True)
    emu.on_syscall = lambda uc, nr, args: STATUS_SUCCESS
    r = emu.run_entry(main, max_insn=max_insn)
    report = emu.format_gpa_trace_report()
    print(report)
    if r.crash_report:
        print(r.crash_report)
    r.crash_report = report + '\n' + (r.crash_report or '')
    emu.close()
    return r


def test_cmd_trace(root: str = DEFAULT_X64, max_insn: int = 500_000) -> EmuResult:
    """Run cmd entry with strict memory + trace; print full crash report."""
    main = 'cmd_shim.exe' if os.path.isfile(os.path.join(root, 'cmd_shim.exe')) else 'cmd.exe'
    emu = UserMode64Emu(root)
    emu.load(main, strict_mem=True, trace=True, trace_last=128, isolated=True)
    emu.on_syscall = lambda uc, nr, args: STATUS_SUCCESS
    r = emu.run_entry(main, max_insn=max_insn)
    if r.crash_report:
        print(r.crash_report)
    emu.close()
    return r


def test_kernel_export(root: str = DEFAULT_X64,
                       export: str = 'NtClose') -> EmuResult:
    """Run a kernel export in ring-0 emulator."""
    emu = Ring0Environment64(root)
    emu.load_core()
    r = emu.run_export(export, args=[0])
    emu.close()
    return r


def test_kernel_entry(root: str = DEFAULT_X64, max_insn: int = 50_000) -> EmuResult:
    emu = Ring0Environment64(root)
    emu.load_core()
    r = emu.run_entry(max_insn=max_insn)
    emu.close()
    return r


def test_x86_kernel_baseline(root: str = DEFAULT_X86,
                             export: str = 'NtClose') -> Optional[EmuResult]:
    """Optional: run x86 kernel via win2k_analyzer KernelEnvironment."""
    if not os.path.isdir(_ANALYZER):
        return None
    try:
        from nt_analyzer.kernel_debugger import KernelEnvironment, DebugSession
    except ImportError:
        return None
    env = KernelEnvironment(root)
    env.load_core()
    env.auto_load_dependencies()
    dbg = DebugSession(env)
    t0 = time.perf_counter()
    out = dbg.run(export, args=[0], stop_at_entry=False)
    elapsed = time.perf_counter() - t0
    env.close()
    return EmuResult(
        name=f'x86!{export}',
        return_value=out.get('return_value', 0),
        status=ntstatus_name(out.get('return_value', 0)) if HAS_KMOCKS else '',
        instructions=out.get('instructions', 0),
        stop_reason=out.get('error'),
        elapsed=elapsed,
    )


def _print_result(r: EmuResult, verbose: bool = False) -> None:
    print(f"  {r.name}")
    print(f"    return   : 0x{r.return_value:016X} ({r.status})")
    print(f"    insns    : {r.instructions:,}  ({r.elapsed:.2f}s)")
    if r.syscalls:
        print(f"    syscalls : {len(r.syscalls)}  "
              f"(first: nr=0x{r.syscalls[0][0]:X})")
    if r.api_calls:
        print(f"    api mock : {len(r.api_calls)}  "
              f"(last: {r.api_calls[-1][0]})")
    if r.stop_reason:
        print(f"    stopped  : {r.stop_reason}")
    print(f"    last RIP : 0x{r.last_rip:X}")
    if verbose and r.registers:
        print("    regs     : "
              + " ".join(f"{k}=0x{v:X}" for k, v in list(r.registers.items())[:6]))
    if verbose and r.trace_tail:
        print(f"    trace    : {len(r.trace_tail)} insns buffered")
        for t in r.trace_tail[-5:]:
            print(f"      0x{t.rip:X}  {t.text}")


def run_all_tests(x64_root: str = DEFAULT_X64, x86_root: str = DEFAULT_X86) -> int:
    fails = 0
    print('=' * 60)
    print('  Win2000 x64 Ring-0 / Ring-3 Emulator Tests')
    print('=' * 60)
    print(f'  x64 tree: {x64_root}')
    print(f'  x86 ref : {x86_root}')
    print()

    tests = [
        ('ntdll NtClose stub (ring3 + SYSCALL)', lambda: test_ntdll_stub(x64_root)),
        ('ntdll NtQuerySystemInformation', lambda: test_ntdll_query(x64_root)),
        ('kernel export NtClose (ring0)', lambda: test_kernel_export(x64_root)),
        ('cmd entry (ring3)', lambda: test_cmd_entry(x64_root, 100_000)),
        ('kernel entry (ring0)', lambda: test_kernel_entry(x64_root, 20_000)),
    ]

    for label, fn in tests:
        print(f'--- {label} ---')
        try:
            r = fn()
            _print_result(r)
            ok = r.instructions > 0 and r.exception is None
            if 'int3' in (r.stop_reason or '').lower() and r.instructions > 10:
                ok = True  # expected for partial translation
            print(f"    => {'PASS' if ok else 'FAIL'}")
            if not ok:
                fails += 1
        except Exception as exc:
            print(f'    => FAIL: {exc}')
            fails += 1
        print()

    print('--- x86 kernel baseline (win2k_analyzer) ---')
    try:
        r = test_x86_kernel_baseline(x86_root)
        if r:
            _print_result(r)
            print('    => PASS (reference)')
        else:
            print('    => SKIP (win2k_analyzer unavailable)')
    except Exception as exc:
        print(f'    => SKIP: {exc}')
    print()
    print('=' * 60)
    print(f'  Done: {len(tests) - fails}/{len(tests)} passed')
    print('=' * 60)
    return fails


def main() -> None:
    ap = argparse.ArgumentParser(description='Win2000 x64 ring-0/ring-3 emulator')
    ap.add_argument('--root', default=DEFAULT_X64, help='Translated x64 system folder')
    ap.add_argument('--x86-root', default=DEFAULT_X86, help='x86 SP4 folder (baseline)')
    ap.add_argument('--test', choices=[
        'ntdll', 'ntdll-query', 'kernel', 'kernel-entry',
        'cmd-entry', 'cmd-trace', 'cmd-gpa-trace', 'x86-baseline', 'all',
    ], default='all')
    ap.add_argument('--export', default='NtClose', help='Kernel export name')
    ap.add_argument('--max-insn', type=int, default=200_000)
    ap.add_argument('--trace', action='store_true',
                    help='Record instruction trace (cmd-entry)')
    ap.add_argument('--strict', action='store_true',
                    help='Stop on unmapped memory (no lazy zero-fill)')
    ap.add_argument('--verbose', '-v', action='store_true',
                    help='Extra register / trace summary')
    ap.add_argument('--report', metavar='FILE',
                    help='Write crash report to file (cmd-trace)')
    args = ap.parse_args()

    if args.test == 'all':
        sys.exit(run_all_tests(args.root, args.x86_root))

    runners = {
        'ntdll': lambda: test_ntdll_stub(args.root),
        'ntdll-query': lambda: test_ntdll_query(args.root),
        'kernel': lambda: test_kernel_export(args.root, args.export),
        'kernel-entry': lambda: test_kernel_entry(args.root, args.max_insn),
        'cmd-entry': lambda: test_cmd_entry(
            args.root, args.max_insn, trace=args.trace, strict=args.strict),
        'cmd-trace': lambda: test_cmd_trace(args.root, args.max_insn),
        'cmd-gpa-trace': lambda: test_cmd_gpa_trace(args.root, args.max_insn),
        'x86-baseline': lambda: test_x86_kernel_baseline(args.x86_root, args.export),
    }
    r = runners[args.test]()
    if r:
        if args.test not in ('cmd-trace', 'cmd-gpa-trace'):
            _print_result(r, verbose=args.verbose)
        if args.report and r.crash_report:
            with open(args.report, 'w', encoding='utf-8') as fh:
                fh.write(r.crash_report)
            print(f'  Report written: {args.report}')
        elif args.verbose and r.crash_report:
            print(r.crash_report)


if __name__ == '__main__':
    main()
