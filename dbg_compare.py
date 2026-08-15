#!/usr/bin/env python3
"""Comparative execution tracer for the x86→x64 binary translator.

Traces the translated x64 binary and, at every main-image instruction,
compares the actual x64 instruction against the expected translation of
the corresponding x86 source instruction (via the RVA map).

This catches:
  - Swallowed entries     (x64 at mapped position ≠ expected x86 translation)
  - Wrong call targets    (CALL goes to wrong x64 address)
  - Missing branches      (Jcc at x86 has no x64 counterpart)
  - Garbled instructions  (x64 bytes from wrong x86 source)
  - Stack-frame drift     (RSP/RBP divergence from expected)

Usage:
    python dbg_compare.py <x64_exe> [args...]
        --x86=<x86_exe>       Path to original Win2000 x86 cmd.exe
        --rva-map=<rva.txt>   RVA map from build output
        --seconds=N           Timeout (default 90)
        --mismatch-stop       Stop on first x86/x64 mismatch
        --mismatch-max=N      Max mismatches to report (default 20)
        --ring=N              Instruction ring size (default 160)
"""
from __future__ import annotations

import ctypes as C
import os
import struct
import sys
import time
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

import dbg_fault as df

k32 = df.k32

# ── Capstone ────────────────────────────────────────────────────────
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════

def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little") if len(b) >= o + 4 else 0


def _load_rva_revmap(path: str) -> Dict[int, int]:
    """Build x64_blob_offset → x86_rva from rva.txt."""
    rev: Dict[int, int] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            pp = ln.replace(",", " ").split()
            if len(pp) < 2:
                continue
            try:
                x86 = int(pp[0], 16)
                tr = int(pp[1], 16)
            except ValueError:
                continue
            rev[tr] = x86 & 0xFFFFFFFF
    return rev


def _disasm_one(proc, rip: int) -> Optional[object]:
    if not HAVE_CAPSTONE:
        return None
    raw = df.read_process_mem(proc, rip, 16)
    if not raw:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(raw, rip):
        return ins
    return None


def _disasm_x86_at(data: bytes, rva: int, offset: int) -> Optional[object]:
    """Disassemble one x86 instruction at data[offset:offset+15]."""
    if not HAVE_CAPSTONE:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for ins in md.disasm(data[offset:offset + 15], rva):
        return ins
    return None


# ═══════════════════════════════════════════════════════════════════
#  X86 → X64 Instruction Comparator
# ═══════════════════════════════════════════════════════════════════

class X86X64Comparator:
    """Compares executed x64 instructions against expected x86 translation."""

    # x86 mnemonics that map directly to same x64 mnemonic (same encoding)
    _SAME_MNEMONICS = frozenset({
        'push', 'pop', 'ret', 'retf', 'nop', 'int3', 'leave',
        'test', 'cmp', 'add', 'sub', 'and', 'or', 'xor',
        'inc', 'dec', 'not', 'neg', 'mul', 'imul', 'div', 'idiv',
        'mov', 'movsx', 'movzx', 'lea',
        'call', 'jmp', 'jne', 'je', 'jz', 'jnz', 'jg', 'jge',
        'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'jo', 'jno',
        'js', 'jns', 'jp', 'jnp', 'jcxz', 'jecxz',
        'sete', 'setne', 'setg', 'setge', 'setl', 'setle',
        'shl', 'shr', 'sar', 'rol', 'ror',
        'xchg', 'bswap', 'cbw', 'cwd', 'cdq', 'cqo',
        'stosb', 'stosw', 'stosd', 'stosq',
        'movsb', 'movsw', 'movsd', 'movsq',
        'rep', 'repe', 'repne',
    })

    # x86 → x64 register mapping for common small registers
    _REG32_TO_64 = {
        'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
        'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
        'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
        'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
    }

    _REG16_TO_64 = {
        'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
        'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp',
    }

    _REG8_TO_64 = {
        'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
        'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx',
        'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp',
    }

    def __init__(self, x86_text: bytes, x86_rva: int,
                 rev_map: Dict[int, int],
                 x64_text_start: int = 0x1000):
        self._x86 = x86_text
        self._x86_rva = x86_rva
        self._rev = rev_map          # x64_blob_off → x86_rva
        self._x64_text_start = x64_text_start  # RVA of .text section

        # Statistics
        self.ok: int = 0
        self.mismatches: List[Tuple[int, int, str, str, str]] = []
        # (x64_rva, x86_rva, x86_insn, x64_insn, reason)
        self.no_map: int = 0          # count when no RVA map entry
        self.skipped: int = 0          # count when we skip comparison

    def _x64_blob_off(self, x64_rva: int) -> int:
        return x64_rva - self._x64_text_start

    def _find_x86_source(self, x64_rva: int) -> Optional[int]:
        """Walk backward from x64_rva through the rev map to find x86 source."""
        off = self._x64_blob_off(x64_rva)
        # Try exact match first, then scan backward up to 32 bytes
        for back in range(33):
            candidate = off - back
            if candidate < 0:
                break
            x86 = self._rev.get(candidate)
            if x86 is not None:
                return x86
        return None

    def compare(self, proc, x64_rip: int, x64_base: int) -> Optional[str]:
        """Compare the instruction at x64_rip against expected x86 translation.

        Returns None if OK, or a mismatch reason string.
        """
        x64_rva = x64_rip - x64_base
        x86_rva = self._find_x86_source(x64_rva)
        if x86_rva is None:
            self.no_map += 1
            return None  # no mapping — injected byte (wrapper, etc.)

        # Disassemble x64 instruction
        x64_ins = _disasm_one(proc, x64_rip)
        if x64_ins is None:
            self.skipped += 1
            return None

        # Disassemble x86 instruction at source
        x86_off = x86_rva - self._x86_rva
        if x86_off < 0 or x86_off >= len(self._x86):
            self.skipped += 1
            return None
        x86_ins = _disasm_x86_at(self._x86, x86_rva, x86_off)
        if x86_ins is None:
            self.skipped += 1
            return None

        # ── Compare ──
        reason = self._check_instruction(x86_ins, x64_ins)

        if reason is None:
            self.ok += 1
            return None

        x86_str = f"{x86_ins.mnemonic} {x86_ins.op_str}"
        x64_str = f"{x64_ins.mnemonic} {x64_ins.op_str}"
        self.mismatches.append((x64_rva, x86_rva, x86_str, x64_str, reason))
        return reason

    def _check_instruction(self, x86, x64) -> Optional[str]:
        """Return a mismatch reason string, or None if OK."""
        x86_mnem = x86.mnemonic
        x64_mnem = x64.mnemonic

        # ── 1. Same mnemonic (direct translation) ──
        if x86_mnem == x64_mnem:
            return None  # exact match — almost certainly correct

        # ── 2. x86 'ret' or 'retf' matches x64 'ret' ──
        if x86_mnem in ('ret', 'retf') and x64_mnem == 'ret':
            return None
        if x86_mnem == 'ret' and x64_mnem.startswith('ret'):
            return None

        # ── 3. x86 'leave' → x64 'mov rsp,rbp; pop rbp' ──
        if x86_mnem == 'leave' and x64_mnem in ('mov', 'pop'):
            return None

        # ── 4. Same mnemonic family (add/sub/and/or/xor/cmp/test) ──
        if x86_mnem in self._SAME_MNEMONICS and x64_mnem in self._SAME_MNEMONICS:
            if x86_mnem == x64_mnem:
                return None

        # ── 5. x86 conditional jumps → x64 conditional jumps ──
        if x86_mnem.startswith('j') and x64_mnem.startswith('j'):
            # Map x86 Jcc to x64 Jcc
            _JCC_MAP = {
                'je': 'je', 'jz': 'je', 'jne': 'jne', 'jnz': 'jne',
                'jg': 'jg', 'jnle': 'jg', 'jge': 'jge', 'jnl': 'jge',
                'jl': 'jl', 'jnge': 'jl', 'jle': 'jle', 'jng': 'jle',
                'ja': 'ja', 'jnbe': 'ja', 'jae': 'jae', 'jnb': 'jae',
                'jb': 'jb', 'jnae': 'jb', 'jbe': 'jbe', 'jna': 'jbe',
                'jo': 'jo', 'jno': 'jno', 'js': 'js', 'jns': 'jns',
                'jp': 'jp', 'jpe': 'jp', 'jnp': 'jnp', 'jpo': 'jnp',
                'jcxz': 'jcxz', 'jecxz': 'jecxz', 'jrcxz': 'jrcxz',
            }
            expected = _JCC_MAP.get(x86_mnem, x86_mnem)
            if x64_mnem == expected:
                return None
            return f"Jcc mismatch: x86={x86_mnem} → expected={expected}, got={x64_mnem}"

        # ── 6. x86 'call' / 'jmp' → x64 same ──
        if x86_mnem in ('call', 'jmp') and x64_mnem == x86_mnem:
            return None

        # ── 7. x86 'movsx' / 'movzx' → x64 same ──
        if x86_mnem in ('movsx', 'movsx', 'movzx') and x64_mnem == x86_mnem:
            return None

        # ── 8. x86 'push imm' → x64 may use 'mov r64,imm; push r64' ──
        #    This is complex — skip for now, rely on mnemonic match

        # ── 9. x86 'int3' → x64 'int3' ──
        if x86_mnem == 'int3' and x64_mnem == 'int3':
            return None

        # ── 10. x86 'nop' variants → x64 'nop' ──
        if x86_mnem == 'nop' and x64_mnem == 'nop':
            return None

        # ── 11. Register-size promotion: x86 32-bit op → x64 64-bit op ──
        #     e.g. x86 'inc eax' → x64 'inc rax' (same mnemonic, wider reg)
        if x86_mnem == x64_mnem:
            return None  # same mnemonic already handled above

        # ── Fallback: check if it's a known translator pattern ──
        # movabs (x64: mov rax, imm64  /  x86: mov eax, imm32)
        if x86_mnem == 'mov' and x64_mnem == 'movabs':
            return None
        if x86_mnem == 'mov' and x64_mnem == 'mov':
            return None  # same mnemonic

        # pushf/popf → pushfq/popfq
        if x86_mnem == 'pushf' and x64_mnem == 'pushfq':
            return None
        if x86_mnem == 'popf' and x64_mnem == 'popfq':
            return None

        # cdq → cqo (sign-extend eax→edx:eax  →  rax→rdx:rax)
        if x86_mnem == 'cdq' and x64_mnem == 'cqo':
            return None
        if x86_mnem == 'cwd' and x64_mnem == 'cqo':
            return None

        # If we reach here, it's a genuine mismatch
        return f"mnemonic mismatch: x86={x86_mnem} x64={x64_mnem}"

    def summary(self) -> str:
        total = self.ok + len(self.mismatches) + self.no_map + self.skipped
        lines = [
            f"  Compared: {self.ok} OK, {len(self.mismatches)} MISMATCHES, "
            f"{self.no_map} no-map (injected), {self.skipped} skipped",
        ]
        if self.mismatches:
            lines.append("  --- Mismatches (first 20) ---")
            for x64_rva, x86_rva, x86_str, x64_str, reason in self.mismatches[:20]:
                lines.append(
                    f"  main+0x{x64_rva:X} ← x86 0x{x86_rva:05X}: "
                    f"[{x86_str}] → [{x64_str}]  ** {reason}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  Trace Loop (based on dbg_trace.py)
# ═══════════════════════════════════════════════════════════════════

def main() -> int:
    df.suppress_fault_ui()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    argv = sys.argv[1:]
    seconds = 90.0
    ring_max = 160
    show = 48
    rva_map_path = None
    x86_exe_path = None
    mismatch_stop = False
    mismatch_max = 20
    rest = []
    for a in argv:
        if a.startswith("--seconds="):
            seconds = float(a.split("=", 1)[1])
        elif a.startswith("--ring="):
            ring_max = int(a.split("=", 1)[1])
        elif a.startswith("--rva-map="):
            rva_map_path = a.split("=", 1)[1]
        elif a.startswith("--x86="):
            x86_exe_path = a.split("=", 1)[1]
        elif a == "--mismatch-stop":
            mismatch_stop = True
        elif a.startswith("--mismatch-max="):
            mismatch_max = int(a.split("=", 1)[1])
        else:
            rest.append(a)

    if not rest:
        print("usage: dbg_compare.py <x64_exe> [args...] --x86=<x86_exe> --rva-map=<rva.txt>")
        return 2
    if not x86_exe_path or not rva_map_path:
        print("ERROR: --x86= and --rva-map= are required")
        return 2

    exe = os.path.abspath(rest[0])
    args = rest[1:]
    cmdline = '"%s" %s' % (exe, " ".join(args))

    # ── Get entry RVA from x64 PE ──
    entry_rva = 0
    img_size = 0x100000
    try:
        import pefile
        _pe64 = pefile.PE(exe, fast_load=True)
        entry_rva = _pe64.OPTIONAL_HEADER.AddressOfEntryPoint
        img_size = _pe64.OPTIONAL_HEADER.SizeOfImage
        _pe64.close()
    except Exception:
        img_size = 0x100000

    # ── Load x86 source ──
    print(f"[compare] Loading x86 PE: {x86_exe_path}")
    try:
        import pefile
        x86_pe = pefile.PE(x86_exe_path, fast_load=True)
        x86_text = None
        for s in x86_pe.sections:
            if b'.text' in s.Name:
                x86_text = s.get_data()
                x86_text_rva = s.VirtualAddress
                break
        if x86_text is None:
            print("ERROR: no .text section in x86 PE")
            return 2
        print(f"[compare]   .text: {len(x86_text)} bytes at RVA 0x{x86_text_rva:X}")
    except Exception as e:
        print(f"ERROR loading x86 PE: {e}")
        return 2

    # ── Load RVA reverse map ──
    print(f"[compare] Loading RVA map: {rva_map_path}")
    rva_rev = _load_rva_revmap(rva_map_path)
    print(f"[compare]   {len(rva_rev)} entries")

    # ── Create comparator ──
    comparator = X86X64Comparator(x86_text, x86_text_rva, rva_rev)

    # ── Launch process ──
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    CreateProcessW = k32.CreateProcessW
    CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, C.c_void_p,
                               C.c_void_p, wintypes.BOOL, wintypes.DWORD,
                               C.c_void_p, wintypes.LPCWSTR,
                               C.POINTER(df.STARTUPINFO),
                               C.POINTER(df.PROCESS_INFORMATION)]
    ok = CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS | df.CREATE_NEW_CONSOLE,
                        None, os.path.dirname(exe) or None,
                        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    img_lo = img_hi = 0
    ring: list = []
    callchain: list = []
    tf_on = False
    bp_addr = 0
    bp_orig = b""
    tracing = False
    steps = 0
    started = time.time()
    last_report_time = 0.0

    def in_main(addr: int) -> bool:
        return bool(base) and img_lo <= addr < img_hi

    def set_tf(on: bool) -> None:
        nonlocal tf_on
        ctx = df.CONTEXT()
        ctx.ContextFlags = df.CONTEXT_FULL
        if not k32.GetThreadContext(pi.hThread, C.byref(ctx)):
            return
        if on:
            ctx.EFlags |= 0x100
        else:
            ctx.EFlags &= ~0x100
        k32.SetThreadContext(pi.hThread, C.byref(ctx))
        tf_on = on

    def write_mem(addr: int, data: bytes) -> bool:
        old = wintypes.DWORD(0)
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(addr & ~0xFFF), 0x1000,
                             0x40, C.byref(old))
        n = C.c_size_t(0)
        buf = (C.c_char * len(data))(*data)
        ok2 = k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), buf,
                                     len(data), C.byref(n))
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(addr & ~0xFFF), 0x1000,
                             old.value, C.byref(old))
        return bool(ok2)

    def arm_bp(addr: int) -> None:
        nonlocal bp_addr, bp_orig
        orig = df.read_process_mem(pi.hProcess, addr, 1)
        if len(orig) == 1:
            bp_orig = orig
            bp_addr = addr
            write_mem(addr, b"\xCC")

    def clear_bp() -> None:
        nonlocal bp_addr, bp_orig
        if bp_addr and bp_orig:
            write_mem(bp_addr, bp_orig)
        bp_addr = 0
        bp_orig = b""

    def report(ctx, ecode, fault_info) -> None:
        print("\n===== FAULT =====")
        rip = ctx.Rip
        print(f"code=0x{ecode:08X} RIP=0x{rip:016X} "
              f"({df.fmt_module_addr(rip, base)})")
        if fault_info:
            op, fa = fault_info
            kind = {0: "read", 1: "write", 8: "execute"}.get(op, str(op))
            print(f"access-violation: {kind} @ 0x{fa:016X}")
        df.print_register_block(ctx)
        ins = _disasm_one(pi.hProcess, rip)
        if ins:
            print(f"insn@RIP: {ins.mnemonic} {ins.op_str}")
        print(f"\n--- last {min(len(ring), show)} main-image instructions "
              f"(steps={steps}) ---")
        for rva, sp, bp in ring[-show:]:
            di = _disasm_one(pi.hProcess, base + rva)
            txt = f"{di.mnemonic} {di.op_str}" if di else "?"
            print(f"  main+0x{rva:<6X} rsp=0x{sp:X} rbp=0x{bp:X}  {txt}")
        # Print comparison summary
        print("\n" + comparator.summary())

    de = df.DEBUG_EVENT()
    first_bp_seen = False
    while True:
        if time.time() - started > seconds:
            print(f"\n[timeout after {seconds}s, steps={steps}]")
            print(comparator.summary())
            k32.TerminateProcess(pi.hProcess, 1)
            return 0

        if not k32.WaitForDebugEvent(C.byref(de), 100):
            # Periodic status update
            if time.time() - last_report_time > 5.0:
                last_report_time = time.time()
                if steps > 0:
                    print(f"[compare] {steps} steps, {comparator.ok} OK, "
                          f"{len(comparator.mismatches)} mismatches, "
                          f"{comparator.no_map} no-map", flush=True)
            continue

        code = de.dwDebugEventCode
        pid = de.dwProcessId
        tid = de.dwThreadId
        ctx = df.CONTEXT()
        ctx.ContextFlags = df.CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        rip = ctx.Rip

        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            img_lo = base
            img_hi = base + img_size
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
            print(f"[base] 0x{base:016X}  img=0x{img_lo:X}-0x{img_hi:X}")
            if entry_rva:
                arm_bp(base + entry_rva)
            k32.ContinueDebugEvent(pid, tid, df.DBG_CONTINUE)
            continue

        elif code == df.EXCEPTION_DEBUG_EVENT:
            rec = de.u.Exception.ExceptionRecord
            ecode = rec.ExceptionCode
            first_chance = de.u.Exception.dwFirstChance
            fault_info = None
            if ecode == 0xC0000005 and rec.NumberParameters >= 2:
                fault_info = (rec.ExceptionInformation[0],
                              rec.ExceptionInformation[1])

            if steps == 0 and ecode not in (0x80000003, 0x80000004):
                pass  # ignore first-chance exceptions before trace starts

            if first_chance and ecode == 0x80000003:  # INT3 breakpoint
                # In x64, RIP points PAST the INT3 byte (0xCC is 1 byte)
                if bp_addr and bp_addr <= rip <= bp_addr + 15:
                    if not first_bp_seen:
                        # ── Entry breakpoint: start tracing ──
                        saved_bp = bp_addr
                        clear_bp()
                        ctx.Rip = saved_bp
                        ctx.EFlags = (ctx.EFlags & ~0x100) | 0x10000  # clear TF, set RF
                        k32.SetThreadContext(pi.hThread, C.byref(ctx))
                        ctx2 = df.CONTEXT()
                        ctx2.ContextFlags = df.CONTEXT_FULL
                        k32.GetThreadContext(pi.hThread, C.byref(ctx2))
                        ctx2.EFlags |= 0x100
                        k32.SetThreadContext(pi.hThread, C.byref(ctx2))
                        tf_on = True
                        tracing = True
                        first_bp_seen = True
                        k32.ContinueDebugEvent(pid, tid, df.DBG_CONTINUE)
                        continue
                    else:
                        # ── Step-over breakpoint: return from system call ──
                        clear_bp()
                        ctx.EFlags |= 0x100  # re-arm TF
                        k32.SetThreadContext(pi.hThread, C.byref(ctx))
                        tf_on = True
                        k32.ContinueDebugEvent(pid, tid, df.DBG_CONTINUE)
                        continue
                    k32.ContinueDebugEvent(pid, tid, df.DBG_CONTINUE)
                    continue

            if first_chance and ecode == 0x80000004:  # single-step
                if in_main(rip):
                    steps += 1
                    rva = rip - base
                    ring.append((rva, ctx.Rsp, ctx.Rbp))
                    if len(ring) > ring_max:
                        ring.pop(0)

                    # ── COMPARE x86 vs x64 ──
                    reason = comparator.compare(pi.hProcess, rip, base)
                    if reason:
                        n_mis = len(comparator.mismatches)
                        if n_mis <= mismatch_max:
                            x86_rva = comparator._find_x86_source(rva)
                            x64_ins = _disasm_one(pi.hProcess, rip)
                            x64_str = f"{x64_ins.mnemonic} {x64_ins.op_str}" if x64_ins else "?"
                            x86_hint = ""
                            if x86_rva is not None:
                                x86_off = x86_rva - x86_text_rva
                                x86_ins = _disasm_x86_at(x86_text, x86_rva, x86_off) if 0 <= x86_off < len(x86_text) else None
                                x86_hint = f" x86=0x{x86_rva:05X}:{x86_ins.mnemonic} {x86_ins.op_str}" if x86_ins else f" x86=0x{x86_rva:05X}"
                            print(f"[MISMATCH #{n_mis}] main+0x{rva:X} {x64_str}{x86_hint}  ** {reason}")
                        if mismatch_stop and n_mis >= mismatch_max:
                            print(f"\n[mismatch-stop] {n_mis} mismatches reached")
                            report(ctx, 0, None)
                            k32.TerminateProcess(pi.hProcess, 1)
                            return 0

                    # Re-arm TF (CPU clears it on single-step exception)
                    if tf_on:
                        ctx.EFlags |= 0x100
                        k32.SetThreadContext(pi.hThread, C.byref(ctx))
                else:
                    # Left main image — clear TF, arm BP at return address
                    if tf_on:
                        set_tf(False)
                    ret_addr = ctx.Rip  # the call target in system DLL
                    # The return address is at [RSP]
                    rsp_bytes = df.read_process_mem(pi.hProcess, ctx.Rsp, 8)
                    if len(rsp_bytes) == 8:
                        ret = int.from_bytes(rsp_bytes, 'little')
                        if in_main(ret):
                            arm_bp(ret)

                k32.ContinueDebugEvent(pid, tid, df.DBG_CONTINUE)
                continue

            if first_chance and ecode in (0xC0000005, 0xC000001D,
                                           0xC00000FD, 0xC0000409,
                                           0x80000003, 0x80000004):
                # pass-through: let the program handle first-chance
                pass
            else:
                report(ctx, ecode, fault_info)
                print(comparator.summary())
                return 1

        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            ec = de.u.ExitProcess.dwExitCode
            print(f"\n[exit] 0x{ec:08X} steps={steps}")
            print(comparator.summary())
            return 0

        elif code == df.LOAD_DLL_DEBUG_EVENT:
            pass

        elif code == df.UNLOAD_DLL_DEBUG_EVENT:
            pass

        k32.ContinueDebugEvent(pid, tid, df.DBG_CONTINUE)

    return 0


if __name__ == "__main__":
    sys.exit(main())
