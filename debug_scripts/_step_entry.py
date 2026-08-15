#!/usr/bin/env python3
"""Single-step from CRT entry until fault; print last N main-image steps."""
import ctypes as C
import os
import struct
import sys

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

CONTEXT_DEBUG_REGISTERS = 0x00010010
CONTEXT_FULL = 0x10001B


def set_hw_bp(ctx, addr):
    ctx.Dr0 = addr
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1  # local enable Dr0, exec


def clear_hw_bp(ctx):
    ctx.Dr7 &= ~0xF
    ctx.Dr0 = 0


def main():
    exe = os.path.abspath(sys.argv[1])
    args = sys.argv[2:]
    cmdline = '"' + exe + '" ' + " ".join(args)
    si = df.STARTUPINFO()
    si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    entry_off = 0x8778
    ring = []
    stepping = False
    max_steps = 8000
    steps = 0
    de = df.DEBUG_EVENT()

    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = DBG_CONTINUE
        code = de.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            entry = base + entry_off
            print(f"base=0x{base:x} hw_bp=main+0x{entry_off:x}")
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            set_hw_bp(ctx, entry)
            ctx.EFlags |= 0x100  # trap flag for first step after bp
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            h = de.u.LoadDll.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            if ec == EXCEPTION_BREAKPOINT and base and rip == base + entry_off:
                print(f"HIT entry main+0x{entry_off:x}")
                stepping = True
                ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                clear_hw_bp(ctx)
            elif ec == EXCEPTION_SINGLE_STEP and stepping:
                steps += 1
                if base and base <= rip < base + 0x500000:
                    buf = (C.c_ubyte * 8)()
                    n = C.c_size_t(0)
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(rip), buf, 8, C.byref(n))
                    b = bytes(buf[:n.value])
                    ring.append((rip - base, b, ctx.Rax, ctx.Rcx, ctx.Rsi, ctx.R11))
                    if len(ring) > 40:
                        ring.pop(0)
                if steps >= max_steps:
                    print(f"stopped after {max_steps} steps rip=main+0x{rip-base:x}")
                    break
                ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == EXCEPTION_ACCESS_VIOLATION:
                print(f"FAULT rip=0x{rip:x} main+0x{rip-base:x if base else 0:x}")
                print(f"  RAX=0x{ctx.Rax:x} RCX=0x{ctx.Rcx:x} RSI=0x{ctx.Rsi:x} R11=0x{ctx.R11:x}")
                print(f"  steps={steps}")
                break
            else:
                if ec not in (EXCEPTION_BREAKPOINT,):
                    print(f"other exc 0x{ec:08x} rip=0x{rip:x}")
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    print("\n--- last main steps ---")
    for rva, b, rax, rcx, rsi, r11 in ring[-25:]:
        print(f"  main+0x{rva:x}  {b.hex()}  rax=0x{rax:x} rcx=0x{rcx:x} rsi=0x{rsi:x} r11=0x{r11:x}")

    k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
