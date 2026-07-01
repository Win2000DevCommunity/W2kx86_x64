#!/usr/bin/env python3
"""Hardware-breakpoint trace through interactive banner path."""
import ctypes as C
import os
import sys
import time

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()
CREATE_NEW_CONSOLE = 0x10
CONTEXT_DEBUG = 0x10001B | 0x00010010
DBG_CONTINUE = 0x00010002
EXC_BP = 0x80000003
EXC_SINGLE_STEP = 0x80000004

SITES = [
    0x8F61, 0x9072, 0x91B5, 0x2E4B2, 0x2E4D0, 0x2E519, 0x2E542, 0x2E5C4,
    0x2E5E7, 0x2E6F2, 0x2E728, 0x2EAD4, 0x3D196,
]
ENTRY_RVA = 0x8778


def set_hw(ctx, addr):
    ctx.Dr0 = addr
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1


def clear_hw(ctx):
    ctx.Dr7 &= ~0xF
    ctx.Dr0 = 0


def main() -> int:
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_out11/cmd_shim.exe")
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        exe, C.create_unicode_buffer('"' + exe + '"'), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi),
    )
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    site_i = 0
    hits = []
    de = df.DEBUG_EVENT()
    t0 = time.time()

    while k32.WaitForDebugEvent(C.byref(de), 100):
        if time.time() - t0 > 15:
            print("timeout")
            break
        st = DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            set_hw(ctx, base + SITES[0])
            print(f"watch #1 0x{SITES[0]:X}")
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
            h = de.u.LoadDll.hFile
            if h:
                k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            if ec == 0xC0000005:
                ctx = df.CONTEXT()
                ctx.ContextFlags = CONTEXT_DEBUG
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"FAULT @ 0x{ctx.Rip - base:x} after {len(hits)} hits")
                break
            if ec in (EXC_BP, EXC_SINGLE_STEP):
                ctx = df.CONTEXT()
                ctx.ContextFlags = CONTEXT_DEBUG
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                rva = ctx.Rip - base
                want = SITES[site_i]
                if rva != want:
                    ctx.EFlags |= 0x10000
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                else:
                    print(f"HIT #{site_i + 1} 0x{want:X} RAX=0x{ctx.Rax:x}")
                    hits.append(want)
                    site_i += 1
                    clear_hw(ctx)
                    if site_i < len(SITES):
                        set_hw(ctx, base + SITES[site_i])
                        print(f"watch #{site_i + 1} 0x{SITES[site_i]:X}")
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit", hex(de.u.ExitProcess.dwExitCode))
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    print("hits:", ", ".join(hex(h) for h in hits))
    k32.TerminateProcess(pi.hProcess, 0)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
