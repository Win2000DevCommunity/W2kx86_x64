#!/usr/bin/env python3
"""Capture banner buffer at print call (interactive, debug attach)."""
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


def set_hw(ctx, addr):
    ctx.Dr0 = addr
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1


def main():
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_out11/cmd_shim.exe")
    bp_rva = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x2E542
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
    hit = False
    de = df.DEBUG_EVENT()
    t0 = time.time()
    while k32.WaitForDebugEvent(C.byref(de), 50):
        if time.time() - t0 > 20:
            print("timeout waiting for 0x%X" % bp_rva)
            break
        st = DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print("base=0x%x bp=0x%x" % (base, bp_rva))
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            set_hw(ctx, base + bp_rva)
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
            if ec == EXC_BP:
                ctx = df.CONTEXT()
                ctx.ContextFlags = CONTEXT_DEBUG
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                rva = ctx.Rip - base
                if rva == bp_rva:
                    hit = True
                    for reg, name in ((ctx.Rdx, "rdx"), (ctx.Rcx, "rcx"), (ctx.Rbp, "rbp")):
                        s = ""
                        if reg > 0x10000:
                            try:
                                s = df.read_wstr(pi.hProcess, reg, 200)
                            except Exception as e:
                                s = f"<err {e}>"
                        print(f"  {name}=0x{reg:x} {s!r}")
                    try:
                        buf = df.read_wstr(pi.hProcess, ctx.Rbp - 0xCC, 200)
                        print(f"  [rbp-0xcc]={buf!r}")
                    except Exception as e:
                        print(f"  [rbp-0xcc] err: {e}")
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit 0x%x" % de.u.ExitProcess.dwExitCode)
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    print("hit" if hit else "MISS")
    k32.TerminateProcess(pi.hProcess, 0)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return 0 if hit else 1


if __name__ == "__main__":
    raise SystemExit(main())
