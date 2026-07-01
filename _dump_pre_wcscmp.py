#!/usr/bin/env python3
"""Break at main+0x917A and dump rbx/rcx strings + rsp."""
import ctypes as C
import os
import sys

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()
CONTEXT_DEBUG = 0x10001B | 0x00010010
DBG_CONTINUE = 0x00010002


def main():
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_out11/cmd_shim.exe")
    bp = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x917A
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    k32.CreateProcessW(
        exe, C.create_unicode_buffer('"' + exe + '"'), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS | 0x10,
        None, os.path.dirname(exe), C.byref(si), C.byref(pi),
    )
    base = None
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), 100):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = base + bp
            ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            if ec in (0x80000003, 0x80000004):
                ctx = df.CONTEXT()
                ctx.ContextFlags = CONTEXT_DEBUG
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                if ctx.Rip == base + bp:
                    print(f"RSP=0x{ctx.Rsp:x} RBP=0x{ctx.Rbp:x} RBX=0x{ctx.Rbx:x}")
                    for name, addr in (("rbx", ctx.Rbx), ("rcx", ctx.Rcx), ("rbp-228", ctx.Rbp - 0x228)):
                        try:
                            b = df.read_process_mem(pi.hProcess, addr, 240)
                            s = b.decode("utf-16-le", errors="replace").split("\x00")[0]
                            print(f"  {name}: {s!r}")
                        except Exception as e:
                            print(f"  {name}: err {e}")
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit", hex(de.u.ExitProcess.dwExitCode))
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
    k32.TerminateProcess(pi.hProcess, 0)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)


if __name__ == "__main__":
    main()
