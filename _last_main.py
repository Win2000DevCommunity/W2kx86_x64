#!/usr/bin/env python3
"""Log first main-image RIP and last before AV."""
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()


def main():
    exe = os.path.abspath(sys.argv[1])
    cmdline = '"' + exe + '" ' + " ".join(sys.argv[2:])
    si = df.STARTUPINFO(); si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi))
    if not ok:
        print("fail", C.get_last_error()); return 1

    base = None
    first_main = None
    last_main = None
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
            h = de.u.LoadDll.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            if base and base <= rip < base + 0x500000:
                rva = rip - base
                if first_main is None:
                    first_main = (rva, ctx.Rcx, ctx.R11)
                last_main = (rva, ctx.Rax, ctx.Rcx, ctx.Rsi, ctx.R11)
            if ec == 0xC0000005 and rip == 0:
                print(f"first_main={first_main}")
                print(f"last_main={last_main}")
                print(f"RCX=0x{ctx.Rcx:x} R11=0x{ctx.R11:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
