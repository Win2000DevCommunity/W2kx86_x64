#!/usr/bin/env python3
"""Log every exception until exit; show first non-BP fault."""
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
    k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
    base = None
    n = 0
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            if ec in (0x80000003, 0x80000004):
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
                continue
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            tag = ""
            if base and base <= rip < base + 0x500000:
                tag = f" main+0x{rip-base:x}"
            n += 1
            info = er.ExceptionInformation
            bad = info[1] if info and len(info) > 1 else 0
            print(f"#{n} ec=0x{ec:08x} fc={er.ExceptionFlags&1} rip=0x{rip:x}{tag} bad=0x{bad:x}")
            if n >= 12:
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x80010001)  # NOT_HANDLED first chance
    k32.TerminateProcess(pi.hProcess, 1)

if __name__ == "__main__":
    main()
