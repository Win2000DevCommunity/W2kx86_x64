#!/usr/bin/env python3
"""Check if entry breakpoint fires before RIP=0."""
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()
CONTEXT_DEBUG_REGISTERS = 0x00010010

def main():
    exe = os.path.abspath(sys.argv[1])
    args = sys.argv[2:]
    cmdline = '"' + exe + '" ' + " ".join(args)
    si = df.STARTUPINFO(); si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi))
    if not ok:
        print("fail", C.get_last_error()); return 1
    base = None
    entry = 0x8778
    entry_hit = False
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            ctx = df.CONTEXT()
            ctx.ContextFlags = df.CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = base + entry
            ctx.Dr7 = (ctx.Dr7 & ~0xFF) | 0x1
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            print(f"armed bp main+0x{entry:x}")
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if base and ctx.Rip == base + entry:
                entry_hit = True
                print(f"ENTRY HIT rsp=0x{ctx.Rsp:x} rcx=0x{ctx.Rcx:x}")
                ctx.Dr7 &= ~0xFF
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and ctx.Rip == 0:
                print(f"RIP=0 entry_hit={entry_hit} rcx=0x{ctx.Rcx:x} r11=0x{ctx.R11:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} entry_hit={entry_hit}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
