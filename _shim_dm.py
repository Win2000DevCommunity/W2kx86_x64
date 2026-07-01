#!/usr/bin/env python3
"""Break on w2kshim DllMain and log until RIP=0 fault."""
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

SHIM_BASE = 0x1800100000
DM_RVA = 0x12E0


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

    main_base = None
    shim_base = None
    dm_hit = False
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            main_base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"main=0x{main_base:x}")
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
            b = de.u.LoadDll.lpBaseOfDll
            if b == SHIM_BASE or (shim_base is None and b > 0x1800000000):
                shim_base = b
                print(f"shim=0x{b:x} DllMain=0x{b+DM_RVA:x}")
            h = de.u.LoadDll.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            if shim_base and rip == shim_base + DM_RVA and ec == 0x80000003:
                print(f"DllMain hit RCX=0x{ctx.Rcx:x} EDX={ctx.Rdx & 0xFFFFFFFF:x} RSP=0x{ctx.Rsp:x}")
                dm_hit = True
            elif ec == 0xC0000005 and rip == 0:
                print(f"RIP=0 fault RCX=0x{ctx.Rcx:x} R11=0x{ctx.R11:x} dm_hit={dm_hit}")
                print(f"  main_entry=0x{(main_base or 0)+0x8778:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
