#!/usr/bin/env python3
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
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if (de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF) == 0xC0000005 and ctx.Rip == 0:
                print(f"RIP=0 RAX=0x{ctx.Rax:x} RCX=0x{ctx.Rcx:x} R11=0x{ctx.R11:x}")
                for rva in [0x6f3e1, 0x6f3e9, 0x6f469, 0x6efed, 0x6eff5, 0x6e4e0, 0x6e4d8]:
                    q = C.c_ulonglong()
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(q), 8, None)
                    print(f"  slot 0x{rva:x} -> 0x{q.value:x}")
                print(f"  ff15@8f10 -> slot 0x{0x8f10+6+0x664cb:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)

if __name__ == "__main__":
    main()
