#!/usr/bin/env python3
"""Log all exceptions until terminal fault."""
import ctypes as C
import os
import sys
import struct
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

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
    de = df.DEBUG_EVENT()
    n = 0
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
            b = de.u.LoadDll.lpBaseOfDll
            print(f"  load dll@0x{b:x}")
            h = de.u.LoadDll.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            if ec in (0x80000003, 0x80000004) and er.ExceptionFlags & 1:
                pass  # skip initial bp
            else:
                ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                rip = ctx.Rip
                tag = ""
                if base and base <= rip < base + 0x500000:
                    tag = f" main+0x{rip-base:x}"
                elif rip == 0:
                    tag = " RIP=0"
                n += 1
                ra = C.c_ulonglong()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), C.byref(ra), 8, None)
                past = base and rip >= base + entry
                print(f"#{n} ec=0x{ec:08x} fc={er.ExceptionFlags&1} rip=0x{rip:x}{tag} past_entry={past} [rsp]=0x{ra.value:x}")
                print(f"    RCX=0x{ctx.Rcx:x} R11=0x{ctx.R11:x} RAX=0x{ctx.Rax:x}")
                if ec == 0xC0000005 and n > 3:
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
