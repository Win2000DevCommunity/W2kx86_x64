#!/usr/bin/env python3
"""Break at CRT indirect call sites and print target register."""
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

BPS = [0x835D, 0x8876, 0x88B2, 0x8A41]  # call rax / call rsi / FF15 / fn6314 call


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
    pending = set(BPS)
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            if base:
                rva = rip - base
                if rva in pending and ec in (0x80000003, 0x80000004):
                    pending.discard(rva)
                    print(f"BP main+0x{rva:x} RAX=0x{ctx.Rax:x} RCX=0x{ctx.Rcx:x} RSI=0x{ctx.Rsi:x} R11=0x{ctx.R11:x}")
                    # read cell if at 835d
                    if rva == 0x835D:
                        cell = C.c_ulonglong()
                        k32.ReadProcessMemory(pi.hProcess, C.c_void_p(0x8006f4d1), C.byref(cell), 8, None)
                        print(f"  cell[0x6f4d1]=0x{cell.value:x}")
                elif ec == 0xC0000005:
                    print(f"AV rip=0x{rip:x} main+0x{rva:x} RAX=0x{ctx.Rax:x} RCX=0x{ctx.Rcx:x}")
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
