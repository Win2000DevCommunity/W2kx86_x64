#!/usr/bin/env python3
import ctypes as C
import os
import sys
import time

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()


def main():
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_out11/cmd_shim.exe")
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    k32.CreateProcessW(
        exe, C.create_unicode_buffer('"' + exe + '"'), None, None, False,
        0x10, None, os.path.dirname(exe), C.byref(si), C.byref(pi),
    )
    ctx = df.CONTEXT()
    ctx.ContextFlags = 0x10001B
    base = 0x80000000
    for _ in range(30):
        time.sleep(0.5)
        ec = C.c_ulong()
        k32.GetExitCodeProcess(pi.hProcess, C.byref(ec))
        if ec.value != 259:
            print("exit", hex(ec.value))
            break
        k32.SuspendThread(pi.hThread)
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        k32.ResumeThread(pi.hThread)
        rva = ctx.Rip - base
        print(f"rip=main+0x{rva:x} rsp=0x{ctx.Rsp:x}")
    else:
        print("still alive after 15s")
    k32.TerminateProcess(pi.hProcess, 0)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)


if __name__ == "__main__":
    main()
