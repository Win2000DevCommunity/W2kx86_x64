#!/usr/bin/env python3
"""Run cmd_shim and dump memory state on first AV.

This avoids SEH/jump-through artifacts by reading process memory directly from
the debug event that reports the access violation.
"""
import ctypes as C
import os
from ctypes import wintypes

import dbg_fault as df


def u64(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)


def main() -> int:
    df.suppress_fault_ui()
    exe = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
    cmdline = f"\"{exe}\" /c echo test"

    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    ok = df.k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi)
    )
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    de = df.DEBUG_EVENT()
    first_bp = True
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            if ec == 0x80000003 and first_bp:
                # initial system bp
                first_bp = False
            elif ec == 0xC0000005:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                rip = ctx.Rip
                print(f"AV RIP=0x{rip:016X} (main+0x{(rip - base):X})" if base else f"AV RIP=0x{rip:016X}")
                print(f"  RAX=0x{ctx.Rax:016X} RBX=0x{ctx.Rbx:016X} RCX=0x{ctx.Rcx:016X} RDX=0x{ctx.Rdx:016X}")
                print(f"  RSI=0x{ctx.Rsi:016X} RDI=0x{ctx.Rdi:016X} RBP=0x{ctx.Rbp:016X} RSP=0x{ctx.Rsp:016X}")

                if base:
                    g = df.read_process_mem(pi.hProcess, base + 0x41460, 8)
                    if len(g) == 8:
                        print(f"  [main+0x41460]=0x{u64(g):016X}")
                    iat = df.read_process_mem(pi.hProcess, base + 0x6D439, 8)
                    if len(iat) == 8:
                        print(f"  [main+0x6D439]=0x{u64(iat):016X}")
                    code = df.read_process_mem(pi.hProcess, base + 0x27ED8, 0x30)
                    if code:
                        print(f"  bytes@27ED8={code.hex()}")
                    code2 = df.read_process_mem(pi.hProcess, rip, 0x10)
                    if code2:
                        print(f"  bytes@RIP ={code2.hex()}")
                break

        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

