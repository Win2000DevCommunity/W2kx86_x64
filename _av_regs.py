#!/usr/bin/env python3
"""Capture AV registers and last main-image RIP before fault."""
import os
import struct
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(
        EXE, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    base = None
    de = df.DEBUG_EVENT()
    last_main = None
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            ctx = df.get_thread_context(pi.hThread)
            if base and base <= ctx.Rip < base + 0x500000:
                last_main = ctx.Rip - base
            if ec == 0xC0000005 and de.u.Exception.dwFirstChance:
                print(f"AV RIP={ctx.Rip:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x}")
                print(f"  last main+0x{last_main:x}" if last_main else "  (no main trace)")
                if ctx.Rsp and base:
                    raw = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x40)
                    for i in range(0, len(raw) - 8, 8):
                        val = struct.unpack_from("<Q", raw, i)[0]
                        if base <= val < base + 0x500000:
                            print(f"  [rsp+0x{i:x}] -> main+0x{val - base:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
