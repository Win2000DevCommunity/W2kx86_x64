#!/usr/bin/env python3
"""At first-chance AV, dump stack slots pointing into cmd_shim .text."""
import os
import struct
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
TEXT_LO = 0x1000
TEXT_HI = 0x42000


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
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            if ec == 0xC0000005 and base:
                ctx = df.get_thread_context(pi.hThread)
                print(f"AV RIP={ctx.Rip:#x} (main+0x{ctx.Rip - base:x}) RSP={ctx.Rsp:#x}")
                raw = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x80)
                print("Stack return candidates in .text:")
                for i in range(0, len(raw) - 8, 8):
                    val = struct.unpack_from("<Q", raw, i)[0]
                    rva = val - base
                    if TEXT_LO <= rva < TEXT_HI:
                        print(f"  [rsp+0x{i:x}] -> main+0x{rva:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
