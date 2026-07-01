#!/usr/bin/env python3
"""Quick INT3 probe at cmd_shim entry."""
import os
import ctypes as C

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
ENTRY = 0x8777


def patch_byte(proc, addr, val):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), C.c_char(val), 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok and n.value == 1


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    ok = df.k32.CreateProcessW(
        EXE, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1
    base = None
    de = df.DEBUG_EVENT()
    hits = []
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            patch_byte(pi.hProcess, base + ENTRY, b"\xcc")
            print(f"base=0x{base:x} patched entry+0x{ENTRY:x}")
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - (base or 0)
            fc = de.u.Exception.dwFirstChance
            print(f"exc ec=0x{ec:08x} rva=0x{rva:x} first={fc}")
            if ec == 0x80000003:
                hits.append(rva)
                if rva == ENTRY:
                    print("ENTRY BREAKPOINT HIT")
                    ctx = df.get_thread_context(pi.hThread)
                    print(f"  RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
            df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            print("hits:", hits)
            break
        else:
            df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
