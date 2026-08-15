#!/usr/bin/env python3
"""Log all debug exceptions for cmd_shim — find why INT3 trace misses."""
import os
import ctypes as C

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))


def main() -> int:
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
    n_exc = 0
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        code = de.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"CREATE base=0x{base:x} entry=0x{de.u.CreateProcessInfo.lpStartAddress:x}")
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0) if base else 0
            fc = de.u.Exception.dwFirstChance
            n_exc += 1
            if n_exc <= 40 or ec not in (0x40010006, 0x406D1388):
                in_main = base and base <= ea < base + df.MAIN_IMAGE_MAX
                tag = f"main+0x{rva:x}" if in_main else f"0x{ea:x}"
                print(f"  exc#{n_exc} ec=0x{ec:08x} @ {tag} fc={fc}")
            if ec == 0xC0000005 and fc:
                ctx = df.get_thread_context(pi.hThread)
                print(f"    AV RIP={ctx.Rip:#x} RAX={ctx.Rax:#x}")
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"EXIT 0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} ({n_exc} exceptions)")
            break
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            print(f"  LOAD dll @ 0x{de.u.LoadDll.lpBaseOfDll:x}")
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
