#!/usr/bin/env python3
import os
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
ENTRY = 0x8777
k32 = df.k32


def rw_test(proc, addr, when):
    buf = C.create_string_buffer(16)
    n = C.c_size_t(0)
    ok_r = k32.ReadProcessMemory(proc, C.c_void_p(addr), buf, 16, C.byref(n))
    err_r = C.get_last_error()
    print(f"[{when}] read ok={ok_r} n={n.value} err={err_r} bytes={buf.raw[:8].hex() if ok_r else '?'}")

    old = C.c_uint32(0)
    ok_p = k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    err_p = C.get_last_error()
    print(f"[{when}] VirtualProtectEx ok={ok_p} old={old.value:#x} err={err_p}")

    patch = b"\xcc"
    n2 = C.c_size_t(0)
    ok_w = k32.WriteProcessMemory(proc, C.c_void_p(addr), patch, 1, C.byref(n2))
    err_w = C.get_last_error()
    print(f"[{when}] write ok={ok_w} n={n2.value} err={err_w}")

    if ok_w:
        ok_r2 = k32.ReadProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))
        print(f"[{when}] readback={buf.raw[0]:#x}")


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO(); si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(EXE, C.create_unicode_buffer(cmdline), None, None, False,
                          df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    base = None
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"CREATE base=0x{base:x}")
            rw_test(pi.hProcess, base + ENTRY, "CREATE")
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            if ec == 0x80000003 and base and ea > base + 0x10000:
                rw_test(pi.hProcess, base + ENTRY, "LOADER_BP")
                df.k32.TerminateProcess(pi.hProcess, 0)
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
