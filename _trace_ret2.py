#!/usr/bin/env python3
import os
import struct
import ctypes as C
import pefile
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
RET = 0x2DD90
AFTER = 0x8A46


def pb(proc, addr, val):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))
    return ok and n.value == 1


def main():
    df.suppress_fault_ui()
    pe = pefile.PE(EXE, fast_load=True)
    oret, oafter = pe.get_data(RET, 1)[0], pe.get_data(AFTER, 1)[0]
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
            pb(pi.hProcess, base + RET, 0xCC)
            pb(pi.hProcess, base + AFTER, 0xCC)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0)
            if ec == 0x80000003 and rva == RET:
                ctx = df.get_thread_context(pi.hThread)
                ra = struct.unpack_from("<Q", df.read_process_mem(pi.hProcess, ctx.Rsp, 8), 0)[0]
                print(f"fn6314 ret: RAX={ctx.Rax:#x} retaddr={ra:#x} expect={base+0x8a46:#x}")
                pb(pi.hProcess, ea, oret)
                ctx.Rip = ea
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0x80000003 and rva == AFTER:
                ctx = df.get_thread_context(pi.hThread)
                print(f"after call: RAX={ctx.Rax:#x} RIP will continue")
                pb(pi.hProcess, ea, oafter)
                ctx.Rip = ea
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
