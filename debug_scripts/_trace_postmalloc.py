#!/usr/bin/env python3
import os
import ctypes as C
import pefile
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {
    0x8A99: "lea/mov rcx",
    0x8ABD: "after malloc",
    0x8AF9: "after startup call",
    0x8EB6: "crt ret",
}


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
    orig = {r: pe.get_data(r, 1)[0] for r in BPS}
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO(); si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(EXE, C.create_unicode_buffer(cmdline), None, None, False,
                          df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    base = None
    de = df.DEBUG_EVENT()
    hits = []
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            for r in BPS:
                pb(pi.hProcess, base + r, 0xCC)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0)
            if ec == 0x80000003 and base and base <= ea < base + 0x500000 and rva in orig:
                ctx = df.get_thread_context(pi.hThread)
                print(f"{BPS[rva]}: RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RSP={ctx.Rsp:#x}")
                hits.append(BPS[rva])
                pb(pi.hProcess, ea, orig[rva])
                ctx.Rip = ea
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base and base <= ea < base + 0x500000:
                print(f"AV main+0x{rva:x} RAX={df.get_thread_context(pi.hThread).Rax:#x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} hits={hits}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
