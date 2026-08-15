#!/usr/bin/env python3
"""Log register state at fn6314 return and cmdline setup."""
import os
import ctypes as C
import pefile
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {
    0x8A4B: "after fn6314",
    0x8A99: "mov rcx,rax cmdline",
    0x8E91: "early CRT ret",
}


def patch_byte(proc, addr, val: int):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok and n.value == 1


def main():
    df.suppress_fault_ui()
    pe = pefile.PE(EXE, fast_load=True)
    orig = {rva: pe.get_data(rva, 1)[0] for rva in BPS}

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
            for rva in BPS:
                patch_byte(pi.hProcess, base + rva, 0xCC)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0)
            if ec == 0x80000003 and rva in BPS:
                ctx = df.get_thread_context(pi.hThread)
                label = BPS[rva]
                print(f"{label} @ 0x{rva:x}: RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RSI={ctx.Rsi:#x} RBX={ctx.Rbx:#x}")
                hits.append(label)
                patch_byte(pi.hProcess, ea, orig[rva])
                ctx.Rip = ea
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0x80000003 and (not base or ea < base or ea >= base + 0x500000):
                pass  # loader BP
            elif ec == 0xC0000005:
                print(f"AV @ 0x{rva:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} hits={hits}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
