#!/usr/bin/env python3
import os
import ctypes as C
import pefile
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {
    0x8A41: "call fn6314",
    0x8A4B: "after fn6314",
    0x2DC0B: "fn6314 entry",
    0x2DC2F: "fn6314 call 3b826",
    0x2DD65: "fn6314 ret0",
    0x2DD68: "fn6314 ret path",
}


def patch_byte(proc, addr, val: int):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))
    return ok and n.value == 1


def read_utf16(h, addr, n=80):
    raw = df.read_process_mem(h, addr, n)
    if not raw:
        return "?"
    u = raw.decode("utf-16-le", errors="replace").split("\x00")[0]
    return repr(u[:60])


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
            if ec == 0x80000003 and base and base <= ea < base + 0x500000 and rva in orig:
                ctx = df.get_thread_context(pi.hThread)
                label = BPS[rva]
                extra = ""
                if rva in (0x2DC0B, 0x8A41):
                    s = read_utf16(pi.hProcess, ctx.Rcx) if ctx.Rcx > 0x10000 else hex(ctx.Rcx)
                    extra = f" RCXstr={s.encode('ascii','backslashreplace').decode()}"
                print(f"{label}: RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} R10={ctx.R10:#x}{extra}")
                hits.append(label)
                patch_byte(pi.hProcess, ea, orig[rva])
                ctx.Rip = ea
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base and base <= ea < base + 0x500000:
                print(f"AV main+0x{rva:x}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} hits={hits}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
