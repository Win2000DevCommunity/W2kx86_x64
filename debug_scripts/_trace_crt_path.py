#!/usr/bin/env python3
import os
import ctypes as C

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
WATCH = {
    0x8A41: "call fn6314",
    0x8A46: "after fn6314",
    0x8D83: "crt jne",
    0x8E0D: "cmp cpw",
    0x8E26: "jmp main",
    0x8EB6: "crt ret",
    0x8EB9: "main",
}


def patch_byte(proc, addr, val: int) -> bool:
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n)) and n.value == 1
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok


def resume_after(ctx, ea: int, size: int = 1) -> None:
    ctx.Rip = ea + size


def main() -> int:
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(
        EXE, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE),
        C.byref(si), C.byref(pi))
    base = None
    orig = {}
    hits = []
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            for rva in WATCH:
                orig[rva] = df.read_process_mem(pi.hProcess, base + rva, 1)[0]
                patch_byte(pi.hProcess, base + rva, 0xCC)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            if ec == 0x80000003 and base and base <= ea < base + 0x500000:
                rva = ea - base
                if rva in orig:
                    ctx = df.get_thread_context(pi.hThread)
                    label = WATCH[rva]
                    print(f"{label} main+0x{rva:x} RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} "
                          f"RDI={ctx.Rdi:#x} RCX={ctx.Rcx:#x}")
                    hits.append(label)
                    patch_byte(pi.hProcess, ea, orig[rva])
                    step = 5 if orig[rva] == 0xE8 else 1
                    resume_after(ctx, ea, step)
                    df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base:
                ctx = df.get_thread_context(pi.hThread)
                print(f"AV main+0x{ctx.Rip - base:x} hits={hits}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            ec = de.u.ExitProcess.dwExitCode & 0xFFFFFFFF
            print(f"exit=0x{ec:08x} hits={hits}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
