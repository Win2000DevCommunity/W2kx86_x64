#!/usr/bin/env python3
"""INT3 trace of CRT exit path in cmd_shim."""
import os
import struct
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
WATCH = {
    0x8777: "entry",
    0x8A41: "call fn6314",
    0x8A46: "after fn6314",
    0x8D83: "crt continue",
    0x8E02: "after CreateProcessW",
    0x8E0A: "cmp cpw result",
    0x8E28: "CreateProcessW fail path",
    0x8E23: "CreateProcessW ok jmp cleanup",
    0x2E042: "cleanup entry",
    0x2E0F3: "cleanup ret path",
    0x8EB6: "early ret",
    0x3FDA0: "near main",
    0x3B822: "call from 3fd85",
}


def patch_byte(proc, addr, val: int):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    buf = (C.c_ubyte * 1)(val)
    n = C.c_size_t(0)
    return k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n)) and n.value == 1


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
    orig = {}
    de = df.DEBUG_EVENT()
    hits = []
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
                    print(f"{label} (main+0x{rva:x}): RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} "
                          f"RDI={ctx.Rdi:#x} RCX={ctx.Rcx:#x}")
                    hits.append(label)
                    patch_byte(pi.hProcess, ea, orig[rva])
                    ctx.Rip = ea
                    df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005 and base:
                ctx = df.get_thread_context(pi.hThread)
                print(f"AV main+0x{ctx.Rip - base:x} hits={hits}")
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} hits={hits}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
