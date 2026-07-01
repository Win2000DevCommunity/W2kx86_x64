#!/usr/bin/env python3
"""INT3 trace for cmd_shim CRT startup — find where we exit without echo."""
import os
import struct
import ctypes as C

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))

BPS = {
    0x883D: "after __set_app_type",
    0x8900: "after first __getmainargs block",
    0x8A4B: "after fn6314",
    0x8A87: "after GetCommandLineA align call",
    0x8ABD: "after GetStartupInfo align call",
    0x8E91: "early CRT ret 1",
    0x8EB6: "CRT ret after main setup",
}


def patch_byte(proc, addr, val):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), C.c_char(val), 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok and n.value == 1


def main() -> int:
    df.suppress_fault_ui()
    pe_data = open(EXE, "rb").read()
    patches = {}
    for rva, label in BPS.items():
        off = struct.unpack_from("<I", pe_data, 0x3C)[0]
        # resolve rva to file offset via pefile logic simplified
        import pefile
        pe = pefile.PE(EXE, fast_load=True)
        patches[rva] = (pe.get_data(rva, 1)[0], label)

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
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            for rva, (orig, label) in patches.items():
                patch_byte(pi.hProcess, base + rva, 0xCC)
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            print("hits:", hits)
            break
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - (base or 0)
            if ec == 0x80000003 and rva in patches:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                label = patches[rva][1]
                print(f"\n=== main+0x{rva:X} {label} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                print(f"  RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} RBP={ctx.Rbp:#x}")
                hits.append(label)
                orig = patches[rva][0]
                patch_byte(pi.hProcess, base + rva, orig)
                ctx.Rip = base + rva
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005:
                print(f"AV at main+0x{rva:X}")
                break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
