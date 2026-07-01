#!/usr/bin/env python3
"""Patch INT3 after loader BP, verify startup milestones."""
import os
import ctypes as C
import pefile

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {
    0x883D: "after __set_app_type",
    0x8A4B: "after fn6314",
    0x8A99: "mov rcx,rax cmdline",
    0x8E91: "early CRT ret",
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
    pe = pefile.PE(EXE, fast_load=True)
    orig = {rva: pe.get_data(rva, 1)[0] for rva in BPS}

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
    patched = False
    de = df.DEBUG_EVENT()
    hits = []
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x} entry=0x{de.u.CreateProcessInfo.lpStartAddress:x}")
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0)
            if ec == 0x80000003 and not patched and base and rva > 0x100000:
                for bp_rva in BPS:
                    patch_byte(pi.hProcess, base + bp_rva, b"\xcc")
                patched = True
                print(f"patched {len(BPS)} BPs after loader BP @ 0x{rva:x}")
            elif ec == 0x80000003 and rva in BPS:
                ctx = df.get_thread_context(pi.hThread)
                label = BPS[rva]
                print(f"\n=== main+0x{rva:X} {label} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                print(f"  RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} RBP={ctx.Rbp:#x}")
                hits.append(label)
                patch_byte(pi.hProcess, base + rva, bytes([orig[rva]]))
                ctx.Rip = base + rva
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            print("hits:", hits)
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
