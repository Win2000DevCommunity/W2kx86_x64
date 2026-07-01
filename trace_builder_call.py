#!/usr/bin/env python3
"""Break at builder-call setup and dump caller frame."""
import os
import struct
import ctypes as C
from ctypes import wintypes

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = [0x27106, 0x2729A]  # mov r8d,eax; builder homed r8 -> [rbp+0x20]
k32 = df.k32
PAGE_EXECUTE_READWRITE = 0x40


def patch_byte(proc, addr, val):
    old = wintypes.DWORD(0)
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000,
                         PAGE_EXECUTE_READWRITE, C.byref(old))
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), C.c_char(val), 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok


def rva_to_off(data, rva):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_sz = struct.unpack_from("<H", data, pe + 20)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    sec = pe + 24 + opt_sz
    for i in range(n):
        o = sec + i * 40
        vs, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        if va <= rva < va + max(vs, rawsz):
            return rawptr + (rva - va)
    return None


def main():
    df.suppress_fault_ui()
    pe_data = open(EXE, "rb").read()
    patches = {}
    for bp in BPS:
        off = rva_to_off(pe_data, bp)
        if off is not None:
            patches[bp] = pe_data[off]
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
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            for bp in patches:
                patch_byte(pi.hProcess, base + bp, 0xCC)
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit without hitting bp")
            break
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - (base or 0)
            if ec == 0x80000003 and rva in patches:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\n=== main+0x{rva:X} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                print(f"  R8={ctx.R8:#x} R9={ctx.R9:#x} RBP={ctx.Rbp:#x}")
                for off, sz in ((-4, 4), (-0xC, 4), (0x10, 8), (0x18, 4),
                                (0x20, 8), (0x30, 4), (0x38, 4), (0x40, 4)):
                    v = df.read_process_mem(pi.hProcess, ctx.Rbp + off, sz)
                    if len(v) == sz:
                        print(f"  [rbp{off:+d}]={int.from_bytes(v, 'little'):#x}")
                patch_byte(pi.hProcess, base + rva, patches[rva])
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
