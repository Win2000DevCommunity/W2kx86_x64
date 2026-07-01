#!/usr/bin/env python3
"""Verify INT3 patches land and break at builder call."""
import os
import struct
import ctypes as C
from ctypes import wintypes

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BP = 0x274F9  # after sub eax,ebx — inspect length in eax
k32 = df.k32
PAGE_EXECUTE_READWRITE = 0x40


def patch_byte(proc, addr, val):
    old = wintypes.DWORD(0)
    pg = k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000,
                              PAGE_EXECUTE_READWRITE, C.byref(old))
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), C.c_char(val), 1, C.byref(n))
    err = C.get_last_error()
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return pg, ok, n.value, err


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
    off = rva_to_off(pe_data, BP)
    orig = pe_data[off]
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
    n_int3 = 0
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            addr = base + BP
            pg, ok, n, err = patch_byte(pi.hProcess, addr, 0xCC)
            b = df.read_process_mem(pi.hProcess, addr, 1)
            print(f"base=0x{base:x} patch main+0x{BP:X} vpe={pg} wpm={ok} n={n} err={err} mem=0x{b[0]:02x}")
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit without hitting bp (int3_count={n_int3})")
            break
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - (base or 0)
            if ec == 0x80000003:
                n_int3 += 1
                print(f"INT3 #{n_int3} at main+0x{rva:X}")
                if rva == BP:
                    ctx = df.CONTEXT()
                    ctx.ContextFlags = df.CONTEXT_FULL
                    df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                    print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RBP={ctx.Rbp:#x}")
                    for off in (-4, 0x18, 0x30, 0x38, 0x40):
                        v = df.read_process_mem(pi.hProcess, ctx.Rbp + off, 4)
                        if len(v) == 4:
                            print(f"  [rbp{off:+d}]={int.from_bytes(v,'little'):#x}")
                    patch_byte(pi.hProcess, base + BP, orig)
                    ctx.Rip = base + BP
                    df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005:
                print(f"AV at main+0x{rva:X}")
                break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
