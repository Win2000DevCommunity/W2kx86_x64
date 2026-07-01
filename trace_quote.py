#!/usr/bin/env python3
"""INT3 trace for cmdline builder quote/heap path (uses VirtualProtectEx)."""
import os
import struct
import ctypes as C
from ctypes import wintypes

import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
BPS = {
    0x278DA: "builder entry",
    0x27CA3: "heap loop iter",
    0x27E54: "pre mov rdi,[table+rcx]",
    0x27ED5: "pre closing quote",
}
PAGE_EXECUTE_READWRITE = 0x40


def patch_byte(proc, addr, val):
    old = wintypes.DWORD(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000,
                         PAGE_EXECUTE_READWRITE, C.byref(old))
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), C.c_char(val), 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok and n.value == 1


def read_u64(proc, addr):
    b = df.read_process_mem(proc, addr, 8)
    return int.from_bytes(b, "little") if len(b) == 8 else None


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
    skip_first = True
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            for bp in patches:
                if not patch_byte(pi.hProcess, base + bp, 0xCC):
                    print(f"  patch failed at 0x{bp:x}")
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit without fault")
            break
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - (base or 0)
            if ec == 0x80000003 and skip_first:
                skip_first = False
            elif ec == 0x80000003 and rva in patches:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\n=== main+0x{rva:X} {BPS[rva]} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                print(f"  RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} R8={ctx.R8:#x} RBP={ctx.Rbp:#x}")
                if ctx.Rbp:
                    for off, sz in ((0x10, 8), (0x18, 8), (0x20, 4), (0x28, 4),
                                    (0x38, 1), (-4, 8), (-8, 8), (-0x10, 4), (-0x14, 4)):
                        b = df.read_process_mem(pi.hProcess, ctx.Rbp + off, sz)
                        if len(b) == sz:
                            v = int.from_bytes(b, "little")
                            print(f"  [rbp{off:+d}]={v:#x}")
                if rva == 0x27E54 and ctx.Rax and ctx.Rcx is not None:
                    slot = read_u64(pi.hProcess, ctx.Rax + ctx.Rcx)
                    print(f"  table={ctx.Rax:#x} off={ctx.Rcx:#x} slot={slot:#x}")
                patch_byte(pi.hProcess, base + rva, patches[rva])
                ctx.Rip = base + rva
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\nFAULT main+0x{rva:X} RAX={ctx.Rax:#x} RDI={ctx.Rdi:#x} RBX={ctx.Rbx:#x} RBP={ctx.Rbp:#x}")
                if ctx.Rbp:
                    for off, sz in ((0x10, 8), (0x18, 8), (0x20, 4), (0x38, 1), (-4, 8), (-8, 8)):
                        b = df.read_process_mem(pi.hProcess, ctx.Rbp + off, sz)
                        if len(b) == sz:
                            print(f"  [rbp{off:+d}]={int.from_bytes(b, 'little'):#x}")
                break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
