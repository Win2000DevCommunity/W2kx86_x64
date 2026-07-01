#!/usr/bin/env python3
"""INT3 breakpoints at RVAs — print registers and continue once."""
import os
import sys
import struct
import ctypes as C

import dbg_fault as df

EXE = r"C:\Users\Win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\win2000_x64\cmd_shim.exe"
BPS = [0x2747A, 0x27485, 0x27B79, 0x27BBB, 0x27BF9]


def read_u32(proc, addr):
    b = df.read_mem(proc, addr, 4)
    return int.from_bytes(b, "little") if len(b) == 4 else None


def read_u64(proc, addr):
    b = df.read_mem(proc, addr, 8)
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
    for rva in BPS:
        off = rva_to_off(pe_data, rva)
        if off is None:
            print(f"skip unmapped rva {rva:#x}")
            continue
        patches[rva] = (off, pe_data[off])

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
    seen = set()
    patched = False
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        code = de.dwDebugEventCode
        status = df.DBG_CONTINUE
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            for rva, (off, orig) in patches.items():
                addr = base + rva
                df.k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(addr),
                    C.c_char(0xCC), 1, C.byref(C.c_size_t(0)))
            patched = True
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            addr = er.ExceptionAddress or 0
            rva = addr - base if base else 0

            if ecode == 0x80000003 and patched:
                if rva in patches and rva not in seen:
                    seen.add(rva)
                    ctx = df.CONTEXT()
                    ctx.ContextFlags = df.CONTEXT_FULL
                    df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                    print(f"\n=== BP main+0x{rva:X} ===")
                    print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                    print(f"  RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} RBP={ctx.Rbp:#x}")
                    if ctx.Rbp:
                        for off in (0x10, 0x18, 0x20, 0x28, 0x40, -4):
                            v = read_u32(pi.hProcess, ctx.Rbp + (off & 0xFFFFFFFF))
                            print(f"  [rbp{off:+d}]={v:#x}" if v is not None else f"  [rbp{off:+d}]=?")
                    orig = patches[rva][1]
                    df.k32.WriteProcessMemory(
                        pi.hProcess, C.c_void_p(addr),
                        C.c_char(orig), 1, C.byref(C.c_size_t(0)))
                    ctx.Rip = addr
                    df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ecode == 0xC0000005:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\n=== FAULT main+0x{rva:X} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RDI={ctx.Rdi:#x} RBP={ctx.Rbp:#x}")
                status = df.DBG_EXCEPTION_NOT_HANDLED
                break

        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)

    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
