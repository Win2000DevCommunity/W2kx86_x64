#!/usr/bin/env python3
"""INT3 trace for cmdline builder heap + quote path."""
import os
import struct
import ctypes as C

import dbg_fault as df

EXE = os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe")
BPS = [
    0x274F3,  # mov eax,[rbp-4]
    0x274F9,  # sub eax,ebx (next: mov r8,rax)
    0x2768A,  # builder entry
    0x27A9F,  # heap slot store (approx)
    0x27C2E,  # mov eax,[rbp+0x20]
]


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


def dump_frame(proc, rbp):
    for off in (0x10, 0x18, 0x20, 0x28, -4, -8, -0x10, -0x14, -0x18):
        v = read_u32(proc, rbp + off)
        if v is not None:
            print(f"  [rbp{off:+d}]={v:#x}")


def main():
    df.suppress_fault_ui()
    exe = os.path.abspath(EXE)
    pe_data = open(exe, "rb").read()
    patches = {}
    for rva in BPS:
        off = rva_to_off(pe_data, rva)
        if off is not None:
            patches[rva] = pe_data[off]

    cmdline = f'"{exe}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    ok = df.k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    first = True
    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            for rva in patches:
                df.k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(base + rva),
                    C.c_char(0xCC), 1, C.byref(C.c_size_t(0)))
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            rva = (er.ExceptionAddress or 0) - base
            if ec == 0x80000003 and first:
                first = False
            elif ec == 0x80000003 and rva in patches:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\n=== main+0x{rva:X} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                print(f"  RDI={ctx.Rdi:#x} RSI={ctx.Rsi:#x} R8={ctx.R8:#x} RBP={ctx.Rbp:#x}")
                if ctx.Rbp:
                    dump_frame(pi.hProcess, ctx.Rbp)
                g = read_u64(pi.hProcess, base + 0x41460)
                print(f"  global@41460 qword={g:#x}")
                if ctx.Rax and ctx.Rcx is not None and rva in (0x27DBE, 0x27E41, 0x27D0C):
                    slot = read_u64(pi.hProcess, ctx.Rax + ctx.Rcx)
                    print(f"  [rax+rcx] slot={slot:#x}")
                orig = patches[rva]
                df.k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(base + rva),
                    C.c_char(orig), 1, C.byref(C.c_size_t(0)))
                ctx.Rip = base + rva
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\nFAULT main+0x{rva:X} RAX={ctx.Rax:#x} RDI={ctx.Rdi:#x} RBX={ctx.Rbx:#x}")
                if ctx.Rbp:
                    dump_frame(pi.hProcess, ctx.Rbp)
                break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
