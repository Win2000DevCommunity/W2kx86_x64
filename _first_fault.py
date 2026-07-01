#!/usr/bin/env python3
"""Capture first fault with exception info and module for RIP."""
import ctypes as C
import os
import struct
import sys

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
STATUS_BREAKPOINT = 0x80000003


def mod_label(base, rip, dll_bases):
    if rip == 0:
        return "RIP=0"
    if base and base <= rip < base + 0x500000:
        return f"main+0x{rip - base:X}"
    for b, name in dll_bases.items():
        if b <= rip < b + 0x2000000:
            return f"{name}+0x{rip - b:X}"
    return f"0x{rip:X}"


def main():
    exe = os.path.abspath(sys.argv[1])
    args = sys.argv[2:]
    cmdline = '"' + exe + '" ' + " ".join(args)
    si = df.STARTUPINFO()
    si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    dll_bases = {}
    entry_rva = 0x8777
    passed_entry = False
    de = df.DEBUG_EVENT()
    n_bp = 0

    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        st = df.DBG_CONTINUE
        code = de.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x} entry=main+0x{entry_rva:x}")
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            b = de.u.LoadDll.lpBaseOfDll
            dll_bases[b] = f"dll@0x{b:x}"
            h = de.u.LoadDll.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            addr = er.ExceptionAddress or 0
            ctx = df.CONTEXT()
            ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            if base and rip >= base + entry_rva:
                passed_entry = True
            if ec == STATUS_BREAKPOINT:
                n_bp += 1
                if n_bp <= 2:
                    print(f"BP #{n_bp} at {mod_label(base, rip, dll_bases)}")
            elif ec == EXCEPTION_ACCESS_VIOLATION:
                info = er.ExceptionInformation
                op = info[0] if info else -1
                bad = info[1] if info and len(info) > 1 else 0
                ops = {0: "read", 1: "write", 8: "exec"}
                print(f"AV op={ops.get(op, op)} bad_addr=0x{bad:x}")
                print(f"  exc_addr={mod_label(base, addr, dll_bases)} ctx_rip={mod_label(base, rip, dll_bases)}")
                print(f"  passed_entry={passed_entry} RAX=0x{ctx.Rax:x} RCX=0x{ctx.Rcx:x} R11=0x{ctx.R11:x}")
                print(f"  RSP=0x{ctx.Rsp:x} RBP=0x{ctx.Rbp:x}")
                # stack
                buf = (C.c_char * 0x80)()
                n = C.c_size_t(0)
                if k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 0x80, C.byref(n)):
                    for i in range(0, min(n.value, 0x80), 8):
                        v = struct.unpack_from("<Q", buf, i)[0]
                        if v:
                            print(f"  [rsp+0x{i:02x}]=0x{v:x} {mod_label(base, v, dll_bases)}")
                break
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
