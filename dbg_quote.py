#!/usr/bin/env python3
"""One-shot register trace for cmd_shim quote-insert path."""
import os
import sys
import ctypes as C

import dbg_fault as df

EXE = r"C:\Users\Win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\win2000_x64\cmd_shim.exe"
BPS = (0x27B44, 0x27C45, 0x27C87, 0x27CC4, 0x27CCF)


def read_u32(proc, addr):
    b = df.read_mem(proc, addr, 4)
    return int.from_bytes(b, "little") if len(b) == 4 else None


def main():
    df.suppress_fault_ui()
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
    first_bp = True

    de = df.DEBUG_EVENT()
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        code = de.dwDebugEventCode
        status = df.DBG_CONTINUE
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            addr = er.ExceptionAddress or 0
            rva = addr - base if base else 0

            if ecode == 0x80000003 and first_bp:
                first_bp = False
                status = df.DBG_CONTINUE
            elif ecode == 0x80000003 and rva in BPS and rva not in seen:
                seen.add(rva)
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\n=== main+0x{rva:X} RBP={ctx.Rbp:#x} ===")
                print(f"  RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                print(f"  RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x}")
                if ctx.Rbp:
                    for off in (0x10, 0x18, 0x20, 0x28, -4, -8, -0xC, -0x10, -0x14, -0x18):
                        v = read_u32(pi.hProcess, ctx.Rbp + (off & 0xFFFFFFFF))
                        print(f"  [rbp{off:+d}]={v:#x}" if v is not None else f"  [rbp{off:+d}]=?")
                if ctx.Rdi and ctx.Rdi < 0x10000:
                    w = df.read_mem(pi.hProcess, ctx.Rdi, 16)
                    print(f"  mem@rdi={w.hex()}")
            elif ecode == 0xC0000005:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"\n=== FAULT main+0x{rva:X} ===")
                print(f"  RBP={ctx.Rbp:#x} RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RDI={ctx.Rdi:#x}")
                status = df.DBG_EXCEPTION_NOT_HANDLED
                break

        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)

    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
