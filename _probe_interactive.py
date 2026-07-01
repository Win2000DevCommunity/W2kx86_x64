#!/usr/bin/env python3
"""Hardware-breakpoint probe for interactive cmd_shim pipeline."""
import ctypes as C
import os
import sys

import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

CREATE_NEW_CONSOLE = 0x10
CONTEXT_FULL = 0x10001B
CONTEXT_DEBUG = 0x10001B | 0x00010010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXC_BP = 0x80000003
EXC_SINGLE_STEP = 0x80000004

SITES = [
    (0x8EB9, "main-entry"),
    (0x9040, "interactive-guard"),
    (0x9072, "drive-letter"),
    (0x91B5, "banner-gate"),
    (0x2E4B2, "banner-root"),
    (0x2E519, "swprintf"),
    (0x2E541, "banner-print"),
    (0x3D196, "readconsole"),
]


def set_hw(ctx, addr):
    ctx.Dr0 = addr
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1


def clear_hw(ctx):
    ctx.Dr7 &= ~0xF
    ctx.Dr0 = 0


def read_w(h, addr, n=120):
    if addr < 0x10000:
        return ""
    try:
        return df.read_wstr(h, addr, n)
    except Exception:
        return ""


def main():
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_out11/cmd_shim.exe")
    cmd = '"' + exe + '"'
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmd), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi),
    )
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    site_i = 0
    hits = []
    entry_rva = 0x8778
    skip_loader_bp = True
    de = df.DEBUG_EVENT()
    timeout_ms = 30000
    import time
    t0 = time.time()

    while k32.WaitForDebugEvent(C.byref(de), 100):
        if (time.time() - t0) * 1000 > timeout_ms:
            print("timeout")
            break
        st = DBG_CONTINUE
        code = de.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva, label = SITES[site_i]
            set_hw(ctx, base + rva)
            print(f"watch #{site_i+1} {label} @ 0x{rva:x}")
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            h = de.u.LoadDll.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            if ec not in (EXC_BP, EXC_SINGLE_STEP):
                if ec == 0x40010006:
                    st = DBG_CONTINUE
                else:
                    ctx = df.CONTEXT()
                    ctx.ContextFlags = CONTEXT_DEBUG
                    k32.GetThreadContext(pi.hThread, C.byref(ctx))
                    rva = ctx.Rip - base if base else 0
                    print(f"fault 0x{ec:x} @ main+0x{rva:x}")
                    break
            else:
                ctx = df.CONTEXT()
                ctx.ContextFlags = CONTEXT_DEBUG
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                rva = ctx.Rip - base
                if skip_loader_bp and ec == EXC_BP and rva != SITES[site_i][0]:
                    if rva in (entry_rva, entry_rva - 1):
                        skip_loader_bp = False
                        k32.SetThreadContext(pi.hThread, C.byref(ctx))
                        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
                        continue
                rva_hit, label = SITES[site_i]
                if rva == rva_hit:
                    hits.append(label)
                    extra = ""
                    if label == "swprintf":
                        extra = f" rdx={read_w(pi.hProcess, ctx.Rdx)!r} rcx={read_w(pi.hProcess, ctx.Rcx)!r}"
                    elif label == "banner-print":
                        extra = f" rcx={read_w(pi.hProcess, ctx.Rcx)!r} rdx={read_w(pi.hProcess, ctx.Rdx)!r}"
                    elif label == "banner-root":
                        extra = f" rcx={read_w(pi.hProcess, ctx.Rcx)!r} rsi={read_w(pi.hProcess, ctx.Rsi)!r}"
                    print(f"HIT {label} @ 0x{rva:x}{extra}")
                    site_i += 1
                    clear_hw(ctx)
                    if site_i < len(SITES):
                        nr, nl = SITES[site_i]
                        set_hw(ctx, base + nr)
                        print(f"watch #{site_i+1} {nl} @ 0x{nr:x}")
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                else:
                    ctx.EFlags |= 0x10000  # resume flag
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit 0x{de.u.ExitProcess.dwExitCode:x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

    print("hits:", ", ".join(hits) or "(none)")
    k32.TerminateProcess(pi.hProcess, 0)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return 0 if len(hits) >= 4 else 1


if __name__ == "__main__":
    raise SystemExit(main())
