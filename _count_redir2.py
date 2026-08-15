"""Hit-count 1E2B4 / fd_chain; dump event handle at first WFS."""
from __future__ import annotations

import ctypes as C
import os
import struct
import sys

import dbg_fault as df

EXE = os.path.abspath("build_univ258/cmd_probe_jcc.exe")


def main() -> int:
    df.suppress_fault_ui()
    k32 = df.k32
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    cmd = C.create_unicode_buffer('"%s"' % EXE)
    assert k32.CreateProcessW(
        None, cmd, None, None, False,
        df.DEBUG_PROCESS | df.DEBUG_ONLY_THIS_PROCESS,
        None, os.path.dirname(EXE), C.byref(si), C.byref(pi))

    base = None
    sites = {0x1E2B4: "redir", 0x3624D: "chain", 0x45853: "wfs"}
    orig: dict[int, int] = {}
    hits = {n: 0 for n in sites.values()}
    wfs_info_done = False

    def read_mem(addr: int, n: int) -> bytes:
        buf = (C.c_ubyte * n)()
        got = C.c_size_t()
        if not k32.ReadProcessMemory(
                pi.hProcess, C.c_void_p(addr), buf, n, C.byref(got)):
            return b""
        return bytes(buf[:got.value])

    while True:
        ev = df.DEBUG_EVENT()
        if not k32.WaitForDebugEvent(C.byref(ev), 10000):
            print("timeout", hits)
            break
        code = ev.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            for off in sites:
                b = (C.c_ubyte * 1)()
                k32.ReadProcessMemory(
                    pi.hProcess, C.c_void_p(base + off), b, 1, None)
                orig[off] = b[0]
                cc = (C.c_ubyte * 1)(0xCC)
                k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(base + off), cc, 1, None)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = ev.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            addr = er.ExceptionAddress
            if base is None:
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            off = addr - base
            if not (0 <= off < 0x88000):
                # system breakpoint / other module
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0x80000003 and off in sites:
                name = sites[off]
                hits[name] += 1
                th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(th, C.byref(ctx))
                if name == "wfs" and not wfs_info_done:
                    wfs_info_done = True
                    # RCX = handle at call site
                    print(f"WFS RCX(handle)={ctx.Rcx:#x} RDX(timeout)={ctx.Rdx:#x}")
                    evh = read_mem(base + 0x5BB40, 8)
                    fae0 = read_mem(base + 0x5BAE0, 4)
                    print("event_cell", evh.hex() if evh else None,
                          "fae0", fae0.hex() if fae0 else None)
                if hits[name] <= 3 or hits[name] % 100 == 0:
                    print(f"{name}#{hits[name]} RSP={ctx.Rsp:#x}")
                # restore, advance RIP past INT3 by executing original via
                # rewrite + TF
                ob = (C.c_ubyte * 1)(orig[off])
                k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(addr), ob, 1, None)
                ctx.EFlags |= 0x100
                k32.SetThreadContext(th, C.byref(ctx))
                k32.CloseHandle(th)
                if hits["redir"] > 300:
                    print("abort", hits)
                    break
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0x80000004:
                for o in sites:
                    cc = (C.c_ubyte * 1)(0xCC)
                    k32.WriteProcessMemory(
                        pi.hProcess, C.c_void_p(base + o), cc, 1, None)
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            print(f"exc {ec:#x} off={off:#x}", hits)
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)

    k32.TerminateProcess(pi.hProcess, 0)
    print("final", hits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
