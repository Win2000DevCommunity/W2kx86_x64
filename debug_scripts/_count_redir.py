"""Count recursive entries into redirect parser 1E2B4 during interactive."""
from __future__ import annotations

import ctypes as C
import os
import sys

import dbg_fault as df

EXE = os.path.abspath("build_univ258/cmd_probe_jcc.exe")
TARGETS = {
    0x1E2B4: "redir_parse",
    0x45853: "wfs_call",
    0x1D35C: "post_wait",
    0x3624D: "fd_chain",
}


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
    orig: dict[int, int] = {}
    hits: dict[str, int] = {n: 0 for n in TARGETS.values()}
    armed = False

    def arm(off: int) -> None:
        buf = (C.c_ubyte * 1)(0xCC)
        k32.WriteProcessMemory(
            pi.hProcess, C.c_void_p(base + off), buf, 1, None)

    def restore(off: int) -> None:
        buf = (C.c_ubyte * 1)(orig[off])
        k32.WriteProcessMemory(
            pi.hProcess, C.c_void_p(base + off), buf, 1, None)

    while True:
        ev = df.DEBUG_EVENT()
        if not k32.WaitForDebugEvent(C.byref(ev), 8000):
            print("timeout", hits)
            break
        code = ev.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            for off in TARGETS:
                b = (C.c_ubyte * 1)()
                k32.ReadProcessMemory(
                    pi.hProcess, C.c_void_p(base + off), b, 1, None)
                orig[off] = b[0]
                arm(off)
            armed = True
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = ev.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            addr = er.ExceptionAddress
            if ec == 0x80000003 and base and armed:
                off = addr - base
                if off in TARGETS:
                    name = TARGETS[off]
                    hits[name] += 1
                    th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                    ctx = df.CONTEXT()
                    ctx.ContextFlags = df.CONTEXT_FULL
                    k32.GetThreadContext(th, C.byref(ctx))
                    if hits[name] <= 5 or hits[name] % 50 == 0:
                        print(f"{name}#{hits[name]} RSP={ctx.Rsp:#x}")
                    restore(off)
                    ctx.EFlags |= 0x100  # TF single-step
                    k32.SetThreadContext(th, C.byref(ctx))
                    k32.CloseHandle(th)
                    if hits["redir_parse"] > 400:
                        print("abort: too many redir_parse", hits)
                        break
                    k32.ContinueDebugEvent(
                        ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                    continue
                # single-step complete — re-arm all sites
                for o in TARGETS:
                    arm(o)
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0x80000004 and base and armed:
                # stray single-step
                for o in TARGETS:
                    arm(o)
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            print(f"exc {ec:#x} off={addr - base:#x}" if base else f"exc {ec:#x}",
                  "hits", hits)
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)

    k32.TerminateProcess(pi.hProcess, 0)
    print("final", hits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
