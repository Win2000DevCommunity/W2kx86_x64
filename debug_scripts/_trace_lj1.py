"""Trace RDX at wait-longjmp and RAX after setjmp on probe_lj1."""
from __future__ import annotations

import ctypes as C
import os
import struct
import sys

import dbg_fault as df

EXE = os.path.abspath("build_univ258/probe_lj1/cmd_probe_lj1.exe")
JB = 0x5BB40


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
    sites: dict[int, str] = {}
    orig: dict[int, int] = {}
    sj_hits = lj_hits = 0

    def read_mem(addr: int, n: int) -> bytes:
        buf = (C.c_ubyte * n)()
        got = C.c_size_t()
        if not k32.ReadProcessMemory(
                pi.hProcess, C.c_void_p(addr), buf, n, C.byref(got)):
            return b""
        return bytes(buf[:got.value])

    def arm(abs_addr: int) -> None:
        b = (C.c_ubyte * 1)()
        k32.ReadProcessMemory(pi.hProcess, C.c_void_p(abs_addr), b, 1, None)
        orig[abs_addr] = b[0]
        cc = (C.c_ubyte * 1)(0xCC)
        k32.WriteProcessMemory(pi.hProcess, C.c_void_p(abs_addr), cc, 1, None)

    def disarm(abs_addr: int) -> None:
        if abs_addr not in orig:
            return
        b = (C.c_ubyte * 1)(orig[abs_addr])
        k32.WriteProcessMemory(pi.hProcess, C.c_void_p(abs_addr), b, 1, None)

    while True:
        ev = df.DEBUG_EVENT()
        if not k32.WaitForDebugEvent(C.byref(ev), 8000):
            print("timeout sj", sj_hits, "lj", lj_hits)
            break
        code = ev.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            for off, name in ((0x1C675, "after_setjmp"), (0x45853, "longjmp_wait")):
                sites[base + off] = name
                arm(base + off)
        elif code == df.EXCEPTION_DEBUG_EVENT:
            exc = ev.u.Exception.ExceptionRecord
            addr = exc.ExceptionAddress
            if exc.ExceptionCode == 0x80000003 and addr in sites:
                ctx = df.CONTEXT64()
                ctx.ContextFlags = 0x10001F
                k32.GetThreadContext(pi.hThread if False else
                    # need thread handle from OpenThread
                    0, C.byref(ctx))
                # Open thread properly
                ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                ctx = df.CONTEXT64()
                ctx.ContextFlags = 0x10001F
                k32.GetThreadContext(ht, C.byref(ctx))
                name = sites[addr]
                if name == "longjmp_wait":
                    lj_hits += 1
                    print(f"WAIT_LJ#{lj_hits} RDX={ctx.Rdx:#x} RCX={ctx.Rcx:#x} "
                          f"RSP={ctx.Rsp:#x}")
                else:
                    sj_hits += 1
                    print(f"AFTER_SJ#{sj_hits} RAX={ctx.Rax:#x} RSP={ctx.Rsp:#x}")
                    if sj_hits >= 6:
                        print("stop after nested setjmps")
                        k32.TerminateProcess(pi.hProcess, 1)
                        break
                disarm(addr)
                ctx.Rip = addr
                ctx.EFlags |= 0x100  # single step to re-arm
                k32.SetThreadContext(ht, C.byref(ctx))
                k32.CloseHandle(ht)
                # remember to re-arm on single-step
                sites["_ss"] = addr  # type: ignore
            elif exc.ExceptionCode == 0x80000004:
                # single-step: re-arm
                prev = sites.get("_ss")
                if isinstance(prev, int):
                    arm(prev)
                    sites.pop("_ss", None)
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            elif exc.ExceptionCode in (0xC00000FD, 0xC0000005):
                print(f"FAULT {exc.ExceptionCode:#x} @ {addr:#x}")
                break
            k32.ContinueDebugEvent(
                ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            continue
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit", ev.u.ExitProcess.dwExitCode)
            break
        k32.ContinueDebugEvent(
            ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
    return 0


if __name__ == "__main__":
    # Fix: CONTEXT helpers live on dbg_fault
    raise SystemExit(main())
