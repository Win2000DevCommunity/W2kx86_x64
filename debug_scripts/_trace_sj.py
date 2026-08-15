"""Trace setjmp/longjmp on bb40 during interactive."""
from __future__ import annotations

import ctypes as C
import os
import struct
import sys

import dbg_fault as df

EXE = os.path.abspath("build_univ258/cmd_probe_lj.exe")
# IAT cells
SETJMP_IAT = 0x84EA0
LONGJMP_IAT = 0x84E78
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
    sj_hits = 0
    lj_hits = 0
    # Break on call sites that use bb40 — setjmp at 1C673, longjmp waiter 45853
    sites = {0x1C673: "setjmp_call", 0x45853: "longjmp_wait"}
    orig: dict[int, int] = {}

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
            print("timeout", "sj", sj_hits, "lj", lj_hits)
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
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0x80000003 and off in sites:
                th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(th, C.byref(ctx))
                name = sites[off]
                if name == "setjmp_call":
                    sj_hits += 1
                    print(f"SETJMP#{sj_hits} RCX={ctx.Rcx:#x} RSP={ctx.Rsp:#x} "
                          f"ret={[hex(struct.unpack_from('<Q', read_mem(ctx.Rsp, 8), 0)[0]) if read_mem(ctx.Rsp, 8) else None]}")
                else:
                    lj_hits += 1
                    jb = read_mem(base + JB, 0x40)
                    rip = rsp = 0
                    if len(jb) >= 0x30:
                        rip = struct.unpack_from("<Q", jb, 0x28)[0]
                        rsp = struct.unpack_from("<Q", jb, 0x20)[0]
                    print(f"LONGJMP#{lj_hits} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} "
                          f"RSP={ctx.Rsp:#x} jb.RIP={rip:#x} jb.RSP={rsp:#x}")
                    if lj_hits >= 5:
                        print("abort after 5 longjmps")
                        break
                ob = (C.c_ubyte * 1)(orig[off])
                k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(addr), ob, 1, None)
                ctx.EFlags |= 0x100
                k32.SetThreadContext(th, C.byref(ctx))
                k32.CloseHandle(th)
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
            print(f"exc {ec:#x} off={off:#x} sj={sj_hits} lj={lj_hits}")
            if ec == 0xC00000FD:
                print("STACK_OVERFLOW")
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)

    k32.TerminateProcess(pi.hProcess, 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
