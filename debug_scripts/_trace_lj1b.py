"""Trace setjmp entry (inside shim) and longjmp with jmp_buf dump."""
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
    shim = None
    sj_hits = 0
    lj_hits = 0
    # Break after call returns path: INT3 on instruction after setjmp call
    # and on longjmp call site — also resolve shim setjmp/longjmp exports
    sites: dict[int, str] = {}
    orig: dict[int, int] = {}

    def read_mem(addr: int, n: int) -> bytes:
        buf = (C.c_ubyte * n)()
        got = C.c_size_t()
        if not k32.ReadProcessMemory(
                pi.hProcess, C.c_void_p(addr), buf, n, C.byref(got)):
            return b""
        return bytes(buf[:got.value])

    def arm(abs_addr: int) -> None:
        off = abs_addr  # store absolute for shim
        b = (C.c_ubyte * 1)()
        k32.ReadProcessMemory(pi.hProcess, C.c_void_p(abs_addr), b, 1, None)
        orig[abs_addr] = b[0]
        cc = (C.c_ubyte * 1)(0xCC)
        k32.WriteProcessMemory(pi.hProcess, C.c_void_p(abs_addr), cc, 1, None)

    while True:
        ev = df.DEBUG_EVENT()
        if not k32.WaitForDebugEvent(C.byref(ev), 12000):
            print("timeout", "sj", sj_hits, "lj", lj_hits)
            break
        code = ev.dwDebugEventCode
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            # post-setjmp and longjmp-wait in main image
            for off, name in ((0x1C675, "after_setjmp"), (0x45853, "longjmp_wait")):
                sites[base + off] = name
                arm(base + off)
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            dll_base = ev.u.LoadDll.lpBaseOfDll
            # Only the translator shim (high user range 0x18000…. or near main)
            if not dll_base or not (0x180000000 <= dll_base < 0x200000000):
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            mz = read_mem(dll_base, 0x200)
            if len(mz) >= 0x40 and mz[:2] == b"MZ":
                e = struct.unpack_from("<I", mz, 0x3C)[0]
                peh = read_mem(dll_base + e, 0x100)
                if len(peh) >= 0x90 and peh[:4] == b"PE\0\0":
                    exp_rva = struct.unpack_from("<I", peh, 0x88)[0]
                    if exp_rva:
                        exp = read_mem(dll_base + exp_rva, 0x40)
                        if len(exp) >= 0x28:
                            nnames = struct.unpack_from("<I", exp, 0x18)[0]
                            nrva = struct.unpack_from("<I", exp, 0x20)[0]
                            orva = struct.unpack_from("<I", exp, 0x1C)[0]
                            arva = struct.unpack_from("<I", exp, 0x24)[0]
                            names = read_mem(dll_base + nrva, nnames * 4)
                            ords = read_mem(dll_base + arva, nnames * 2)
                            funcs = read_mem(dll_base + orva, nnames * 4)
                            for i in range(min(nnames, len(names) // 4)):
                                nr = struct.unpack_from("<I", names, i * 4)[0]
                                nb = read_mem(dll_base + nr, 32)
                                nm = nb.split(b"\0")[0].decode("ascii", "replace")
                                if nm in ("_setjmp3", "longjmp"):
                                    ord_ = struct.unpack_from("<H", ords, i * 2)[0]
                                    fr = struct.unpack_from("<I", funcs, ord_ * 4)[0]
                                    abs_a = dll_base + fr
                                    sites[abs_a] = nm
                                    arm(abs_a)
                                    print(f"armed {nm} @ {abs_a:#x}")
            k32.ContinueDebugEvent(
                ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            continue
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = ev.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            addr = er.ExceptionAddress
            if ec == 0x80000003 and addr not in sites:
                # system breakpoint etc.
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0x80000003 and addr in sites:
                th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(th, C.byref(ctx))
                name = sites[addr]
                if name == "_setjmp3":
                    sj_hits += 1
                    ret = read_mem(ctx.Rsp, 8)
                    retv = struct.unpack_from("<Q", ret, 0)[0] if len(ret) == 8 else 0
                    print(f"SETJMP#{sj_hits} RCX={ctx.Rcx:#x} RSP={ctx.Rsp:#x} "
                          f"ret={retv:#x} RBP={ctx.Rbp:#x}")
                elif name == "longjmp":
                    lj_hits += 1
                    jb = read_mem(ctx.Rcx, 0x40) if ctx.Rcx else b""
                    rip = rsp = 0
                    if len(jb) >= 0x30:
                        rip = struct.unpack_from("<Q", jb, 0x28)[0]
                        rsp = struct.unpack_from("<Q", jb, 0x20)[0]
                    print(f"LONGJMP#{lj_hits} JB={ctx.Rcx:#x} val={ctx.Rdx:#x} "
                          f"curRSP={ctx.Rsp:#x} jb.RIP={rip:#x} jb.RSP={rsp:#x}")
                    if lj_hits >= 8:
                        break
                elif name == "after_setjmp":
                    print(f"AFTER_SJ RAX={ctx.Rax:#x} RSP={ctx.Rsp:#x}")
                    jb = read_mem(base + JB, 0x40)
                    if len(jb) >= 0x30:
                        print(f"  jb.RIP={struct.unpack_from('<Q', jb, 0x28)[0]:#x} "
                              f"jb.RSP={struct.unpack_from('<Q', jb, 0x20)[0]:#x}")
                elif name == "longjmp_wait":
                    print(f"WAIT_LJ_SITE RSP={ctx.Rsp:#x}")
                ob = (C.c_ubyte * 1)(orig[addr])
                k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(addr), ob, 1, None)
                ctx.EFlags |= 0x100
                k32.SetThreadContext(th, C.byref(ctx))
                k32.CloseHandle(th)
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0x80000004:
                for a in sites:
                    cc = (C.c_ubyte * 1)(0xCC)
                    k32.WriteProcessMemory(
                        pi.hProcess, C.c_void_p(a), cc, 1, None)
                k32.ContinueDebugEvent(
                    ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            off = (addr - base) if base and addr >= base else addr
            print(f"exc {ec:#x} off={off:#x} sj={sj_hits} lj={lj_hits}")
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)

    k32.TerminateProcess(pi.hProcess, 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
