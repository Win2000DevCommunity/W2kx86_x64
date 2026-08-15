from __future__ import annotations
import ctypes as C
import os
import struct

import dbg_fault as df
import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

pe = pefile.PE("build_univ261/cmd_pure.exe")
off = pe.get_offset_from_rva(0x29A30)
blob = open("build_univ261/cmd_pure.exe", "rb").read()[off : off + 0x700]
for i in range(len(blob) - 2):
    if blob[i : i + 2] == bytes([0xFF, 0xD7]) and (i == 0 or blob[i - 1] != 0x41):
        print("real call rdi at", hex(0x29A30 + i))
    if blob[i : i + 2] == bytes([0xFF, 0xE7]) and (i == 0 or blob[i - 1] != 0x41):
        print("real jmp rdi at", hex(0x29A30 + i))


def run(exe: str, label: str) -> None:
    df.suppress_fault_ui()
    k32 = df.k32
    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    path = os.path.abspath(exe)
    cmd = C.create_unicode_buffer(f'"{path}" /c echo w2ktest')
    assert k32.CreateProcessW(
        None,
        cmd,
        None,
        None,
        False,
        df.DEBUG_PROCESS | df.DEBUG_ONLY_THIS_PROCESS,
        None,
        os.path.dirname(path),
        C.byref(si),
        C.byref(pi),
    )
    base = None
    bps: dict = {}
    rvas = [0x29B43, 0x29B6A, 0x29B6D, 0x29C00, 0x29D00, 0x2A0F3, 0x2A177]
    while True:
        ev = df.DEBUG_EVENT()
        if not k32.WaitForDebugEvent(C.byref(ev), 20000):
            print(label, "timeout")
            break
        if ev.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            for rva in rvas:
                a = base + rva
                bb = (C.c_ubyte * 1)()
                if not k32.ReadProcessMemory(pi.hProcess, C.c_void_p(a), bb, 1, None):
                    continue
                bps[a] = (rva, bb[0])
                k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(a), (C.c_ubyte * 1)(0xCC), 1, None
                )
        elif ev.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = ev.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            addr = er.ExceptionAddress
            if ec == 0x80000003 and addr in bps:
                rva, orig = bps[addr]
                th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(th, C.byref(ctx))
                print(
                    f"{label} {rva:#x} rax={ctx.Rax:#x} r15={ctx.R15:#x} "
                    f"rdi={ctx.Rdi:#x} rsp={ctx.Rsp:#x}"
                )
                k32.WriteProcessMemory(
                    pi.hProcess, C.c_void_p(addr), (C.c_ubyte * 1)(orig), 1, None
                )
                ctx.Rip = addr
                k32.SetThreadContext(th, C.byref(ctx))
                k32.CloseHandle(th)
                del bps[addr]
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0xC0000005:
                th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(th, C.byref(ctx))
                print(
                    f"{label} FAULT {ctx.Rip:#x} rax={ctx.Rax:#x} "
                    f"rdi={ctx.Rdi:#x} r15={ctx.R15:#x} rsp={ctx.Rsp:#x}"
                )
                st = bytearray(32)
                n = C.c_size_t()
                k32.ReadProcessMemory(
                    pi.hProcess,
                    C.c_void_p(ctx.Rsp),
                    (C.c_ubyte * 32).from_buffer(st),
                    32,
                    C.byref(n),
                )
                print(" stack", [hex(x) for x in struct.unpack("<4Q", st)])
                k32.TerminateProcess(pi.hProcess, 1)
                break
        elif ev.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(label, "exit", ev.u.ExitProcess.dwExitCode)
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)


run("build_univ258/cmd_pure.exe", "258")
print("---")
run("build_univ261/cmd_pure.exe", "261")
