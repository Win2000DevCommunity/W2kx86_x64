from __future__ import annotations

import ctypes as C
import os
import struct

import dbg_fault as df
import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs


def disasm_range(exe: str, rva: int, n: int = 0x200) -> None:
    pe = pefile.PE(exe)
    off = pe.get_offset_from_rva(rva)
    blob = open(exe, "rb").read()[off : off + n]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(f"=== {exe} @ {rva:#x} ===")
    for i in md.disasm(blob, 0x80000000 + rva):
        print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}")
        if i.mnemonic == "ret" and i.address > 0x80000000 + rva + 0x20:
            break
        if i.address >= 0x80000000 + rva + n - 0x10:
            break


def run(exe: str, label: str, rvas: list[int]) -> None:
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
    armed = False
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
                if rva == rvas[0] or armed:
                    armed = True
                    print(
                        f"{label} {rva:#x} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} "
                        f"rdx={ctx.Rdx:#x} r8={ctx.R8:#x} r15={ctx.R15:#x} "
                        f"rdi={ctx.Rdi:#x} rsi={ctx.Rsi:#x} rsp={ctx.Rsp:#x}"
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
                    f"{label} FAULT rip={ctx.Rip:#x} rax={ctx.Rax:#x} "
                    f"rdi={ctx.Rdi:#x} rsi={ctx.Rsi:#x} r15={ctx.R15:#x} "
                    f"rsp={ctx.Rsp:#x}"
                )
                st = bytearray(48)
                n = C.c_size_t()
                k32.ReadProcessMemory(
                    pi.hProcess,
                    C.c_void_p(ctx.Rsp),
                    (C.c_ubyte * 48).from_buffer(st),
                    48,
                    C.byref(n),
                )
                print(" stack", [hex(x) for x in struct.unpack("<6Q", st)])
                k32.TerminateProcess(pi.hProcess, 1)
                break
        elif ev.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(label, "exit", ev.u.ExitProcess.dwExitCode)
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)


# Disasm the gap 29c00..2a0f3 where 261 dies
disasm_range("build_univ261/cmd_pure.exe", 0x29C00, 0x120)
print()
# Trace denser BPs in that window
pe = pefile.PE("build_univ261/cmd_pure.exe")
off = pe.get_offset_from_rva(0x29C00)
blob = open("build_univ261/cmd_pure.exe", "rb").read()[off : off + 0x100]
md = Cs(CS_ARCH_X86, CS_MODE_64)
rvas = [0x29C00]
for i in md.disasm(blob, 0x80029C00):
    if i.mnemonic in ("call", "jmp", "je", "jne", "ret"):
        rvas.append(i.address - 0x80000000)
    if i.address >= 0x80029CF0:
        break
print("BP rvas", [hex(x) for x in rvas])
run("build_univ258/cmd_pure.exe", "258", rvas)
print("---")
run("build_univ261/cmd_pure.exe", "261", rvas)
