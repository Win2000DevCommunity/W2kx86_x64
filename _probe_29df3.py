from __future__ import annotations

import ctypes as C
import os
import struct

import dbg_fault as df
import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

pe = pefile.PE("build_univ261/cmd_pure.exe")
off = pe.get_offset_from_rva(0x29DF3)
blob = open("build_univ261/cmd_pure.exe", "rb").read()[off : off + 0x200]
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 261 @ 29df3 ===")
rvas = [0x29CA8, 0x29DF3]
for i in md.disasm(blob, 0x80029DF3):
    print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}")
    if i.mnemonic in ("call", "jmp", "je", "jne", "ret"):
        rvas.append(i.address - 0x80000000)
    if i.mnemonic == "ret":
        break
    if i.address >= 0x8002A0F0:
        break

# Also compare bytes 29df3..2a0f3 between 258 and 261
pe1 = pefile.PE("build_univ258/cmd_pure.exe")
pe2 = pefile.PE("build_univ261/cmd_pure.exe")
o1 = pe1.get_offset_from_rva(0x29DF3)
o2 = pe2.get_offset_from_rva(0x29DF3)
b1 = open("build_univ258/cmd_pure.exe", "rb").read()
b2 = open("build_univ261/cmd_pure.exe", "rb").read()
span = 0x2A0F3 - 0x29DF3
d1 = b1[o1 : o1 + span]
d2 = b2[o2 : o2 + span]
print("29df3..2a0f3 equal?", d1 == d2)
if d1 != d2:
    for i in range(span):
        if d1[i] != d2[i]:
            j = i
            while j < span and d1[j] != d2[j]:
                j += 1
            print(
                f"  diff {0x29DF3+i:#x}+{j-i}: "
                f"258={d1[i:i+min(24,j-i)].hex()} "
                f"261={d2[i:i+min(24,j-i)].hex()}"
            )
            break

# Resolve IAT 85430 / 85438
for name in ("build_univ258/cmd_pure.exe", "build_univ261/cmd_pure.exe"):
    pe = pefile.PE(name)
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in e.imports:
            rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
            if rva in (0x85430, 0x85438, 0x845F8):
                print(name, hex(rva), e.dll, imp.name)


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
    armed = False
    while True:
        ev = df.DEBUG_EVENT()
        if not k32.WaitForDebugEvent(C.byref(ev), 20000):
            print(label, "timeout")
            break
        if ev.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = ev.u.CreateProcessInfo.lpBaseOfImage
            for rva in sorted(set(rvas + [0x2A0F3, 0x2A177])):
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
                if rva in (0x29CA8, 0x29DF3) or armed:
                    armed = True
                    print(
                        f"{label} {rva:#x} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} "
                        f"rbx={ctx.Rbx:#x} rdi={ctx.Rdi:#x} rsi={ctx.Rsi:#x} "
                        f"rsp={ctx.Rsp:#x} rbp={ctx.Rbp:#x}"
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
                    f"rdi={ctx.Rdi:#x} rsi={ctx.Rsi:#x} rbx={ctx.Rbx:#x} "
                    f"rsp={ctx.Rsp:#x} rbp={ctx.Rbp:#x}"
                )
                # bytes at rip if in image
                if base and base <= ctx.Rip < base + 0x88000:
                    raw = bytearray(16)
                    k32.ReadProcessMemory(
                        pi.hProcess,
                        C.c_void_p(ctx.Rip),
                        (C.c_ubyte * 16).from_buffer(raw),
                        16,
                        None,
                    )
                    print(" bytes", raw.hex())
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


print("BP", [hex(x) for x in sorted(set(rvas))])
run("build_univ258/cmd_pure.exe", "258")
print("---")
run("build_univ261/cmd_pure.exe", "261")
