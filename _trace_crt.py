#!/usr/bin/env python3
"""Single-step only inside CRT band main+0x8778..0x9200 until AV."""
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()
LO, HI, MAX = 0x8778, 0x9200, 8000


def in_band(base, rip):
    return base and LO <= rip - base <= HI


def main():
    exe = os.path.abspath(sys.argv[1])
    cmdline = '"' + exe + '" ' + " ".join(sys.argv[2:])
    si = df.STARTUPINFO(); si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi))
    if not ok:
        print("fail", C.get_last_error()); return 1

    base = None
    ring = []
    steps = 0
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
            h = de.u.LoadDll.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            if ec == 0xC0000005:
                print(f"AV rip=0x{rip:x} last in band below")
                break
            if ec == 0x80000004 and in_band(base, rip):
                steps += 1
                rva = rip - base
                ring.append((rva, ctx.Rax, ctx.Rcx, ctx.Rsi, ctx.R11))
                if len(ring) > 40:
                    ring.pop(0)
                if steps >= MAX:
                    print("max steps"); break
            if in_band(base, rip) and ec in (0x80000003, 0x80000004):
                ctx.EFlags |= 0x100
            else:
                ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)

    for rva, rax, rcx, rsi, r11 in ring[-25:]:
        print(f"  main+0x{rva:x} rax=0x{rax:x} rcx=0x{rcx:x} rsi=0x{rsi:x} r11=0x{r11:x}")
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
