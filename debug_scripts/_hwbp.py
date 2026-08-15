#!/usr/bin/env python3
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()
CONTEXT_DEBUG_REGISTERS = 0x10


def main():
    exe = os.path.abspath(sys.argv[1])
    bp_rva = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x9182
    cmdline = '"' + exe + '" /c echo test'
    si = df.STARTUPINFO(); si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
    base = None
    hit = False
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = base + bp_rva
            ctx.Dr7 = (ctx.Dr7 & ~0xFF) | 0x1
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            print(f"bp main+0x{bp_rva:x}")
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if base and ctx.Rip == base + bp_rva and not hit:
                hit = True
                cell = C.c_ulonglong()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsi), C.byref(cell), 8, None)
                print(f"HIT rsi=0x{ctx.Rsi:x} [rsi]=0x{cell.value:x} rcx=0x{ctx.Rcx:x} r11=0x{ctx.R11:x} rax=0x{ctx.Rax:x}")
                if bp_rva in (0x2dce5, 0x891e):
                    q = C.c_ulonglong()
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(0x8006f3e1), C.byref(q), 8, None)
                    print(f"  cell 0x6f3e1 -> 0x{q.value:x}")
                ctx.Dr7 &= ~0xFF
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0xC0000005:
                print(f"AV rip=0x{ctx.Rip:x} hit_before={hit} rsi=0x{ctx.Rsi:x} rax=0x{ctx.Rax:x}")
                break
            elif hit and ec == 0x80000004:
                # stepped past bp without fault — stop tracing
                pass
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} hit={hit}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)

if __name__ == "__main__":
    main()
