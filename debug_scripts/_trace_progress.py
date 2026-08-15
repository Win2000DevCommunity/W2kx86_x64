#!/usr/bin/env python3
import ctypes as C
import os
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

BPS = {
    0x2D9E0: "call rdi crt",
    0x2DA02: "call post-crt",
    0x8EEB: "main args",
    0x41000: "crash pad",
}


def main():
    exe = os.path.abspath(sys.argv[1])
    cmdline = '"' + exe + '" ' + " ".join(sys.argv[2:])
    si = df.STARTUPINFO()
    si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
    base = None
    hits = set()
    de = df.DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            ctx = df.CONTEXT()
            ctx.ContextFlags = df.CONTEXT_FULL | 0x10
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            for i, rva in enumerate(BPS):
                setattr(ctx, f"Dr{i}", base + rva)
            ctx.Dr7 = (ctx.Dr7 & ~0xFF) | 0x55
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            ctx = df.CONTEXT()
            ctx.ContextFlags = df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva = ctx.Rip - base if base else 0
            if ec in (0x80000001, 0x80000004) and rva in BPS and rva not in hits:
                hits.add(rva)
                cell = C.c_ulonglong()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(0x8006F471), C.byref(cell), 8, None)
                print(f"HIT {BPS[rva]} rva=0x{rva:x} rdi=0x{ctx.Rdi:x} rax=0x{ctx.Rax:x} "
                      f"rcx=0x{ctx.Rcx:x} cell=0x{cell.value:x}")
            if ec == 0xC0000005:
                print(f"AV rip=0x{ctx.Rip:x} rva=0x{rva:x} rsp=0x{ctx.Rsp:x}")
                stk = (C.c_ulonglong * 8)()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), stk, C.sizeof(stk), None)
                print("stack", [hex(x) for x in stk[:6]])
                break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print("exit", hex(de.u.ExitProcess.dwExitCode & 0xFFFFFFFF))
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    print("missed", [hex(r) for r in BPS if r not in hits])


if __name__ == "__main__":
    main()
