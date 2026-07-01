#!/usr/bin/env python3
"""Read runtime IAT slots at first chance after load."""
import ctypes as C
import os
import struct
import sys
import dbg_fault as df

k32 = df.k32
df.suppress_fault_ui()

SLOTS = {
    'wcslen@6f3e1': 0x6F3E1,
    'wcslen@6f3e9': 0x6F3E9,
    'cell@6f469': 0x6F469,
    'GetProc@6efed': 0x6EFED,
    'GWS@6eff5': 0x6EFF5,
}


def main():
    exe = os.path.abspath(sys.argv[1])
    cmdline = '"' + exe + '" ' + " ".join(sys.argv[2:])
    si = df.STARTUPINFO(); si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS | 0x00000001, None, os.path.dirname(exe) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print("fail", C.get_last_error()); return 1
    base = None
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
            ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            if ec == 0xC0000005:
                ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"AV rip=0x{ctx.Rip:x} RAX=0x{ctx.Rax:x}")
                break
            if base and ec in (0x80000003, 0x80000004):
                # after all dlls - check on second BP or when rip in main
                ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                if 0x8778 <= ctx.Rip - base <= 0x9200:
                    print(f"at main+0x{ctx.Rip-base:x}")
                    for name, rva in SLOTS.items():
                        q = C.c_ulonglong()
                        k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(q), 8, None)
                        print(f"  {name} -> 0x{q.value:x}")
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x00010002)
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
