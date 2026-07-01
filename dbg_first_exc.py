"""Print first N exceptions while debugging cmd_shim (no VS JIT popup)."""
import ctypes as C
import os
import sys

import dbg_fault as df

SEM_NOGPFAULTERRORBOX = 0x0002
SEM_FAILCRITICALERRORS = 0x0001
SEM_NOOPENFILEERRORBOX = 0x8000


def suppress_fault_ui():
    df.k32.SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS
                        | SEM_NOOPENFILEERRORBOX)


def main():
    suppress_fault_ui()
    exe = sys.argv[1]
    args = sys.argv[2:]
    limit = 8
    for a in list(args):
        if a.startswith("--n="):
            limit = int(a[4:])
            args.remove(a)
    cmdline = '"' + exe + '" ' + " ".join(args)
    si = df.STARTUPINFO()
    si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = df.k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    n = 0
    de = df.DEBUG_EVENT()
    while True:
        if not df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
            break
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x}")
            h = de.u.CreateProcessInfo.hFile
            if h:
                df.k32.CloseHandle(h)
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            if ecode in (0x80000003, 0x80000004) and n == 0:
                pass
            else:
                ctx = df.CONTEXT()
                ctx.ContextFlags = df.CONTEXT_FULL
                df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
                addr = er.ExceptionAddress or ctx.Rip
                tag = ""
                if 0x1800100000 <= addr < 0x1800200000:
                    tag = f" shim+0x{addr - 0x1800100000:x}"
                elif base and base <= addr < base + 0x200000:
                    tag = f" main+0x{addr - base:x}"
                print(f"  #{n + 1} code=0x{ecode:08x} fc={de.u.Exception.dwFirstChance} "
                      f"rip=0x{ctx.Rip:x} at=0x{addr:x}{tag} rsp=0x{ctx.Rsp:x}")
                n += 1
                if n >= limit:
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
    df.k32.TerminateProcess(pi.hProcess, 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
