"""Break on seed helper; log fbe2/fbc8/sticky each entry."""
import ctypes as C
import ctypes.wintypes as w
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dbg_fault import (
    CONTEXT, CONTEXT_FULL, DEBUG_EVENT, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
    CREATE_PROCESS_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    DEBUG_ONLY_THIS_PROCESS, STARTUPINFO, PROCESS_INFORMATION, k32, INFINITE,
)

HELPER_RVA = 0x48550
FBE2 = 0x5BBE2
FBC8 = 0x5BBC8
STICKY = 0x5BE00


def main():
    exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_univ201/cmd_pure.exe")
    args = sys.argv[2:] or ["/c", "echo", "w2ktest"]
    cwd = os.path.dirname(exe)
    cmdline = '"%s" %s' % (exe, " ".join(args))
    si = STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        exe, C.create_unicode_buffer(cmdline), None, None, False,
        DEBUG_ONLY_THIS_PROCESS, None, cwd, C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    helper = None
    hits = 0
    de = DEBUG_EVENT()
    t0 = time.time()
    while time.time() - t0 < 10:
        if not k32.WaitForDebugEvent(C.byref(de), 1000):
            continue
        status = DBG_CONTINUE
        code = de.dwDebugEventCode
        if code == CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            helper = base + HELPER_RVA
            print(f"base={base:#x} helper={helper:#x}")
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = helper
            ctx.Dr7 = 0x1
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            addr = er.ExceptionAddress or 0
            first = de.u.Exception.dwFirstChance
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if helper and ecode in (0x80000004, 0x80000003) and (
                    ctx.Rip == helper or addr == helper):
                hits += 1
                buf = (C.c_char * 0x40)()
                n = C.c_size_t()
                k32.ReadProcessMemory(
                    pi.hProcess, C.c_void_p(base + FBE2), buf, 0x40, C.byref(n))
                try:
                    fbe2 = bytes(buf).decode("utf-16-le", "replace").split("\0")[0][:40]
                except Exception:
                    fbe2 = "?"
                dw = (C.c_uint32 * 1)()
                k32.ReadProcessMemory(
                    pi.hProcess, C.c_void_p(base + FBC8), dw, 4, C.byref(n))
                st = (C.c_uint32 * 1)()
                k32.ReadProcessMemory(
                    pi.hProcess, C.c_void_p(base + STICKY), st, 4, C.byref(n))
                print(
                    f"hit{hits} rip={ctx.Rip:#x} rcx={ctx.Rcx:#x} "
                    f"fbc8={dw[0]:#x} sticky={st[0]} fbe2={fbe2!r}")
                ctx.EFlags |= 0x10000
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                if hits >= 40:
                    print("hit cap")
                    break
            elif ecode == 0xC00000FD:
                print(f"SO at {addr:#x} rip={ctx.Rip:#x} rcx={ctx.Rcx:#x}")
                break
            elif ecode == 0xC0000005:
                print(f"AV first={first} at {addr:#x}")
                if first:
                    status = DBG_EXCEPTION_NOT_HANDLED
                else:
                    break
            elif ecode in (0x80000003, 0x80000004):
                status = DBG_CONTINUE
            else:
                status = DBG_EXCEPTION_NOT_HANDLED if first else DBG_CONTINUE
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print("exit", de.u.ExitProcess.dwExitCode)
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
    try:
        k32.TerminateProcess(pi.hProcess, 1)
    except Exception:
        pass
    print("done hits", hits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
