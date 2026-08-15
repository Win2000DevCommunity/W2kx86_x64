"""INT3 probes along InitCmd to find last progress before crash."""
import ctypes as C
import os
import sys
from ctypes import wintypes

from dbg_fault import (
    CONTEXT, CONTEXT_FULL, CREATE_PROCESS_DEBUG_EVENT, DBG_CONTINUE,
    DBG_EXCEPTION_NOT_HANDLED, DEBUG_EVENT, DEBUG_ONLY_THIS_PROCESS,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    PROCESS_INFORMATION, STARTUPINFO, k32,
)

probes = [
    0x12594, 0x126cb, 0x128f5, 0x12916, 0x12b58,
    0x12c44, 0x12d20, 0x12e00, 0x12f00, 0x13000,
    0x13100, 0x13200, 0x13300,
]

exe = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build_univ168/cmd_pure.exe")
args = sys.argv[2:] or ["/c", "echo", "w2ktest"]
cmdline = '"%s" %s' % (exe, " ".join(args))
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
ok = k32.CreateProcessW(
    exe, C.create_unicode_buffer(cmdline), None, None, False,
    DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe),
    C.byref(si), C.byref(pi),
)
assert ok, C.get_last_error()

base = None
orig = {}
hit = []
ReadProcessMemory = k32.ReadProcessMemory
WriteProcessMemory = k32.WriteProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
WriteProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]

def rpm(a, n):
    b = (C.c_char * n)(); m = C.c_size_t(0)
    if ReadProcessMemory(pi.hProcess, C.c_void_p(a), b, n, C.byref(m)):
        return bytes(b[:m.value])
    return b""

def wpm(a, data):
    buf = C.create_string_buffer(data); m = C.c_size_t(0)
    return WriteProcessMemory(pi.hProcess, C.c_void_p(a), buf, len(data), C.byref(m))

def plant():
    for rva in probes:
        addr = base + rva
        ob = rpm(addr, 1)
        if len(ob) != 1:
            continue
        orig[rva] = ob
        wpm(addr, b"\xcc")

de = DEBUG_EVENT(); first = 0
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 60000):
        print("timeout"); break
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
        plant(); print("planted at base", hex(base))
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile:
            k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress or 0
        if ecode == 0x80000003:
            if first == 0:
                first = 1
            elif base and base <= addr < base + 0x200000:
                rva = addr - base
                if rva in orig:
                    hit.append(rva)
                    wpm(addr, orig[rva])
                    ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
                    k32.GetThreadContext(pi.hThread, C.byref(ctx))
                    print("HIT rva=%s rsp=%s rax=%s rcx=%s r12=%s rbp=%s rsi=%s rdi=%s" % (
                        hex(rva), hex(ctx.Rsp), hex(ctx.Rax), hex(ctx.Rcx),
                        hex(ctx.R12), hex(ctx.Rbp), hex(ctx.Rsi), hex(ctx.Rdi)))
                    ctx.Rip = addr
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                else:
                    print("unexpected bp", hex(addr - base))
                    status = DBG_EXCEPTION_NOT_HANDLED
        elif ecode == 0xC0000005:
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            op = er.ExceptionInformation[0]
            fault = er.ExceptionInformation[1] & 0xFFFFFFFFFFFFFFFF
            kind = {0: "read", 1: "write", 8: "execute"}.get(op, str(op))
            print("CRASH %s@%s rip=%s last_hits=%s" % (kind, hex(fault), hex(ctx.Rip), [hex(x) for x in hit]))
            print("  rax=%s rcx=%s rdx=%s r12=%s rbp=%s rsi=%s rdi=%s" % (
                hex(ctx.Rax), hex(ctx.Rcx), hex(ctx.Rdx), hex(ctx.R12),
                hex(ctx.Rbp), hex(ctx.Rsi), hex(ctx.Rdi)))
            print("  r14=%s r15=%s rsp=%s" % (hex(ctx.R14), hex(ctx.R15), hex(ctx.Rsp)))
            st = rpm(ctx.Rsp, 0x100)
            for i in range(0, len(st), 8):
                q = int.from_bytes(st[i:i+8], "little")
                mark = ("  rva=%s" % hex(q - base)) if base <= q < base + 0x200000 else ""
                print("  [rsp+%02x]=%s%s" % (i, hex(q), mark))
            k32.TerminateProcess(pi.hProcess, 1)
            break
        else:
            if ecode != 0x80000003:
                status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
print("hits", [hex(x) for x in hit])
