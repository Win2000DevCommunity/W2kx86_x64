import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ210/cmd_pure.exe").resolve())
cwd = str(Path("build_univ210").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
k32.CreateProcessW(exe, C.create_unicode_buffer('"%s" /c echo w2ktest' % exe),
                   None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd,
                   C.byref(si), C.byref(pi))
base = None; de = DEBUG_EVENT(); t0 = time.time()
# Break AFTER store_fae0 completes - at 1eaa0 (jne after store)
# and at entry 14974, and at 1eabd (continue after store)
bps = {
    0x14974: "parse_cmd",
    0x1ea86: "call_parse",
    0x1ea90: "after_parse",  # cmp eax,-1
    0x1eabd: "after_store_ok",
    0x1eaa6: "eof_path",
    0x1498d: "parse_so_site",
}
orig = {}; rearm = None; hits = 0
while time.time() - t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(de), 400):
        continue
    st = DBG_CONTINUE
    if de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        for rva in bps:
            o = C.c_ubyte(); n = C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(o), 1, C.byref(n))
            orig[rva] = o.value
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        if ecode == 0x80000003 and base:
            rva = addr - base
            if rva in bps:
                hits += 1
                fa = C.c_uint32(); n = C.c_size_t()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bae0), C.byref(fa), 4, C.byref(n))
                stv = C.c_uint32()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5be00), C.byref(stv), 4, C.byref(n))
                print("%d %s eax=%#x rcx=%#x fae0=%#x sticky=%d rsp=%#x" % (
                    hits, bps[rva], ctx.Rax & 0xffffffff, ctx.Rcx,
                    fa.value, stv.value, ctx.Rsp))
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(C.c_ubyte(orig[rva])), 1, C.byref(n))
                ctx.Rip = addr; ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = rva
                if hits >= 40:
                    break
                continue
        if ecode == 0x80000004 and rearm is not None:
            n = C.c_size_t()
            for rva in bps:
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = None
        elif ecode == 0xC00000FD:
            print("SO"); break
        elif ecode == 0xC0000005:
            print("AV", hex(addr)); break
        elif ecode not in (0x80000003, 0x80000004):
            st = DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
k32.TerminateProcess(pi.hProcess, 1)
print("hits", hits)