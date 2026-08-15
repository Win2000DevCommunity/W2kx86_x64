import ctypes as C, sys, time
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ212/cmd_pure.exe").resolve())
cwd = str(Path("build_univ212").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
k32.CreateProcessW(exe, C.create_unicode_buffer('"%s" /c echo w2ktest' % exe),
                   None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd,
                   C.byref(si), C.byref(pi))
base = None; de = DEBUG_EVENT(); t0 = time.time()
bps = {
    0x44947: "movzx",
    0x448e3: "weof_ret",
    0x487aa: "gate_weof",
    0x448cb: "seed_call",
    0x1ea90: "after_parse",
}
orig = {}; rearm = None; hits = 0; chars = []
while time.time() - t0 < 6:
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
                n = C.c_size_t(); stv = C.c_uint32(); fa = C.c_uint32()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5be00), C.byref(stv), 4, C.byref(n))
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bae0), C.byref(fa), 4, C.byref(n))
                extra = ""
                if rva == 0x44947:
                    w = C.c_uint16()
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rcx), C.byref(w), 2, C.byref(n))
                    ch = w.value
                    chars.append(ch)
                    extra = " ch=%s" % (chr(ch) if 32 <= ch < 127 else hex(ch))
                if hits <= 40:
                    print("%d %s sticky=%d fae0=%#x eax=%#x%s" % (
                        hits, bps[rva], stv.value, fa.value, ctx.Rax & 0xffffffff, extra))
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(C.c_ubyte(orig[rva])), 1, C.byref(n))
                ctx.Rip = addr; ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = rva
                if hits >= 50:
                    break
                continue
        if ecode == 0x80000004 and rearm is not None:
            n = C.c_size_t()
            for rva in bps:
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = None
        elif ecode in (0xC00000FD, 0xC0000005):
            print("fault", hex(ecode)); break
        elif ecode not in (0x80000003, 0x80000004):
            st = DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
k32.TerminateProcess(pi.hProcess, 1)
s = "".join(chr(c) if 32 <= c < 127 else ("[LF]" if c == 10 else ("[CR]" if c == 13 else "[%#x]" % c)) for c in chars)
print("stream:", s)
print("hits", hits)