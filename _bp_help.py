import ctypes as C, sys, time
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
# Break on helper entry 48550, helper store ret areas, and after call 448d0
bps = {
    0x48550: "helper_entry",
    0x448d0: "after_seed_call",
    0x48779: "gate_entry",
    0x44947: "movzx",
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
                n = C.c_size_t(); stv = C.c_uint32()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5be00), C.byref(stv), 4, C.byref(n))
                buf = (C.c_ubyte * 32)()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bbe2), buf, 32, C.byref(n))
                u = [buf[i] | (buf[i+1] << 8) for i in range(0, 24, 2)]
                s = "".join(chr(c) if 32 <= c < 127 else ("." if c else "\\0") for c in u)
                print("%d %s sticky=%d rip=%#x [%s]" % (hits, bps[rva], stv.value, addr, s))
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(C.c_ubyte(orig[rva])), 1, C.byref(n))
                ctx.Rip = addr; ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = rva
                if hits >= 30:
                    break
                continue
        if ecode == 0x80000004 and rearm is not None:
            n = C.c_size_t()
            for rva in bps:
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = None
        elif ecode in (0xC00000FD, 0xC0000005):
            print("fault", hex(ecode), hex(addr)); break
        elif ecode not in (0x80000003, 0x80000004):
            st = DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
else:
    # sample RIP on timeout
    if base:
        th = k32.OpenThread(0x1F03FF, False, pi.dwThreadId)
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        k32.SuspendThread(th); k32.GetThreadContext(th, C.byref(ctx))
        print("HUNG RIP", hex(ctx.Rip), "RVA", hex(ctx.Rip - base) if base <= ctx.Rip < base + 0x100000 else None)
k32.TerminateProcess(pi.hProcess, 1)
print("hits", hits)