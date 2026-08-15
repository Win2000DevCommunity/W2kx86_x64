import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ207/cmd_pure.exe").resolve())
cwd = str(Path("build_univ207").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
k32.CreateProcessW(exe, C.create_unicode_buffer('"%s" /c echo w2ktest' % exe),
                   None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd,
                   C.byref(si), C.byref(pi))
base = None; de = DEBUG_EVENT(); t0 = time.time()
# BP on cmp eax,0x4000 sites and on IAT WriteConsoleW/WriteFile if we can find
bps = {
    0x1d2ad: "cmp4000_a",
    0x1e145: "cmp4000_b",
    0x1e999: "cmp4000_d",
}
orig = {}; rearm = None; hits = 0
while time.time() - t0 < 5:
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
                eax = ctx.Rax & 0xffffffff
                # dump c8d8 string
                n = C.c_size_t(); c8 = C.c_uint32()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x588d8), C.byref(c8), 4, C.byref(n))
                buf = (C.c_ubyte * 64)()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(c8.value if c8.value else base+0x60320), buf, 64, C.byref(n))
                u = [buf[i] | (buf[i+1] << 8) for i in range(0, 40, 2)]
                s = "".join(chr(c) if 32 <= c < 127 else "." for c in u)
                print(hits, bps[rva], "eax", hex(eax), "c8", hex(c8.value), "[", s, "]")
                n = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(C.c_ubyte(orig[rva])), 1, C.byref(n))
                ctx.Rip = addr; ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = rva
                if hits >= 15:
                    break
                continue
        if ecode == 0x80000004 and rearm is not None:
            n = C.c_size_t()
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rearm), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
            # rearm all
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
print("hits", hits)