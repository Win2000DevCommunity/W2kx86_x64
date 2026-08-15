import ctypes as C, sys, time
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
rva_bp = 0x44947  # movzx rax, word [rcx]
orig = None; rearm = False; chars = []; hits = 0
while time.time() - t0 < 5:
    if not k32.WaitForDebugEvent(C.byref(de), 400):
        continue
    st = DBG_CONTINUE
    if de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        o = C.c_ubyte(); n = C.c_size_t()
        k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + rva_bp), C.byref(o), 1, C.byref(n))
        orig = o.value
        k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva_bp), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        if ecode == 0x80000003 and base and addr == base + rva_bp:
            hits += 1
            w = C.c_uint16(); n = C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rcx), C.byref(w), 2, C.byref(n))
            ch = w.value
            chars.append(ch)
            fa = C.c_uint32()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bae0), C.byref(fa), 4, C.byref(n))
            if hits <= 25:
                s = chr(ch) if 32 <= ch < 127 else ("CR" if ch == 13 else ("LF" if ch == 10 else hex(ch)))
                print("hit", hits, "ch", s, "fae0", hex(fa.value), "rcx", hex(ctx.Rcx))
            n = C.c_size_t()
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(C.c_ubyte(orig)), 1, C.byref(n))
            ctx.Rip = addr; ctx.EFlags |= 0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = True
            if hits >= 30:
                break
        elif ecode == 0x80000004 and rearm:
            n = C.c_size_t()
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva_bp), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx)); rearm = False
        elif ecode in (0xC00000FD, 0xC0000005):
            print("fault", hex(ecode)); break
        elif ecode not in (0x80000003, 0x80000004):
            st = DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
k32.TerminateProcess(pi.hProcess, 1)
out = []
for c in chars:
    if 32 <= c < 127: out.append(chr(c))
    elif c == 13: out.append("[CR]")
    elif c == 10: out.append("[LF]")
    else: out.append("[%#x]" % c)
print("stream:", "".join(out))
print("hits", hits)