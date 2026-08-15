import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ212/cmd_pure.exe").resolve())
cwd = str(Path("build_univ212").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
k32.CreateProcessW(exe, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd,
                   C.byref(si), C.byref(pi))
base = None; de = DEBUG_EVENT(); t0 = time.time()
writes = []
while time.time() - t0 < 6:
    if not k32.WaitForDebugEvent(C.byref(de), 300):
        continue
    st = DBG_CONTINUE
    if de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        # set DR0 write watch on c8d8
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        ctx.Dr0 = base + 0x58d8
        ctx.Dr7 = 0xF0001  # local enable DR0, 4-byte write (len=11b=3 -> need bits)
        # DR7: L0=1, R/W0=01 (write), LEN0=11 (4 bytes) => bits: L0=bit0, RW0=bits16-17=01, LEN0=bits18-19=11
        # value = 1 | (1<<16) | (3<<18) = 1 + 0x10000 + 0xC0000 = 0xD0001
        ctx.Dr7 = 0xD0001
        k32.SetThreadContext(pi.hThread, C.byref(ctx))
        print("watch c8d8 at", hex(base+0x58d8))
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        if ecode == 0x80000004 and base:  # SINGLE_STEP from DR
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva = addr - base
            n = C.c_size_t(); v = C.c_uint32()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x58d8), C.byref(v), 4, C.byref(n))
            print("WRITE? rip=%#x c8d8=%#x rax=%#x rcx=%#x rdx=%#x" % (rva, v.value, ctx.Rax & 0xffffffff, ctx.Rcx & 0xffffffff, ctx.Rdx & 0xffffffff))
            writes.append(rva)
            # re-enable
            ctx.Dr0 = base + 0x58d8
            ctx.Dr7 = 0xD0001
            ctx.EFlags |= 0x10000  # RF to resume
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            if len(writes) >= 15:
                break
        elif ecode in (0xC00000FD, 0xC0000005):
            print("fault", hex(ecode), hex((addr-base) if base else addr)); break
        elif ecode not in (0x80000003, 0x80000004):
            st = DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
k32.TerminateProcess(pi.hProcess, 1)
print("writes", [hex(x) for x in writes])
