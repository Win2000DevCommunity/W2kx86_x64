import ctypes as C, os
from ctypes import wintypes
from dbg_fault import *

# After second PutMsg in InitCmd fallthrough - 12c44 is join. Break there and count steps to AV/loop
probes = {0x12c44: b"", 0x13890: b""}
exe = os.path.abspath("build_univ171_both2/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base = None; orig = {}
ReadProcessMemory = k32.ReadProcessMemory; WriteProcessMemory = k32.WriteProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
WriteProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]

def rpm(a, n):
    b = (C.c_char * n)(); m = C.c_size_t(0)
    if ReadProcessMemory(pi.hProcess, C.c_void_p(a), b, n, C.byref(m)):
        return bytes(b[:m.value])
    return b""

def wpm(a, d):
    buf = C.create_string_buffer(d); m = C.c_size_t(0)
    return WriteProcessMemory(pi.hProcess, C.c_void_p(a), buf, len(d), C.byref(m))

de = DEBUG_EVENT(); first = 0; hits = []
steps = 0; tracing = False
while True:
    assert k32.WaitForDebugEvent(C.byref(de), 30000)
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
        for rva in probes:
            addr = base + rva; ob = rpm(addr, 1)
            if len(ob) == 1:
                orig[rva] = ob; wpm(addr, b"\xcc")
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff)); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        if ecode == 0x80000003:
            if first == 0:
                first = 1
            elif base and (addr - base) in orig:
                rva = addr - base
                hits.append(rva)
                wpm(addr, orig[rva])
                ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print("HIT", hex(rva), "rax", hex(ctx.Rax), "rcx", hex(ctx.Rcx), "rsp", hex(ctx.Rsp))
                ctx.Rip = addr
                if rva == 0x12c44:
                    tracing = True
                    ctx.EFlags |= 0x100
                    print("start single-step")
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            else:
                status = DBG_EXCEPTION_NOT_HANDLED
        elif ecode == 0x80000004 and tracing:
            steps += 1
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if steps <= 5 or steps % 5000 == 0:
                rva = ctx.Rip - base if base and base <= ctx.Rip < base + 0x200000 else None
                print("step", steps, "rva", hex(rva) if rva is not None else hex(ctx.Rip), "rax", hex(ctx.Rax), "rsp", hex(ctx.Rsp))
            if steps >= 50000:
                print("abort steps")
                k32.TerminateProcess(pi.hProcess, 1); break
            ctx.EFlags |= 0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif ecode == 0xC0000005:
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            fault = er.ExceptionInformation[1] & 0xffffffffffffffff
            print("AV", hex(fault), "rip", hex(ctx.Rip), "steps", steps)
            print(" rax", hex(ctx.Rax), "rcx", hex(ctx.Rcx), "rbp", hex(ctx.Rbp))
            k32.TerminateProcess(pi.hProcess, 1); break
        elif ecode not in (0x80000003,):
            status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
