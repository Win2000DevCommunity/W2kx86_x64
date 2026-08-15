import ctypes as C, os
from ctypes import wintypes
from dbg_fault import *
exe = os.path.abspath("build_univ175/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base = None; orig = {}; n474 = 0
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

de = DEBUG_EVENT(); first = 0
while True:
    assert k32.WaitForDebugEvent(C.byref(de), 60000)
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
        for rva in (0x474fc, 0x17c36, 0x1c783):
            ob = rpm(base + rva, 1); orig[rva] = ob; wpm(base + rva, b"\xcc")
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        if ecode == 0x80000003:
            if first == 0:
                first = 1
            elif base and (addr - base) in orig:
                rva = addr - base
                wpm(addr, orig[rva])
                ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                retq = int.from_bytes(rpm(ctx.Rsp, 8) or b"\0" * 8, "little")
                print("HIT", hex(rva), "rax", hex(ctx.Rax), "rbx", hex(ctx.Rbx), "[rsp]", hex(retq), "ret_rva", hex(retq - base) if base <= retq < base + 0x200000 else None)
                ctx.Rip = addr
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                if rva == 0x474fc:
                    n474 += 1
                    if n474 < 5:
                        wpm(base + rva, b"\xcc")
                else:
                    wpm(base + 0x17c36, b"\xcc")
                    wpm(base + 0x1c783, b"\xcc")
                if n474 > 8:
                    k32.TerminateProcess(pi.hProcess, 1); break
        elif ecode == 0xC0000005:
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("AV rbx", hex(ctx.Rbx), "rsi", hex(ctx.Rsi))
            k32.TerminateProcess(pi.hProcess, 1); break
        elif ecode != 0x80000003:
            status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
