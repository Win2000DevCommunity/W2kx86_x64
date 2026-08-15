import ctypes as C, os, time
from ctypes import wintypes
from dbg_fault import *

exe = os.path.abspath("build_univ171_both/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base = None
de = DEBUG_EVENT(); first = 0; t0 = time.time()
while time.time() - t0 < 20:
    if not k32.WaitForDebugEvent(C.byref(de), 1000):
        continue
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
        print("base", hex(base))
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff)); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        firstc = de.u.Exception.dwFirstChance
        if ecode == 0x80000003 and first == 0:
            first = 1
        else:
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva = (ctx.Rip - base) if base and base <= ctx.Rip < base + 0x200000 else None
            print("EXC", hex(ecode), "first", firstc, "rip", hex(ctx.Rip), "rva", hex(rva) if rva is not None else None, "rax", hex(ctx.Rax), "rsp", hex(ctx.Rsp))
            if ecode == 0xC0000005:
                op = er.ExceptionInformation[0]; fault = er.ExceptionInformation[1] & 0xffffffffffffffff
                print(" AV", {0:"read",1:"write",8:"execute"}.get(op,op), hex(fault))
                k32.TerminateProcess(pi.hProcess, 1); break
            if ecode not in (0x80000003, 0x80000004):
                status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
else:
    ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
    k32.GetThreadContext(pi.hThread, C.byref(ctx))
    print("HUNG rip", hex(ctx.Rip), "rva", hex(ctx.Rip-base) if base else None, "rax", hex(ctx.Rax), "rsp", hex(ctx.Rsp))
    # stack scan
    ReadProcessMemory = k32.ReadProcessMemory
    ReadProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    buf = (C.c_char * 0x100)(); n = C.c_size_t(0)
    ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 0x100, C.byref(n))
    for i in range(0, n.value, 8):
        q = int.from_bytes(buf[i:i+8], "little")
        if base and base <= q < base + 0x200000:
            print("  [rsp+%x]=rva %s" % (i, hex(q-base)))
    k32.TerminateProcess(pi.hProcess, 1)
