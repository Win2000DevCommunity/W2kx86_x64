import ctypes as C, os, time
from ctypes import wintypes
from dbg_fault import *

exe = os.path.abspath("build_univ171_both2/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base = None
de = DEBUG_EVENT(); first = 0; t0 = time.time()
last_rips = []
while time.time() - t0 < 12:
    wait = 200
    if not k32.WaitForDebugEvent(C.byref(de), wait):
        # sample
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        if k32.GetThreadContext(pi.hThread, C.byref(ctx)) and base:
            if base <= ctx.Rip < base + 0x200000:
                last_rips.append(ctx.Rip - base)
                if len(last_rips) > 30: last_rips.pop(0)
        continue
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff)); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        if ecode == 0x80000003 and first == 0:
            first = 1
        elif ecode == 0xC0000005:
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            fault = er.ExceptionInformation[1] & 0xffffffffffffffff
            op = er.ExceptionInformation[0]
            print("AV", {0:"read",1:"write",8:"execute"}.get(op,op), hex(fault))
            print(" rip", hex(ctx.Rip), "rva", hex(ctx.Rip-base) if base and base<=ctx.Rip<base+0x200000 else None)
            print(" rax", hex(ctx.Rax), "rcx", hex(ctx.Rcx), "rdx", hex(ctx.Rdx), "rbp", hex(ctx.Rbp), "rsp", hex(ctx.Rsp))
            print(" rsi", hex(ctx.Rsi), "rdi", hex(ctx.Rdi), "r8", hex(ctx.R8), "r9", hex(ctx.R9))
            ReadProcessMemory = k32.ReadProcessMemory
            ReadProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
            buf = (C.c_char * 0x80)(); n = C.c_size_t(0)
            ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 0x80, C.byref(n))
            for i in range(0, n.value, 8):
                q = int.from_bytes(buf[i:i+8], "little")
                mark = ""
                if base and base <= q < base + 0x200000: mark = " rva="+hex(q-base)
                print("  [%x]=%s%s" % (i, hex(q), mark))
            print("recent rips", [hex(x) for x in last_rips[-15:]])
            k32.TerminateProcess(pi.hProcess, 1); break
        elif ecode not in (0x80000003, 0x80000004):
            status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
else:
    print("no AV; last rips", [hex(x) for x in last_rips[-20:]])
    k32.TerminateProcess(pi.hProcess, 1)
