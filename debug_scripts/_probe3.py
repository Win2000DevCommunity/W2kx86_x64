import ctypes as C, os
from ctypes import wintypes
from dbg_fault import *
import pefile

p = pefile.PE("build_univ171_ff15/cmd_pure.exe")
for e in p.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.name and b"FormatMessage" in imp.name:
            print("FM", hex(imp.address - p.OPTIONAL_HEADER.ImageBase), e.dll, imp.name)

probes = [0x14878, 0x14909, 0x12b85, 0x12bad, 0x12bce, 0x12c68, 0x12c99, 0x12d20]
exe = os.path.abspath("build_univ171_ff15/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base = None; orig = {}; hit = []
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

def plant():
    for rva in probes:
        addr = base + rva; ob = rpm(addr, 1)
        if len(ob) == 1:
            orig[rva] = ob; wpm(addr, b"\xcc")

de = DEBUG_EVENT(); first = 0
while True:
    assert k32.WaitForDebugEvent(C.byref(de), 60000)
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
        plant()
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress or 0
        if ecode == 0x80000003:
            if first == 0:
                first = 1
            elif base and base <= addr < base + 0x200000 and (addr - base) in orig:
                rva = addr - base; hit.append(rva); wpm(addr, orig[rva])
                ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print("HIT", hex(rva), "rax", hex(ctx.Rax), "rcx", hex(ctx.Rcx), "rdx", hex(ctx.Rdx), "r8", hex(ctx.R8), "r9", hex(ctx.R9), "rbp", hex(ctx.Rbp))
                ctx.Rip = addr; k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif ecode == 0xC0000005:
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            fault = er.ExceptionInformation[1] & 0xFFFFFFFFFFFFFFFF
            print("CRASH", hex(fault), "hits", [hex(x) for x in hit])
            print(" rax", hex(ctx.Rax), "rcx", hex(ctx.Rcx), "rdx", hex(ctx.Rdx), "r8", hex(ctx.R8), "r9", hex(ctx.R9))
            k32.TerminateProcess(pi.hProcess, 1); break
        else:
            if ecode != 0x80000003:
                status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
