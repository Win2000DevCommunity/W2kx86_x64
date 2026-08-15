import ctypes as C
import struct
import time
import sys
import os

sys.path.insert(0, ".")
import dbg_fault as df

df.suppress_fault_ui()
k32 = df.k32
CONTEXT_ALL = df.CONTEXT_FULL | df.CONTEXT_AMD64 | 0x10

EXE = os.path.abspath(r"build_univ258\cmd_pure.exe")
si = df.STARTUPINFO()
si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = '"' + EXE + '"'
ok = k32.CreateProcessW(
    None, C.create_unicode_buffer(cmd), None, None, False,
    df.DEBUG_PROCESS, None, os.path.dirname(EXE),
    C.byref(si), C.byref(pi))
print("create", ok, "err", C.get_last_error())
base = 0
init = True
de = df.DEBUG_EVENT()
t0 = time.time()
while time.time() - t0 < 5:
    if not k32.WaitForDebugEvent(C.byref(de), 100):
        continue
    code = de.dwDebugEventCode
    if code == 3:
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        print("base", hex(base))
    elif code == 1:
        er = de.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        ea = er.ExceptionAddress or 0
        if ec == 0x80000003 and init:
            init = False
        elif ec in (0xC00000FD, 0xC0000005):
            rva = (ea - base) & 0xFFFFFFFFFFFFFFFF
            print("EX", hex(ec), "rva", hex(rva),
                  "fc", de.u.Exception.dwFirstChance)
            ctx = df.CONTEXT()
            ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("rip", hex((ctx.Rip - base) & 0xFFFFFFFFFFFFFFFF),
                  "rsp", hex(ctx.Rsp), "rbp", hex(ctx.Rbp))
            print("rax", hex(ctx.Rax), "rcx", hex(ctx.Rcx),
                  "rdx", hex(ctx.Rdx), "rbx", hex(ctx.Rbx))
            print("rsi", hex(ctx.Rsi), "rdi", hex(ctx.Rdi),
                  "r12", hex(ctx.R12), "r13", hex(ctx.R13))
            buf = (C.c_ubyte * 0x120)()
            n = C.c_size_t()
            k32.ReadProcessMemory(
                pi.hProcess, C.c_void_p(ctx.Rsp), buf, 0x120, C.byref(n))
            stk = bytes(buf)
            for off in range(0, 0x120, 8):
                q = struct.unpack_from("<Q", stk, off)[0]
                if base <= q < base + 0x100000:
                    print(f"  rsp+{off:#x}={(q - base):#x}")
            break
    elif code == 5:
        print("EXIT", de.u.ExitProcess.dwExitCode)
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x10002)
k32.TerminateProcess(pi.hProcess, 1)
