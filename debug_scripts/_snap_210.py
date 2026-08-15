import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ210/cmd_pure.exe").resolve())
cwd = str(Path("build_univ210").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
k32.CreateProcessW(exe, C.create_unicode_buffer('"%s" /c echo w2ktest' % exe),
                   None, None, False, 0x4, None, cwd, C.byref(si), C.byref(pi))
k32.ResumeThread(pi.hThread)
time.sleep(1.5)
base = 0x80000000
n = C.c_size_t()
stv = C.c_uint32(); fbc8 = C.c_uint32(); fa = C.c_uint32()
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5be00), C.byref(stv), 4, C.byref(n))
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bbc8), C.byref(fbc8), 4, C.byref(n))
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bae0), C.byref(fa), 4, C.byref(n))
buf = (C.c_ubyte * 64)(); buf2 = (C.c_ubyte * 64)()
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bbe2), buf, 64, C.byref(n))
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x60320), buf2, 64, C.byref(n))
def ws(b):
    u = [b[i] | (b[i+1] << 8) for i in range(0, 48, 2)]
    return "".join(chr(c) if 32 <= c < 127 else ("." if c else "\\0") for c in u)
print("sticky", stv.value, "fbc8", hex(fbc8.value), "fae0", hex(fa.value))
print("fbe2", ws(bytes(buf)))
print("60320", ws(bytes(buf2)))
# PEB cmdline
# read TEB->PEB via ntdll - skip, use NtQuery or just print
th = k32.OpenThread(0x1F03FF, False, pi.dwThreadId)
ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
k32.SuspendThread(th); k32.GetThreadContext(th, C.byref(ctx))
print("RIP", hex(ctx.Rip), "RAX", hex(ctx.Rax))
k32.TerminateProcess(pi.hProcess, 1)