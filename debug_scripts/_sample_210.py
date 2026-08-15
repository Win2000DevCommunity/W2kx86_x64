import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ210/cmd_pure.exe").resolve())
cwd = str(Path("build_univ210").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
cmd = '"%s" /c echo w2ktest' % exe
k32.CreateProcessW(exe, C.create_unicode_buffer(cmd), None, None, False,
                   0x4, None, cwd, C.byref(si), C.byref(pi))
k32.ResumeThread(pi.hThread)
time.sleep(3)
th = k32.OpenThread(0x1F03FF, False, pi.dwThreadId)
ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
k32.SuspendThread(th)
k32.GetThreadContext(th, C.byref(ctx))
print("RIP", hex(ctx.Rip))
if 0x80000000 <= ctx.Rip < 0x80200000:
    print("RVA", hex(ctx.Rip - 0x80000000))
print("RAX", hex(ctx.Rax), "RCX", hex(ctx.Rcx), "RSP", hex(ctx.Rsp))
buf = (C.c_ubyte * 0x100)(); n = C.c_size_t()
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 0x100, C.byref(n))
raw = bytes(buf)
for i in range(0, 0x100, 8):
    v = struct.unpack_from("<Q", raw, i)[0]
    if 0x80000000 <= v < 0x80200000:
        print("  rsp+%#x = %#x rva=%#x" % (i, v, v - 0x80000000))
    elif 0x7FF000000000 <= v:
        print("  rsp+%#x = %#x (sys)" % (i, v))
k32.TerminateProcess(pi.hProcess, 1)