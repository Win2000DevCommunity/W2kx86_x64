import ctypes as C
import struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
CONTEXT_ALL = df.CONTEXT_FULL | df.CONTEXT_AMD64 | 0x10

def rpm(h, addr, n):
    buf = (C.c_ubyte * n)()
    br = C.c_size_t()
    if not k32.ReadProcessMemory(h, C.c_void_p(addr), buf, n, C.byref(br)):
        return None
    return bytes(buf)

EXE = os.path.abspath(r"build_univ257\cmd_probe_univ.exe")
cmd = f'"{EXE}" /c echo w2ktest'
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
k32.CreateProcessW(None, C.create_unicode_buffer(cmd), None, None, False,
                    df.DEBUG_PROCESS, None, os.path.dirname(EXE),
                    C.byref(si), C.byref(pi))
base = 0; init = True
de = df.DEBUG_EVENT()
t0 = time.time()
last_rip = None
samples = []
while time.time() - t0 < 6:
    if not k32.WaitForDebugEvent(C.byref(de), 100):
        # sample rip
        ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
        if k32.GetThreadContext(pi.hThread, C.byref(ctx)):
            rva = (ctx.Rip - base) & 0xffffffffffffffff
            if rva != last_rip:
                samples.append((time.time()-t0, rva, ctx.Rsp))
                last_rip = rva
                print(f"t={time.time()-t0:.2f} rip={rva:#x}")
        continue
    code = de.dwDebugEventCode
    if code == 3:
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        print("base", hex(base))
    elif code == 1:
        ec = de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
        if ec == 0x80000003 and init:
            init = False
        elif ec == 0xC0000005:
            ea = de.u.Exception.ExceptionRecord.ExceptionAddress or 0
            print("AV", hex(ea-base)); break
    elif code == 5:
        print("EXIT", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x10002)

# final stack
ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
k32.GetThreadContext(pi.hThread, C.byref(ctx))
print("FINAL rip", hex(ctx.Rip-base), "rsp", hex(ctx.Rsp))
stk = rpm(pi.hProcess, ctx.Rsp, 0x100)
if stk:
    for off in range(0, 0x100, 8):
        q = struct.unpack_from("<Q", stk, off)[0]
        if base <= q < base + 0x100000:
            print(f"  rsp+{off:#x} = {(q-base):#x}")
# sticky/fae0
for name,off in [("sticky",0x5BE00),("fae0",0x5BAE0),("sc",0x58F64),("evt",0x5BB40)]:
    b = rpm(pi.hProcess, base+off, 4)
    print(name, hex(struct.unpack_from("<I", b)[0]) if b else None)
k32.TerminateProcess(pi.hProcess, 1)
