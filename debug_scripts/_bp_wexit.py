import ctypes as C
from ctypes import wintypes
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

def dword(h, addr):
    b = rpm(h, addr, 4)
    return struct.unpack_from("<I", b)[0] if b else None

EXE = os.path.abspath(r"build_univ257\cmd_probe_univ.exe")
cmd = f'"{EXE}" /c echo w2ktest'
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
k32.CreateProcessW(None, C.create_unicode_buffer(cmd), None, None, False,
                    df.DEBUG_PROCESS, None, os.path.dirname(EXE),
                    C.byref(si), C.byref(pi))
base = 0; init = True
# DR0=cave entry 48c58, DR1=TerminateProcess jmp 48c7e, DR2=WFS call 48ca1, DR3=old waiter 45832
HW = [0x48c58, 0x48c68, 0x48c80, 0x45832]
labels = ["cave", "do_exit", "do_wait", "jmp_cave"]
de = df.DEBUG_EVENT()
t0 = time.time()
hits = []
while time.time() - t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(de), 200):
        continue
    code = de.dwDebugEventCode
    if code == 3:
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        print("base", hex(base))
    elif code == 1:
        er = de.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        if ec == 0x80000003 and init:
            init = False
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            for i,a in enumerate(HW):
                setattr(ctx, f"Dr{i}", base+a)
            ctx.Dr7 = 0x55
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            print("armed", [hex(x) for x in HW])
        elif ec == 0x80000004:
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            which = [labels[i] for i in range(4) if ctx.Dr6 & (1<<i)]
            sticky = dword(pi.hProcess, base+0x5BE00)
            fae0 = dword(pi.hProcess, base+0x5BAE0)
            print(f"HW {which} rip={(ctx.Rip-base):#x} sticky={sticky} fae0={fae0}")
            hits.append(which)
            ctx.Dr6 = 0; ctx.EFlags |= 0x10000
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            if "do_exit" in which:
                print("EXIT PATH HIT"); break
        elif ec == 0xC0000005:
            print("AV", hex((er.ExceptionAddress or 0)-base)); break
    elif code == 5:
        print("EXIT code", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x10002)
print("hits", hits)
print("sticky final", dword(pi.hProcess, base+0x5BE00) if base else None)
k32.TerminateProcess(pi.hProcess, 1)
