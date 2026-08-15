import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ166/cmd_pure.exe").resolve())
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = '"' + exe + '" /c echo w2ktest'
assert k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, str(Path(exe).parent), C.byref(si), C.byref(pi))
CONTEXT_FULL = 0x10001F
class CTX(C.Structure):
    _fields_ = [("P1",C.c_uint64),("P2",C.c_uint64),("P3",C.c_uint64),("P4",C.c_uint64),("P5",C.c_uint64),("P6",C.c_uint64),("ContextFlags",C.c_uint32),("MxCsr",C.c_uint32),("SegCs",C.c_uint16),("SegDs",C.c_uint16),("SegEs",C.c_uint16),("SegFs",C.c_uint16),("SegGs",C.c_uint16),("SegSs",C.c_uint16),("EFlags",C.c_uint32),("Dr0",C.c_uint64),("Dr1",C.c_uint64),("Dr2",C.c_uint64),("Dr3",C.c_uint64),("Dr6",C.c_uint64),("Dr7",C.c_uint64),("Rax",C.c_uint64),("Rcx",C.c_uint64),("Rdx",C.c_uint64),("Rbx",C.c_uint64),("Rsp",C.c_uint64),("Rbp",C.c_uint64),("Rsi",C.c_uint64),("Rdi",C.c_uint64),("R8",C.c_uint64),("R9",C.c_uint64),("R10",C.c_uint64),("R11",C.c_uint64),("R12",C.c_uint64),("R13",C.c_uint64),("R14",C.c_uint64),("R15",C.c_uint64),("Rip",C.c_uint64)]
TARGETS = {
    0x80012a5d: "join",
    0x80012a84: "call2951c",
    0x80012ac9: "GetStdHandle",
    0x80012afa: "GetConsoleMode",
    0x80012b4d: "skip",
}
bps = {}
def setbp(addr):
    b = df.read_process_mem(pi.hProcess, addr, 1)
    if not b: return False
    bps[addr] = b[0]
    return df.patch_byte(pi.hProcess, addr, 0xCC)
for a in TARGETS: print(hex(a), setbp(a))
de = df.DEBUG_EVENT(); t0=time.time(); hits=[]
while time.time()-t0 < 40:
    if not k32.WaitForDebugEvent(C.byref(de), 1000): continue
    if de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception; ec = er.ExceptionRecord.ExceptionCode
        if ec == 0x80000003:
            ctx = CTX(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            hit = ctx.Rip-1 if (ctx.Rip-1) in bps else (ctx.Rip if ctx.Rip in bps else None)
            if hit is not None:
                df.patch_byte(pi.hProcess, hit, bps[hit])
                ctx.Rip = hit
                name = TARGETS.get(hit, "?")
                print(f"HIT {name} rax={ctx.Rax:x} rcx={ctx.Rcx:x} rdx={ctx.Rdx:x} rbp={ctx.Rbp:x} rsp={ctx.Rsp:x}")
                hits.append(name)
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE); continue
        if ec == 0xC0000005:
            ctx = CTX(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print(f"AV rip={ctx.Rip:x} rax={ctx.Rax:x} rcx={ctx.Rcx:x} rbp={ctx.Rbp:x} rsp={ctx.Rsp:x}")
            raw=df.read_process_mem(pi.hProcess, ctx.Rsp-16, 32) or b""
            print("near rsp", raw.hex())
            print("hits", hits)
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        break
    else:
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
k32.TerminateProcess(pi.hProcess, 1)
