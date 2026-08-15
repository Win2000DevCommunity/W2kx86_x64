import ctypes as C, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ163/cmd_pure.exe").resolve())
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = '"' + exe + '" /c echo w2ktest'
assert k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, str(Path(exe).parent), C.byref(si), C.byref(pi))
CONTEXT_FULL = 0x10001F
class CTX(C.Structure):
    _fields_ = [("P1",C.c_uint64),("P2",C.c_uint64),("P3",C.c_uint64),("P4",C.c_uint64),("P5",C.c_uint64),("P6",C.c_uint64),("ContextFlags",C.c_uint32),("MxCsr",C.c_uint32),("SegCs",C.c_uint16),("SegDs",C.c_uint16),("SegEs",C.c_uint16),("SegFs",C.c_uint16),("SegGs",C.c_uint16),("SegSs",C.c_uint16),("EFlags",C.c_uint32),("Dr0",C.c_uint64),("Dr1",C.c_uint64),("Dr2",C.c_uint64),("Dr3",C.c_uint64),("Dr6",C.c_uint64),("Dr7",C.c_uint64),("Rax",C.c_uint64),("Rcx",C.c_uint64),("Rdx",C.c_uint64),("Rbx",C.c_uint64),("Rsp",C.c_uint64),("Rbp",C.c_uint64),("Rsi",C.c_uint64),("Rdi",C.c_uint64),("R8",C.c_uint64),("R9",C.c_uint64),("R10",C.c_uint64),("R11",C.c_uint64),("R12",C.c_uint64),("R13",C.c_uint64),("R14",C.c_uint64),("R15",C.c_uint64),("Rip",C.c_uint64)]
TARGET = 0x80011699
bps = {}
def setbp(addr):
    b = df.read_process_mem(pi.hProcess, addr, 1)
    if not b: return False
    bps[addr] = b[0]
    df.write_process_mem(pi.hProcess, addr, b"\xcc")
    return True
print("bp", setbp(TARGET), hex(TARGET))
de = df.DEBUG_EVENT(); stepped=0; tracing=False; last=[]; ctrl=[]; t0=time.time()
while time.time()-t0 < 120:
    if not k32.WaitForDebugEvent(C.byref(de), 1000): continue
    code = de.dwDebugEventCode
    if code == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception; ec = er.ExceptionRecord.ExceptionCode
        if ec == 0x80000003:
            ctx = CTX(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            hit = ctx.Rip-1 if (ctx.Rip-1) in bps else ctx.Rip
            if hit in bps:
                df.write_process_mem(pi.hProcess, hit, bytes([bps[hit]]))
                ctx.Rip = hit
                if hit == TARGET:
                    tracing = True
                    print("HIT", hex(ctx.Rsi), hex(ctx.Rsp), hex(ctx.Rbp))
                    ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE); continue
        if ec == 0x80000004 and tracing:
            ctx = CTX(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            stepped += 1
            op8 = df.read_process_mem(pi.hProcess, ctx.Rip, 8) or b""
            b0 = op8[0] if op8 else 0
            last.append((ctx.Rip, ctx.Rsp, ctx.Rax, ctx.Rsi, ctx.Rdi, ctx.Rbp, op8.hex()))
            if len(last)>20: last.pop(0)
            if b0 in (0xC3,0xC2,0xE8,0xE9,0xEB) or (b0==0xFF):
                ctrl.append((ctx.Rip, ctx.Rsp, ctx.Rax, ctx.Rsi, ctx.Rdi, ctx.Rbp, op8.hex()))
                if len(ctrl)>40: ctrl.pop(0)
            if stepped > 400000:
                print("limit"); break
            ctx.EFlags |= 0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE); continue
        if ec == 0xC0000005:
            ctx = CTX(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("AV", hex(ctx.Rip), "rsi", hex(ctx.Rsi), "rdi", hex(ctx.Rdi), "rbp", hex(ctx.Rbp), "rdx", hex(ctx.Rdx), "steps", stepped)
            print("CTRL:")
            for e in ctrl[-25:]:
                print(" ", hex(e[0]), hex(e[1]), "rax", hex(e[2]), "rsi", hex(e[3]), "rdi", hex(e[4]), "rbp", hex(e[5]), e[6])
            print("LAST:")
            for e in last:
                print(" ", hex(e[0]), hex(e[1]), hex(e[2]), hex(e[3]), hex(e[4]), hex(e[5]), e[6])
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    else:
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
k32.TerminateProcess(pi.hProcess, 1)
print("done", stepped)
