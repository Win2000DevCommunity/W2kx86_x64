import ctypes as C, struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32=df.k32
CONTEXT_ALL=df.CONTEXT_FULL|df.CONTEXT_AMD64|0x10

EXE=os.path.abspath(r"build_univ258\cmd_pure.exe")
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(f'"{EXE}"'),None,None,False,
                    df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True
de=df.DEBUG_EVENT(); t0=time.time()
samples=[]
while time.time()-t0 < 3.5:
    if not k32.WaitForDebugEvent(C.byref(de), 30):
        if base:
            k32.SuspendThread(pi.hThread)
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            if k32.GetThreadContext(pi.hThread, C.byref(ctx)):
                rva=(ctx.Rip-base)&0xffffffffffffffff
                samples.append((time.time()-t0, rva, ctx.Rsp))
            k32.ResumeThread(pi.hThread)
        continue
    code=de.dwDebugEventCode
    if code==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif code==1:
        ec=de.u.Exception.ExceptionRecord.ExceptionCode&0xFFFFFFFF
        ea=de.u.Exception.ExceptionRecord.ExceptionAddress or 0
        if ec==0x80000003 and init: init=False
        elif ec in (0xC00000FD, 0xC0000005):
            print("EX", hex(ec), "at", hex((ea-base)&0xffffffffffffffff))
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("final rsp", hex(ctx.Rsp), "rip", hex((ctx.Rip-base)&0xffffffffffffffff))
            break
    elif code==5:
        print("EXIT"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x10002)

# print rsp trend
print("n samples", len(samples))
for t,r,s in samples[::max(1,len(samples)//15)]:
    print(f"t={t:.2f} rip={r:#x} rsp={s:#x}")
if samples:
    print("rsp first", hex(samples[0][2]), "last", hex(samples[-1][2]), "delta", samples[0][2]-samples[-1][2])
k32.TerminateProcess(pi.hProcess,1)
