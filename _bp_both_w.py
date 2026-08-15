import ctypes as C, struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32=df.k32
CONTEXT_ALL=df.CONTEXT_FULL|df.CONTEXT_AMD64|0x10

def dword(h,a):
    b=(C.c_ubyte*4)(); n=C.c_size_t()
    if not k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(n)): return None
    return struct.unpack_from("<I", bytes(b))[0]

EXE=os.path.abspath(r"build_univ257\cmd_probe_bp.exe")
cmd=f'"{EXE}" /c echo w2ktest'
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True
# both waiter sites + AC92
HW=[0x361BF, 0x4581E, 0x14818, 0x1EA9D]
labels=["w361","w458","ac92","fae0wr"]
de=df.DEBUG_EVENT(); t0=time.time(); n=0
while time.time()-t0<5 and n<30:
    if not k32.WaitForDebugEvent(C.byref(de),100): continue
    code=de.dwDebugEventCode
    if code==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif code==1:
        ec=de.u.Exception.ExceptionRecord.ExceptionCode&0xFFFFFFFF
        if ec==0x80000003 and init:
            init=False
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            for i,a in enumerate(HW): setattr(ctx,f"Dr{i}",base+a)
            ctx.Dr7=0x55; k32.SetThreadContext(pi.hThread,C.byref(ctx))
            print("armed", [hex(x) for x in HW])
        elif ec==0x80000004:
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            which=[labels[i] for i in range(4) if ctx.Dr6&(1<<i)]
            st=dword(pi.hProcess,base+0x5BE00); fa=dword(pi.hProcess,base+0x5BAE0)
            print(f"#{n} {which} sticky={st} fae0={fa:#x if fa is not None else fa} rip={(ctx.Rip-base):#x}")
            n+=1
            ctx.Dr6=0; ctx.EFlags|=0x10000; k32.SetThreadContext(pi.hThread,C.byref(ctx))
            if "ac92" in which:
                print("AC92 rcx", hex(ctx.Rcx)); break
    elif code==5: print("EXIT", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,0x10002)
print("total", n, "final sticky", dword(pi.hProcess,base+0x5BE00), "fae0", dword(pi.hProcess,base+0x5BAE0))
k32.TerminateProcess(pi.hProcess,1)
