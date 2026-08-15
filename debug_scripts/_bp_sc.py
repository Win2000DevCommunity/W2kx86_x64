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

EXE=os.path.abspath(r"build_univ257\cmd_probe_sc.exe")
cmd=f'"{EXE}" /c echo w2ktest'
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True
HW=[0x17A8E, 0x17AA8, 0x14818, 0x13ECC]  # SC cmp, call AC92, AC92, /c store
labels=["sc_cmp","sc_call","ac92","c_store"]
de=df.DEBUG_EVENT(); t0=time.time(); hits=[]
while time.time()-t0<6:
    if not k32.WaitForDebugEvent(C.byref(de),150): continue
    code=de.dwDebugEventCode
    if code==3:
        base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif code==1:
        ec=de.u.Exception.ExceptionRecord.ExceptionCode&0xFFFFFFFF
        if ec==0x80000003 and init:
            init=False
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            for i,a in enumerate(HW): setattr(ctx,f"Dr{i}",base+a)
            ctx.Dr7=0x55; k32.SetThreadContext(pi.hThread,C.byref(ctx))
            print("armed")
        elif ec==0x80000004:
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            which=[labels[i] for i in range(4) if ctx.Dr6&(1<<i)]
            sc=dword(pi.hProcess,base+0x58F64); st=dword(pi.hProcess,base+0x5BE00)
            print(f"HW {which} rip={(ctx.Rip-base):#x} SC={sc} sticky={st} rcx={ctx.Rcx:#x}")
            hits.append(which)
            ctx.Dr6=0; ctx.EFlags|=0x10000; k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif ec==0xC0000005:
            print("AV"); break
    elif code==5:
        print("EXIT", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,0x10002)
print("hits", hits)
print("final SC", dword(pi.hProcess, base+0x58F64), "sticky", dword(pi.hProcess, base+0x5BE00))
k32.TerminateProcess(pi.hProcess,1)
