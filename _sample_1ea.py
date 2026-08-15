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
de=df.DEBUG_EVENT(); t0=time.time(); n=0; saw_echo=False
# Use INT3 patch instead of HW BP for reliability
# Actually use SuspendThread sampling after 0.5s intervals looking for rip in 1ea3c
while time.time()-t0<4:
    if not k32.WaitForDebugEvent(C.byref(de),50):
        if base:
            k32.SuspendThread(pi.hThread)
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            rva=(ctx.Rip-base)&0xffffffffffffffff
            st=dword(pi.hProcess,base+0x5BE00); fa=dword(pi.hProcess,base+0x5BAE0)
            if 0x1EA3C <= rva < 0x1EB80 or 0x457F0 <= rva < 0x45890:
                print(f"t={time.time()-t0:.2f} rip={rva:#x} sticky={st} fae0={fa}")
                n+=1
            k32.ResumeThread(pi.hThread)
        continue
    code=de.dwDebugEventCode
    if code==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0; print("base",hex(base))
    elif code==1:
        ec=de.u.Exception.ExceptionRecord.ExceptionCode&0xFFFFFFFF
        if ec==0x80000003 and init: init=False
        elif ec==0xC0000005: print("AV"); break
    elif code==5: print("EXIT"); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,0x10002)
print("samples", n, "final sticky", dword(pi.hProcess,base+0x5BE00), "fae0", dword(pi.hProcess,base+0x5BAE0))
k32.TerminateProcess(pi.hProcess,1)
