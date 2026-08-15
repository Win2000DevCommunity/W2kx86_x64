# After echo hang: is fbe2 empty? fbc8? What about execute flag?
import ctypes as C, struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui(); k32=df.k32
CONTEXT_ALL=df.CONTEXT_FULL|df.CONTEXT_AMD64|0x10

def rpm(h,a,n):
    b=(C.c_ubyte*n)(); br=C.c_size_t()
    if not k32.ReadProcessMemory(h,C.c_void_p(a),b,n,C.byref(br)): return None
    return bytes(b)

EXE=os.path.abspath(r"build_univ257\cmd_probe_bp.exe")
cmd=f'"{EXE}" /c echo w2ktest'
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True
de=df.DEBUG_EVENT(); t0=time.time()
while time.time()-t0<2.5:
    if not k32.WaitForDebugEvent(C.byref(de),100): continue
    if de.dwDebugEventCode==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif de.dwDebugEventCode==1:
        ec=de.u.Exception.ExceptionRecord.ExceptionCode&0xFFFFFFFF
        if ec==0x80000003 and init: init=False
    elif de.dwDebugEventCode==5: break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,0x10002)
# dump state after echo likely done
k32.SuspendThread(pi.hThread)
for name,off,n in [("sticky",0x5BE00,4),("fae0",0x5BAE0,4),("fbc8",0x5BBC8,4),("fbe2",0x5BBE2,32),("c8d8ptr",0x58D8,8),("sc",0x58F64,4)]:
    b=rpm(pi.hProcess, base+off, n)
    if b is None: print(name, None); continue
    if n<=8: print(name, b.hex(), struct.unpack("<I", b[:4])[0] if n>=4 else "")
    else: print(name, b[:32])
k32.TerminateProcess(pi.hProcess,1)
