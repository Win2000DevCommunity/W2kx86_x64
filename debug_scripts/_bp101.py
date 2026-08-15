"""Hardware watchpoint on c8d8 and fbc8 writes via single-step is too slow.
Instead BP at known writers and also dump who filled c8d8 before ADAD."""
import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ101/cmd_pure.exe").resolve())
# From rva map
m = {}
for ln in Path("build_univ101/rva.txt").read_text().splitlines():
    a=ln.split()
    if len(a)>=2:
        try: m[int(a[0],16)]=int(a[1],16)
        except: pass
ADAD = 0x80000000 + m[0xADAD]
EFD6 = 0x80000000 + m[0xEFD6]
# also entry
ENTRY = 0x80059EE0
C8D8 = 0x8006A8D8
FBC8 = 0x8006DBC8

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
bps={}; ev=df.DEBUG_EVENT(); hProcess=None; t0=time.time(); done=False

def set_bp(proc, addr):
    b=df.read_process_mem(proc,addr,1)
    if not b: return
    bps[addr]=b[0]
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc,C.c_void_p(addr),b"\xCC",1,C.byref(wr))
def clear_bp(proc, addr):
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc,C.c_void_p(addr),bytes([bps[addr]]),1,C.byref(wr))

def snap(proc, label, ctx):
    c8=struct.unpack("<Q", df.read_process_mem(proc,C8D8,8) or b"\0"*8)[0]
    fbc8=struct.unpack("<I", df.read_process_mem(proc,FBC8,4) or b"\0"*4)[0]
    def u(a):
        if not a: return ''
        b=df.read_process_mem(proc,a,80) or b''
        try: return b.decode('utf-16-le','replace').split('\x00')[0][:70]
        except: return '?'
    ret=struct.unpack("<Q", df.read_process_mem(proc,ctx.Rsp,8) or b"\0"*8)[0]
    print(f"[{label}] RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} ret={ret:#x}")
    print(f"  c8d8={c8:#x} ({u(c8)!r}) fbc8={fbc8:#x} ({u(fbc8)!r})")

while not done and time.time()-t0<12:
    if not k32.WaitForDebugEvent(C.byref(ev),400): continue
    code=ev.dwDebugEventCode; cont=df.DBG_CONTINUE; handled=False
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess=ev.u.CreateProcessInfo.hProcess
        set_bp(hProcess, ADAD); set_bp(hProcess, EFD6)
    elif code==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord; ec=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ec==0x80000003 and addr in bps:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(th)
            name='ADAD' if addr==ADAD else 'EFD6'
            snap(hProcess, name, ctx)
            if name=='EFD6':
                done=True
            clear_bp(hProcess, addr)
            ctx.Rip=addr; ctx.EFlags|=0x100; ctx.ContextFlags=df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            while True:
                k32.WaitForDebugEvent(C.byref(ev),2000)
                if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
                    er2=ev.u.Exception.ExceptionRecord
                    if (er2.ExceptionCode&0xffffffff)==0x80000004:
                        ctx2=df.get_thread_context(th); ctx2.EFlags&=~0x100; ctx2.ContextFlags=df.CONTEXT_FULL
                        k32.SetThreadContext(th, C.byref(ctx2))
                        if not done: set_bp(hProcess, addr)
                        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE); break
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
                else:
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            k32.CloseHandle(th); handled=True
        elif ec==0xC0000005:
            print('AV'); done=True; cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif code==df.EXIT_PROCESS_DEBUG_EVENT:
        done=True
    if not handled:
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
try: k32.TerminateProcess(pi.hProcess,1)
except: pass
