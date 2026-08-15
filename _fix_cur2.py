"""Runtime: on every ADD9 entry, if [fbc8]==0 or *[fbc8]==0, set fbc8=RCX."""
import ctypes as C, struct, sys, time, subprocess
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()

# First test with subprocess after using a debug launcher that patches then continues detached - hard.
# Simpler: patch binary to insert logic - too hard.
# Use debug loop: fix fbc8 on each add9, don't single-step messily, just fix and continue with TF off.

k32 = df.k32
exe = str(Path("build_univ101/cmd_pure.exe").resolve())
m = {int(a[0],16):int(a[1],16) for ln in Path("build_univ101/rva.txt").read_text().splitlines() if len(a:=ln.split())>=2}
ADD9 = 0x80000000 + m[0xADD9]
FBC8 = 0x8006DBC8
F000 = 0x8006F000
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
# Create with pipe for stdout
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
bps={}; ev=df.DEBUG_EVENT(); hProcess=None; t0=time.time(); nfix=0; done=False
orig=None

def set_bp(proc, addr):
    global orig
    orig=df.read_process_mem(proc,addr,1)[0]
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc,C.c_void_p(addr),b"\xCC",1,C.byref(wr))
def clear_bp(proc, addr):
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc,C.c_void_p(addr),bytes([orig]),1,C.byref(wr))

while not done and time.time()-t0 < 15:
    if not k32.WaitForDebugEvent(C.byref(ev), 400): continue
    code=ev.dwDebugEventCode; cont=df.DBG_CONTINUE; handled=False
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess=ev.u.CreateProcessInfo.hProcess
        set_bp(hProcess, ADD9)
    elif code==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord; ec=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ec==0x80000003 and addr==ADD9:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(th)
            if ctx.Rcx:
                fbc8=struct.unpack("<I", df.read_process_mem(hProcess,FBC8,4) or b"\0"*4)[0]
                ch=b"\0\0"
                if fbc8:
                    ch=df.read_process_mem(hProcess,fbc8,2) or b"\0\0"
                if not fbc8 or ch==b"\0\0":
                    ptr=ctx.Rcx & 0xFFFFFFFF
                    wr=C.c_size_t(0)
                    k32.WriteProcessMemory(hProcess,C.c_void_p(FBC8),struct.pack("<I",ptr),4,C.byref(wr))
                    k32.WriteProcessMemory(hProcess,C.c_void_p(F000),struct.pack("<I",ptr),4,C.byref(wr))
                    nfix+=1
                    if nfix<=5:
                        print(f"[fix #{nfix}] fbc8:= {ptr:#x} flags={ctx.Rdx:#x}")
            clear_bp(hProcess, ADD9)
            ctx.Rip=ADD9; ctx.EFlags|=0x100; ctx.ContextFlags=df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            while True:
                k32.WaitForDebugEvent(C.byref(ev),2000)
                if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
                    er2=ev.u.Exception.ExceptionRecord
                    if (er2.ExceptionCode&0xffffffff)==0x80000004:
                        ctx2=df.get_thread_context(th); ctx2.EFlags&=~0x100; ctx2.ContextFlags=df.CONTEXT_FULL
                        k32.SetThreadContext(th, C.byref(ctx2))
                        set_bp(hProcess, ADD9)
                        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE); break
                    elif (er2.ExceptionCode&0xffffffff)==0xC0000005:
                        ctx2=df.get_thread_context(th)
                        print(f"[AV] RIP={ctx2.Rip:#x} fixes={nfix}")
                        done=True
                        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED); break
                    else:
                        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
                elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
                    print(f"[exit] {ev.u.ExitProcess.dwExitCode:#x} fixes={nfix}")
                    done=True; break
                else:
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            k32.CloseHandle(th); handled=True
        elif ec==0xC0000005:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId); ctx=df.get_thread_context(th)
            print(f"[AV2] RIP={ctx.Rip:#x} fixes={nfix}")
            done=True; cont=df.DBG_EXCEPTION_NOT_HANDLED
            k32.CloseHandle(th)
    elif code==df.EXIT_PROCESS_DEBUG_EVENT:
        print(f"[exit] {ev.u.ExitProcess.dwExitCode:#x} fixes={nfix}"); done=True
    if not handled:
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
try: k32.TerminateProcess(pi.hProcess,1)
except: pass
