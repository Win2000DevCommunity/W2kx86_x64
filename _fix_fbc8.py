"""At ADD9 entry, set fbc8 = rcx (buffer) then continue; see if echo works."""
import ctypes as C, struct, sys, time, subprocess
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ99p/cmd_pure.exe").resolve())
ADD9 = 0x800146F4
FBC8 = 0x8006DBC8
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
# Use CREATE_NO_WINDOW via startup? keep debug
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
# redirect stdout via pipe? simpler: just fix cursor and let it run, read... 
# Actually capture console is hard under debug. Just check exit and count More via shared console.
# Use a temp approach: write flag and run without capturing - check if we hit More path less.

ev = df.DEBUG_EVENT(); hProcess=None; t0=time.time(); fixed=False; orig=None
more_hits = 0
# also bp a known More? print site if we can find it - use AE0D mapped wrong; use B21C instead
B21C = 0x80014FB8
bps = {}

def set_bp(proc, addr):
    b=df.read_process_mem(proc,addr,1)
    if not b: return
    bps[addr]=b[0]
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc,C.c_void_p(addr),b"\xCC",1,C.byref(wr))
def clear_bp(proc, addr):
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc,C.c_void_p(addr),bytes([bps[addr]]),1,C.byref(wr))

done=False
while not done and time.time()-t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(ev), 300): continue
    code=ev.dwDebugEventCode; cont=df.DBG_CONTINUE; handled=False
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess=ev.u.CreateProcessInfo.hProcess
        set_bp(hProcess, ADD9)
        set_bp(hProcess, B21C)
    elif code==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord; ec=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ec==0x80000003 and addr in bps:
            th=k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx=df.get_thread_context(th)
            if addr==ADD9 and not fixed:
                # force fbc8 = buffer (rcx)
                buf = ctx.Rcx & 0xFFFFFFFF
                wr=C.c_size_t(0)
                k32.WriteProcessMemory(hProcess, C.c_void_p(FBC8), struct.pack("<I", buf), 4, C.byref(wr))
                # also 21000
                k32.WriteProcessMemory(hProcess, C.c_void_p(0x8006F000), struct.pack("<I", buf), 4, C.byref(wr))
                print(f"[fix] fbc8 := {buf:#x} flags={ctx.Rdx:#x}")
                fixed=True
            elif addr==B21C:
                more_hits += 1
                if more_hits <= 3:
                    print(f"[B21C #{more_hits}] refill hit")
                if more_hits > 20:
                    print("too many refills"); done=True
            clear_bp(hProcess, addr)
            ctx.Rip=addr; ctx.EFlags|=0x100; ctx.ContextFlags=df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            while True:
                k32.WaitForDebugEvent(C.byref(ev), 2000)
                if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
                    er2=ev.u.Exception.ExceptionRecord
                    if (er2.ExceptionCode&0xffffffff)==0x80000004:
                        ctx2=df.get_thread_context(th); ctx2.EFlags&=~0x100; ctx2.ContextFlags=df.CONTEXT_FULL
                        k32.SetThreadContext(th, C.byref(ctx2))
                        if not done and addr==ADD9:
                            pass  # one-shot add9
                        elif not done:
                            set_bp(hProcess, addr)
                        if addr==ADD9:
                            set_bp(hProcess, ADD9)  # allow later add9 with fix again? only first
                        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE); break
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
                else:
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            k32.CloseHandle(th); handled=True
        elif ec==0xC0000005:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId); ctx=df.get_thread_context(th)
            print(f"[AV] RIP={ctx.Rip:#x} B21C_hits={more_hits}")
            done=True; cont=df.DBG_EXCEPTION_NOT_HANDLED
            k32.CloseHandle(th)
    elif code==df.EXIT_PROCESS_DEBUG_EVENT:
        print(f"[exit] code={ev.u.ExitProcess.dwExitCode} B21C_hits={more_hits} fixed={fixed}")
        done=True
    if not handled:
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
try: k32.TerminateProcess(pi.hProcess,1)
except: pass
