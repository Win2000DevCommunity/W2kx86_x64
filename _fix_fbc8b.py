"""One-shot: at first ADD9, set fbc8 to point at ' /c' within buffer (skip exe), continue without further BPs."""
import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ99p/cmd_pure.exe").resolve())
ADD9 = 0x800146F4
FBC8 = 0x8006DBC8
F000 = 0x8006F000
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
ev = df.DEBUG_EVENT(); hProcess=None; t0=time.time(); fixed=False; orig=None

def set_bp(proc, addr):
    global orig
    orig = df.read_process_mem(proc, addr, 1)[0]
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc, C.c_void_p(addr), b"\xCC", 1, C.byref(wr))
def clear_bp(proc, addr):
    wr=C.c_size_t(0); k32.WriteProcessMemory(proc, C.c_void_p(addr), bytes([orig]), 1, C.byref(wr))

done=False
while not done and time.time()-t0 < 10:
    if not k32.WaitForDebugEvent(C.byref(ev), 400): continue
    code=ev.dwDebugEventCode; cont=df.DBG_CONTINUE
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess=ev.u.CreateProcessInfo.hProcess
        set_bp(hProcess, ADD9)
    elif code==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord; ec=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ec==0x80000003 and addr==ADD9 and not fixed:
            th=k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx=df.get_thread_context(th)
            buf=ctx.Rcx
            raw=df.read_process_mem(hProcess, buf, 400) or b""
            # find utf-16 ' /c'
            needle=' /c'.encode('utf-16-le')
            idx=raw.find(needle)
            if idx<0:
                needle='/c'.encode('utf-16-le'); idx=raw.find(needle)
            if idx>=0:
                ptr = (buf + idx) & 0xFFFFFFFF
                print(f"point fbc8 at /c offset {idx} ptr={ptr:#x}")
            else:
                ptr = buf & 0xFFFFFFFF
                print(f"no /c found, use buf start {ptr:#x}")
            wr=C.c_size_t(0)
            k32.WriteProcessMemory(hProcess, C.c_void_p(FBC8), struct.pack("<I", ptr), 4, C.byref(wr))
            k32.WriteProcessMemory(hProcess, C.c_void_p(F000), struct.pack("<I", ptr), 4, C.byref(wr))
            fixed=True
            clear_bp(hProcess, ADD9)
            ctx.Rip=ADD9; ctx.ContextFlags=df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            k32.CloseHandle(th)
            # detach? just continue without TF
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            continue
        elif ec==0x80000003:
            # foreign bp
            pass
        elif ec==0xC0000005:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId); ctx=df.get_thread_context(th)
            print(f"[AV] RIP={ctx.Rip:#x} RCX={ctx.Rcx:#x} RAX={ctx.Rax:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x}")
            # stack
            stk=df.read_process_mem(hProcess, ctx.Rsp, 64) or b""
            print("stack", stk[:32].hex())
            done=True; cont=df.DBG_EXCEPTION_NOT_HANDLED
            k32.CloseHandle(th)
    elif code==df.EXIT_PROCESS_DEBUG_EVENT:
        print(f"[exit] {ev.u.ExitProcess.dwExitCode:#x} fixed={fixed}")
        done=True
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
try: k32.TerminateProcess(pi.hProcess,1)
except: pass
