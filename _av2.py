import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0,".")
import dbg_fault as df
df.suppress_fault_ui()
k32=df.k32
exe=str(Path("build_univ101/cmd_pure.exe").resolve())
m={int(a[0],16):int(a[1],16) for ln in Path("build_univ101/rva.txt").read_text().splitlines() if len(a:=ln.split())>=2}
ADD9=0x80000000+m[0xADD9]; FBC8=0x8006DBC8; F000=0x8006F000
EFD6_RET=0x8001C31E  # after call efd6
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
ok=k32.CreateProcessW(exe, f'"{exe}" /c echo w2ktest', None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,str(Path(exe).parent),C.byref(si),C.byref(pi))
assert ok
bps={}; ev=df.DEBUG_EVENT(); hP=None; t0=time.time(); done=False; phase=0
def sbp(p,a):
    b=df.read_process_mem(p,a,1); bps[a]=b[0]
    wr=C.c_size_t(0); k32.WriteProcessMemory(p,C.c_void_p(a),b"\xCC",1,C.byref(wr))
def cbp(p,a):
    wr=C.c_size_t(0); k32.WriteProcessMemory(p,C.c_void_p(a),bytes([bps[a]]),1,C.byref(wr))
while not done and time.time()-t0<12:
    if not k32.WaitForDebugEvent(C.byref(ev),400): continue
    code=ev.dwDebugEventCode; cont=df.DBG_CONTINUE; handled=False
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        hP=ev.u.CreateProcessInfo.hProcess; sbp(hP,ADD9); sbp(hP,EFD6_RET)
    elif code==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord; ec=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ec==0x80000003 and addr in bps:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId); ctx=df.get_thread_context(th)
            if addr==ADD9 and phase==0:
                ptr=ctx.Rcx&0xffffffff
                wr=C.c_size_t(0)
                k32.WriteProcessMemory(hP,C.c_void_p(FBC8),struct.pack("<I",ptr),4,C.byref(wr))
                k32.WriteProcessMemory(hP,C.c_void_p(F000),struct.pack("<I",ptr),4,C.byref(wr))
                print(f"add9 fix fbc8={ptr:#x} rdx={ctx.Rdx:#x}")
                phase=1
            elif addr==EFD6_RET:
                print(f"after efd6 RAX={ctx.Rax:#x} RBX={ctx.Rbx:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} RIP={ctx.Rip:#x}")
                print(f"RSP={ctx.Rsp:#x} [rsp]={struct.unpack('<Q', df.read_process_mem(hP,ctx.Rsp,8) or b'\\0'*8)[0]:#x}")
                phase=2
            cbp(hP,addr)
            ctx.Rip=addr; ctx.EFlags|=0x100; ctx.ContextFlags=df.CONTEXT_FULL
            k32.SetThreadContext(th,C.byref(ctx))
            k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
            while True:
                k32.WaitForDebugEvent(C.byref(ev),2000)
                if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
                    er2=ev.u.Exception.ExceptionRecord
                    if (er2.ExceptionCode&0xffffffff)==0x80000004:
                        ctx2=df.get_thread_context(th); ctx2.EFlags&=~0x100; ctx2.ContextFlags=df.CONTEXT_FULL
                        k32.SetThreadContext(th,C.byref(ctx2))
                        if addr==ADD9: sbp(hP,ADD9)
                        # don't rearm efd6_ret
                        k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE); break
                    elif (er2.ExceptionCode&0xffffffff)==0xC0000005:
                        ctx2=df.get_thread_context(th)
                        print(f"AV RIP={ctx2.Rip:#x} RAX={ctx2.Rax:#x} RCX={ctx2.Rcx:#x} RDX={ctx2.Rdx:#x} RBX={ctx2.Rbx:#x} RSI={ctx2.Rsi:#x} RDI={ctx2.Rdi:#x}")
                        print(f"RSP={ctx2.Rsp:#x} stack={df.read_process_mem(hP,ctx2.Rsp,48).hex()}")
                        done=True
                        k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_EXCEPTION_NOT_HANDLED); break
                    else:
                        k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_EXCEPTION_NOT_HANDLED)
                else:
                    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
            k32.CloseHandle(th); handled=True
        elif ec==0xC0000005:
            th=k32.OpenThread(0x1F03FF,False,ev.dwThreadId); ctx=df.get_thread_context(th)
            print(f"AV2 RIP={ctx.Rip:#x} RDI={ctx.Rdi:#x} RSI={ctx.Rsi:#x} RAX={ctx.Rax:#x} phase={phase}")
            print(f"stack={df.read_process_mem(hP,ctx.Rsp,64).hex()}")
            done=True; cont=df.DBG_EXCEPTION_NOT_HANDLED; k32.CloseHandle(th)
    elif code==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode); done=True
    if not handled: k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
try: k32.TerminateProcess(pi.hProcess,1)
except: pass
