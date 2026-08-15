import ctypes as C, struct, sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,".")
import dbg_fault as df
md=Cs(CS_ARCH_X86, CS_MODE_64)
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix20.exe")
LO,HI=0x80000000,0x80080000
START=LO+0xcb31   # after HeapAlloc in print fn
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
de=df.DEBUG_EVENT()
orig_start=None; tracing=False; steps=0
ret_bp=None; ret_orig=None
def setbp(addr):
    b=df.read_process_mem(pi.hProcess,addr,1)
    if not b: return None
    df.patch_byte(pi.hProcess,addr,0xCC); return b[0]
while k32.WaitForDebugEvent(C.byref(de),30000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        orig_start=setbp(START)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003 and not tracing and addr in (START,START+1):
            ctx=df.get_thread_context(pi.hThread)
            df.patch_byte(pi.hProcess,START,orig_start); ctx.Rip=START
            ctx.EFlags|=0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); tracing=True
        elif code==0x80000003 and ret_bp is not None and addr in (ret_bp,ret_bp+1):
            ctx=df.get_thread_context(pi.hThread)
            df.patch_byte(pi.hProcess,ret_bp,ret_orig); ctx.Rip=ret_bp
            print(f"      -> rax={ctx.Rax:#x}")
            ret_bp=None; ret_orig=None
            ctx.EFlags|=0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif code==0x80000004 and tracing:
            ctx=df.get_thread_context(pi.hThread)
            steps+=1
            if not (LO<=ctx.Rip<HI):
                print("left image at", hex(ctx.Rip)); k32.TerminateProcess(pi.hProcess,1); break
            b=df.read_process_mem(pi.hProcess,ctx.Rip,16) or b""
            ins=list(md.disasm(b,ctx.Rip))
            if not ins:
                print("undisasm", hex(ctx.Rip)); k32.TerminateProcess(pi.hProcess,1); break
            it=ins[0]; s=f"{it.mnemonic} {it.op_str}"
            interesting = it.mnemonic in ("call","ret","jmp") or "rip" in s
            if interesting:
                print(f"{steps:4d} {ctx.Rip:#x}: {s}   rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} r8={ctx.R8:#x} rax={ctx.Rax:#x}")
            if it.mnemonic=="call":
                # compute target for call reg/rel
                tgt=None
                if it.op_str.startswith("0x"): tgt=int(it.op_str,16)
                else:
                    reg=it.op_str.strip()
                    tgt={"rax":ctx.Rax,"rbx":ctx.Rbx,"rcx":ctx.Rcx,"rdx":ctx.Rdx,
                         "rsi":ctx.Rsi,"rdi":ctx.Rdi,"r13":ctx.R13,"r14":ctx.R14,
                         "r15":ctx.R15,"rbp":ctx.Rbp}.get(reg)
                if tgt is not None and not (LO<=tgt<HI):
                    ret_bp=ctx.Rip+it.size; ret_orig=setbp(ret_bp)
                    ctx.EFlags&=~0x100
                    k32.SetThreadContext(pi.hThread,C.byref(ctx))
                    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont); continue
            if steps>900:
                print("cap"); k32.TerminateProcess(pi.hProcess,1); break
            ctx.EFlags|=0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print(f"EXC {code:#x} rip={ctx.Rip:#x}")
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
