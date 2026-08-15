import ctypes as C, struct, sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,".")
import dbg_fault as df
md=Cs(CS_ARCH_X86, CS_MODE_64)
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix16.exe")
IB=0x80000000
BPS={IB+0xc622:"call_print", IB+0xc627:"after_print", IB+0xc940:"print_entry", IB+0xc98a:"print_pushes"}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0; tracing=False; steps=0
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in BPS:
            b=df.read_process_mem(pi.hProcess,va,1)
            if b: orig[va]=b[0]; df.patch_byte(pi.hProcess,va,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003:
            bp=addr if addr in orig else (addr-1 if addr-1 in orig else None)
            if bp is not None:
                ctx=df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess,bp,orig[bp]); ctx.Rip=bp
                print(f"HIT {BPS[bp]} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} r8={ctx.R8:#x} r9={ctx.R9:#x} rsp={ctx.Rsp:#x}")
                if BPS[bp]=="print_entry":
                    ctx.EFlags|=0x100; tracing=True; steps=0
                else:
                    ctx.EFlags&=~0x100
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
            else:
                skips+=1
                if skips>8: k32.TerminateProcess(pi.hProcess,1); break
        elif code==0x80000004 and tracing:
            ctx=df.get_thread_context(pi.hThread)
            steps+=1
            b=df.read_process_mem(pi.hProcess,ctx.Rip,15) or b""
            ins=list(md.disasm(b, ctx.Rip))
            s=f"{ins[0].mnemonic} {ins[0].op_str}" if ins else "?"
            if steps<=30 or "call" in s or "jmp" in s or ctx.Rip < 0x10000:
                print(f"  {steps} {ctx.Rip:#x}: {s}")
            if steps>60 or ctx.Rip < 0x10000 or (ctx.Rip > 0x100000 and ctx.Rip < 0x70000000):
                print("stop", hex(ctx.Rip)); k32.TerminateProcess(pi.hProcess,1); break
            ctx.EFlags|=0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip),hex(ctx.Rax),hex(ctx.Rcx))
            k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000374:
            print("HEAP",hex(df.get_thread_context(pi.hThread).Rip)); k32.TerminateProcess(pi.hProcess,1); break
        elif code not in (0x80000003,0x80000004):
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
