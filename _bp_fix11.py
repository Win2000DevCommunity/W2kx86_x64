import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix11.exe")
IB=0x80000000
BPS={
 IB+0xc5e5: "call_28a0c",
 IB+0xc5ea: "after_28a0c",
 IB+0xc622: "call_big",
 IB+0xc627: "after_big",
 IB+0xc678: "join",
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0
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
                df.patch_byte(pi.hProcess,bp,orig[bp]); ctx.Rip=bp; ctx.EFlags&=~0x100
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                print(f"HIT {BPS[bp]} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} rsi={ctx.Rsi:#x} rbx={ctx.Rbx:#x} rdi={ctx.Rdi:#x}")
            else:
                skips+=1
                if skips>6:
                    ctx=df.get_thread_context(pi.hThread)
                    print("int3",hex(ctx.Rip),hex(ctx.Rcx)); k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"rax",hex(ctx.Rax),"rsi",hex(ctx.Rsi))
            if not de.u.Exception.dwFirstChance:
                k32.TerminateProcess(pi.hProcess,1); break
            cont=df.DBG_EXCEPTION_NOT_HANDLED
        elif code==0xC0000374:
            ctx=df.get_thread_context(pi.hThread)
            print("HEAP",hex(ctx.Rip),hex(ctx.Rcx),hex(ctx.Rdx)); k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
