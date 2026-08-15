import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix5.exe")
IB=0x80000000
BP=IB+0xc59c
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig=None; de=df.DEBUG_EVENT()
while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        orig=df.read_process_mem(pi.hProcess,BP,1)[0]
        df.patch_byte(pi.hProcess,BP,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003 and addr in (BP,BP+1):
            ctx=df.get_thread_context(pi.hThread)
            df.patch_byte(pi.hProcess,BP,orig); ctx.Rip=BP; ctx.EFlags&=~0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx))
            print("rax",hex(ctx.Rax),"rsi",hex(ctx.Rsi),"rdi",hex(ctx.Rdi),"rbx",hex(ctx.Rbx))
            # if rsi looks like pointer, read string
            if ctx.Rsi > 0x10000 and ctx.Rsi < 0x7fffffff:
                b=df.read_process_mem(pi.hProcess,ctx.Rsi,32)
                print(" [rsi]", b.decode("utf-16-le","replace")[:20] if b else None)
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000003 and code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
