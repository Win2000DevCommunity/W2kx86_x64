import ctypes as C, os, dbg_fault as df
k32=df.k32
df.suppress_fault_ui()
exe=os.path.abspath("build_univ83p/cmd_pure.exe")
cmdline='"%s" /c echo w2ktest' % exe
si=df.STARTUPINFO(); si.cb=C.sizeof(df.STARTUPINFO); pi=df.PROCESS_INFORMATION()
assert k32.CreateProcessW(exe,C.create_unicode_buffer(cmdline),None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.path.dirname(exe),C.byref(si),C.byref(pi))
base=0; de=df.DEBUG_EVENT(); active={}
while True:
    if not k32.WaitForDebugEvent(C.byref(de),20000):
        print("timeout"); break
    st=df.DBG_CONTINUE; code=de.dwDebugEventCode
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        base=int(de.u.CreateProcessInfo.lpBaseOfImage)
        h=de.u.CreateProcessInfo.hFile
        if h: k32.CloseHandle(h)
        for rva in (0x23FB7, 0x23DEE):
            addr=base+rva; old=df.read_process_mem(pi.hProcess,addr,1); active[addr]=old[0]; df.patch_byte(pi.hProcess,addr,0xCC)
    elif code==df.LOAD_DLL_DEBUG_EVENT:
        h=de.u.LoadDll.hFile
        if h: k32.CloseHandle(h)
    elif code==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    elif code==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; ecode=er.ExceptionCode&0xffffffff
        ctx=df.get_thread_context(pi.hThread); rip=int(ctx.Rip)
        bp=rip-1 if (rip-1) in active else (rip if rip in active else None)
        if ecode==0x80000003 and bp is not None:
            rva=bp-base
            print("HIT",hex(rva))
            print("RCX",hex(ctx.Rcx),"RDX",hex(ctx.Rdx),"R8",hex(ctx.R8),"R9",hex(ctx.R9))
            print("RAX",hex(ctx.Rax),"RDI",hex(ctx.Rdi),"RSI",hex(ctx.Rsi))
            for off in (0x20,0x28):
                q=df.read_u64(pi.hProcess,int(ctx.Rsp)+off); print("s",hex(off),hex(q) if q else None)
            df.patch_byte(pi.hProcess,bp,active.pop(bp)); ctx.Rip=bp; ctx.ContextFlags=df.CONTEXT_FULL; k32.SetThreadContext(pi.hThread,C.byref(ctx))
            if rva==0x23FB7:
                k32.TerminateProcess(pi.hProcess,1); break
        elif ecode==0xC0000005:
            print("AV",hex(rip)); k32.TerminateProcess(pi.hProcess,1); break
        elif ecode not in (0x80000003,0x80000004):
            st=df.DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st)
k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)