import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix2.exe")
IB=0x80000000
BPS={IB+0xd3c6:"store_buf", IB+0xd54c:"strlen_arg", IB+0xd56a:"realloc_arg"}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT()
while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in BPS:
            b=df.read_process_mem(pi.hProcess,va,1)
            orig[va]=b[0]; df.patch_byte(pi.hProcess,va,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003:
            bp=addr if addr in orig else (addr-1 if addr-1 in orig else None)
            if bp is not None:
                ctx=df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess,bp,orig[bp]); ctx.Rip=bp; ctx.EFlags&=~0x100
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                h10=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+0x10,8))[0]
                print(BPS[bp], "rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"h10",hex(h10))
        elif code in (0xC0000005,0xC0000374) or (code==0x80000003 and addr not in orig and addr-1 not in orig):
            # heap int3 often
            ctx=df.get_thread_context(pi.hThread)
            if code!=0x80000003 or True:
                print("FAULT/BP",hex(code),"rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx))
                k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
