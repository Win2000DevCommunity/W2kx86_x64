import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ229")
exe = os.path.abspath("cmd_diam.exe")
IB=0x80000000
NAMES={
 IB+0x249e8:"fn249e8",
 IB+0x24a9b:"loop_wcschr",
 IB+0x31ff0:"nullchk_fwd",
}
print("iat rva 0x85480")
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; hits=[]; de=df.DEBUG_EVENT()

while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in NAMES:
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
                nm=NAMES[bp]
                rec=dict(name=nm,rcx=hex(ctx.Rcx),rdx=hex(ctx.Rdx),rax=hex(ctx.Rax),rbp=hex(ctx.Rbp))
                if nm=="fn249e8":
                    ret=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rsp,8))[0]
                    rec["ret"]=hex(ret)
                if nm=="loop_wcschr":
                    a18=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+0x18,8))[0]
                    a10=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+0x10,8))[0]
                    rec["home10"]=hex(a10); rec["home18"]=hex(a18)
                if nm=="nullchk_fwd":
                    rec["arg"]=hex(ctx.Rcx)
                hits.append(rec); print(rec)
                if len(hits)>20:
                    k32.TerminateProcess(pi.hProcess,1); break
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"rdx",hex(ctx.Rdx))
            for h in hits[-15:]: print(h)
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
