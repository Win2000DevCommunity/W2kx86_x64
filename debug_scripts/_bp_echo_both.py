import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_both.exe")
IB=0x80000000
NAMES={
 IB+0x189c4:"echo",
 IB+0xc468:"c468",
 IB+0xc514:"c514",
 IB+0x28858:"lensum",
 IB+0x288ee:"lensum_alloc",
 IB+0xc597:"d08c_call",
 IB+0xd08c:"d08c",
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; hits=[]; de=df.DEBUG_EVENT()
def rw(a,n=40):
    b=df.read_process_mem(pi.hProcess,a,n*2)
    if not b: return None
    return b.decode("utf-16-le","replace").split("\0")[0][:50]

while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in NAMES:
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
                nm=NAMES[bp]
                rec=dict(name=nm,rcx=hex(ctx.Rcx),rdx=hex(ctx.Rdx),rax=hex(ctx.Rax))
                if nm in ("echo","c468","c514","lensum","d08c"):
                    node=ctx.Rcx
                    d38=struct.unpack("<I", df.read_process_mem(pi.hProcess,node+0x38,4))[0]
                    d3c=struct.unpack("<I", df.read_process_mem(pi.hProcess,node+0x3c,4))[0]
                    rec.update(d38=hex(d38),d3c=hex(d3c))
                    if d38>0x10000: rec["s38"]=rw(d38)
                    if d3c>0x10000: rec["s3c"]=rw(d3c)
                if nm=="lensum_alloc": rec["size"]=hex(ctx.Rcx)
                hits.append(rec); print(rec)
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"rdx",hex(ctx.Rdx),"rbp",hex(ctx.Rbp))
            stk=df.read_process_mem(pi.hProcess,ctx.Rsp,0x40)
            if stk: print([hex(x) for x in struct.unpack("<8Q",stk)])
            for h in hits: print(h)
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff), "hits",len(hits)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
