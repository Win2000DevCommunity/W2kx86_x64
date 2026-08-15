import ctypes as C, struct, sys, os
sys.path.insert(0,".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix22.exe")
IB=0x80000000
BPS={IB+0x2725a:"cmp_ret", IB+0x1902e:"post_search", IB+0x142a2 if False else IB+0x272a2:"na"}
BPS={IB+0x2725a:"cmp_ret", IB+0x1902e:"post_search"}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); hits=0
def rd(a,n):
    return df.read_process_mem(pi.hProcess,a,n)
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for a in BPS:
            b=rd(a,1)
            if b: orig[a]=b[0]; df.patch_byte(pi.hProcess,a,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003:
            bp=addr if addr in orig else (addr-1 if addr-1 in orig else None)
            if bp is not None:
                ctx=df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess,bp,orig[bp]); ctx.Rip=bp; ctx.EFlags&=~0x100
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                hits+=1
                nm=""
                b=rd(ctx.Rsi-8,4)
                if b:
                    ptr=struct.unpack("<I",b)[0]
                    t=rd(ptr,24)
                    if t: nm=t.decode("utf-16-le","replace").split("\0")[0]
                print(f"HIT {BPS[bp]} rax={ctx.Rax:#x} rdi={ctx.Rdi:#x} rsi={ctx.Rsi:#x} name='{nm}'")
                if hits>36:
                    for a in list(orig): df.patch_byte(pi.hProcess,a,orig[a])
                    orig.clear()
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("EXC",hex(code),"rip",hex(ctx.Rip))
            st=rd(ctx.Rsp,0x180)
            if st:
                shown=0
                for i in range(0,0x178,8):
                    v=struct.unpack_from("<Q",st,i)[0]
                    if IB<=v<IB+0x80000:
                        print(f"   [rsp+{i:#x}]={v:#x}"); shown+=1
                        if shown>5: break
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
