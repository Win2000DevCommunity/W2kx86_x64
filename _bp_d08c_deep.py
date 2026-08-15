import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix2.exe")
IB=0x80000000
NAMES={
 IB+0xd56a:"realloc",
 IB+0xd583:"after_realloc",
 IB+0xd599:"after_realloc2",
 IB+0xd36c:"wcscmp?",
 IB+0xd3c6:"store410",
 IB+0xd66d:"fail410",
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0
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
                print("HIT", NAMES[bp], "rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"rbx",hex(ctx.Rbx))
            else:
                skips+=1
                if skips>3:
                    ctx=df.get_thread_context(pi.hThread)
                    print("heap_int3",hex(ctx.Rip),hex(ctx.Rcx),hex(ctx.Rax))
                    # stack rets in image
                    stk=df.read_process_mem(pi.hProcess,ctx.Rsp,0x200)
                    for i in range(0,len(stk),8):
                        q=struct.unpack_from("<Q",stk,i)[0]
                        if 0x80001000 <= q < 0x80050000:
                            print(f"  ret [{i:#x}] {q:#x}")
                    k32.TerminateProcess(pi.hProcess,1); break
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),hex(ctx.Rip)); 
            cont=df.DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else df.DBG_CONTINUE
            if not de.u.Exception.dwFirstChance:
                k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
