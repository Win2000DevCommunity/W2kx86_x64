import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix8.exe")
IB=0x80000000
BPS={
 IB+0xd0ab: "after_pushes",  # after push rbx/rsi/rdi - actually at push rbx
 IB+0xd0ae: "after_3push",
 IB+0xd9bc: "early_ret",
 IB+0xc579: "after_lensum",  # mov rsi,rax
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0; saved=None
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
                name=BPS[bp]
                print(f"HIT {name} rip={ctx.Rip:#x} rsp={ctx.Rsp:#x} rbp={ctx.Rbp:#x}")
                print(f"  rax={ctx.Rax:#x} rsi={ctx.Rsi:#x} rdi={ctx.Rdi:#x} rbx={ctx.Rbx:#x}")
                # dump stack top
                st=df.read_process_mem(pi.hProcess, ctx.Rsp, 48)
                if st:
                    qs=[hex(struct.unpack_from("<Q",st,i)[0]) for i in range(0,48,8)]
                    print("  [rsp]=", qs)
                if name=="after_3push":
                    # save locations of callee saves
                    saved=(ctx.Rsp, ctx.Rbp)
                    st=df.read_process_mem(pi.hProcess, ctx.Rsp, 24)
                    print("  saved rdi,rsi,rbx slots:", [hex(struct.unpack_from("<Q",st,i)[0]) for i in range(0,24,8)])
                if name=="early_ret":
                    # compare rbp-based slots
                    for off in (0x230,0x238,0x240,0x228,0x220,0x218):
                        a=ctx.Rbp-off
                        b=df.read_process_mem(pi.hProcess,a,8)
                        if b: print(f"  [rbp-{off:#x}]={struct.unpack('<Q',b)[0]:#x}")
                    if saved:
                        print("  entry rsp/rbp", hex(saved[0]), hex(saved[1]))
                    k32.TerminateProcess(pi.hProcess,1); break
            else:
                skips+=1
                if skips>8:
                    k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            if not de.u.Exception.dwFirstChance:
                k32.TerminateProcess(pi.hProcess,1); break
            cont=df.DBG_EXCEPTION_NOT_HANDLED
        elif code==0xC0000374:
            print("HEAP"); k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
