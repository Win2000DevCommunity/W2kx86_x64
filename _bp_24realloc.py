import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix2.exe")
IB=0x80000000
BP=IB+0x24df5  # mov ecx, [rbp-0x10] before realloc
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig=None; de=df.DEBUG_EVENT(); n=0; skips=0
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        orig=df.read_process_mem(pi.hProcess,BP,1)[0]
        df.patch_byte(pi.hProcess,BP,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003 and addr in (BP,BP+1):
            ctx=df.get_thread_context(pi.hThread)
            df.patch_byte(pi.hProcess,BP,orig); ctx.Rip=BP; ctx.EFlags|=0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx)); 
            # read [rbp-0x10] and rax (size being computed)
            # after lea rax,[rax+rax+4] at 24df0, at 24df5 rax is size
            m10=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp-0x10,8))[0]
            print(f"n={n} rax(size)={ctx.Rax:#x} [rbp-10]={m10:#x} rbp={ctx.Rbp:#x}")
            n+=1
            if n>5: k32.TerminateProcess(pi.hProcess,1); break
        elif code==0x80000004:
            df.patch_byte(pi.hProcess,BP,0xCC)
        elif code==0x80000003:
            skips+=1
            if skips>5:
                ctx=df.get_thread_context(pi.hThread)
                print("heap",hex(ctx.Rip),hex(ctx.Rcx)); k32.TerminateProcess(pi.hProcess,1); break
        elif code in (0xC0000005,0xC0000374):
            print("FAULT",hex(code)); k32.TerminateProcess(pi.hProcess,1); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",n); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
