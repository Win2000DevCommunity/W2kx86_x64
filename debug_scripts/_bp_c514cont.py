import ctypes as C, struct, sys, os, subprocess
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix3.exe")
IB=0x80000000
# BP WriteFile via IAT call sites - break on echo print helpers
NAMES={IB+0xc59c:"after_d08c", IB+0xc631:"jne_path", IB+0xc5a1:"cmp1", IB+0xc5c0:"alloc2"}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0; hits=[]
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
                print("HIT",NAMES[bp],"rax",hex(ctx.Rax),"eax",hex(ctx.Rax&0xffffffff))
                hits.append(NAMES[bp])
            else:
                skips+=1
                if skips>6:
                    print("heap int3"); k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            if de.u.Exception.dwFirstChance:
                cont=df.DBG_EXCEPTION_NOT_HANDLED
            else:
                ctx=df.get_thread_context(pi.hThread)
                print("FAULT2",hex(ctx.Rip),hits); k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000374:
            print("HEAP_CORRUPT",hits); k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff),hits); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
