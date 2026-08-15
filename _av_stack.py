import ctypes as C, struct, sys, os
sys.path.insert(0,".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix20.exe")
LO,HI=0x80000000,0x80080000
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
de=df.DEBUG_EVENT()
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff
        if code in (0xC0000005,0xC0000374,0x80000003):
            ctx=df.get_thread_context(pi.hThread)
            if code==0x80000003 and not (LO<=ctx.Rip<HI):
                pass
            print(f"EXC {code:#x} rip={ctx.Rip:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} r8={ctx.R8:#x} rsp={ctx.Rsp:#x}")
            st=df.read_process_mem(pi.hProcess, ctx.Rsp, 0x200)
            if st:
                seen=[]
                for i in range(0, 0x200-8, 8):
                    v=struct.unpack_from("<Q",st,i)[0]
                    if LO<=v<HI:
                        seen.append((i,v))
                print("  image return addrs on stack:")
                for i,v in seen[:8]:
                    print(f"    [rsp+{i:#x}] = {v:#x}")
            k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
