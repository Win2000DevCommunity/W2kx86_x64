import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_both.exe")
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
de=df.DEBUG_EVENT()
while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff
        if code in (0xC0000005,0xC0000374) and de.u.Exception.dwFirstChance:
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"rdx",hex(ctx.Rdx),
                  "r8",hex(ctx.R8),"r9",hex(ctx.R9),"rax",hex(ctx.Rax),"rbp",hex(ctx.Rbp),"rsp",hex(ctx.Rsp))
            stk=df.read_process_mem(pi.hProcess,ctx.Rsp,0x80)
            qs=struct.unpack("<16Q", stk)
            print("stack:")
            for i,q in enumerate(qs):
                print(f"  [{i*8:#x}] {q:#x}")
            # disasm around rip if in image
            if 0x80000000 <= ctx.Rip < 0x80100000:
                for line in df.disasm_range(pi.hProcess, ctx.Rip, 24, 24):
                    print(" ", line)
            # module
            print("owner", df.module_owner(ctx.Rip, 0x80000000, {}))
            k32.TerminateProcess(pi.hProcess,1); break
        elif code==0x80000003:
            pass
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
