import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ229")
exe = os.path.abspath("cmd_diam.exe")
IB=0x80000000
BP=IB+0x24a9b
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig=None; de=df.DEBUG_EVENT(); pending=None; n=0

while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        orig=df.read_process_mem(pi.hProcess,BP,1)[0]
        df.patch_byte(pi.hProcess,BP,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003 and addr in (BP,BP+1):
            ctx=df.get_thread_context(pi.hThread)
            df.patch_byte(pi.hProcess,BP,orig)
            ctx.Rip=BP; ctx.EFlags|=0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx)); pending=BP
            h18=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+0x18,8))[0]
            h10=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+0x10,8))[0]
            # also dump saved rbp and ret
            sv=struct.unpack("<QQ", df.read_process_mem(pi.hProcess,ctx.Rbp,16))
            ch=ctx.Rdx & 0xffff  # not yet loaded; after mov edx will be char - currently leftover
            # read [rbp-0xc] for char
            ch=struct.unpack("<I", df.read_process_mem(pi.hProcess,ctx.Rbp-0xc,4))[0] & 0xffff
            cur=struct.unpack("<I", df.read_process_mem(pi.hProcess,ctx.Rbp-4,4))[0]
            print(f"n={n} ch={ch:#x}({chr(ch) if 32<=ch<127 else '?'}) home18={h18:#x} home10={h10:#x} savrbp={sv[0]:#x} ret={sv[1]:#x} cur={cur:#x} rbp={ctx.Rbp:#x}")
            n+=1
            if h18 > 0x100000000 or n>40:
                k32.TerminateProcess(pi.hProcess,1); break
        elif code==0x80000004:
            if pending:
                df.patch_byte(pi.hProcess,pending,0xCC); pending=None
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rcx",hex(ctx.Rcx),"n",n)
            k32.TerminateProcess(pi.hProcess,1); break
        else:
            if code!=0x80000003: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",n); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
