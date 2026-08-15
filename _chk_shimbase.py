import ctypes as C, struct, sys, os
sys.path.insert(0,".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix16.exe")
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
de=df.DEBUG_EVENT(); mods={}
while k32.WaitForDebugEvent(C.byref(de),15000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.LOAD_DLL_DEBUG_EVENT:
        base=de.u.LoadDll.lpBaseOfDll
        name=None
        if de.u.LoadDll.lpImageName:
            try:
                ptr=df.read_process_mem(pi.hProcess, de.u.LoadDll.lpImageName, 8)
                if ptr:
                    p=struct.unpack("<Q",ptr)[0]
                    if p:
                        raw=df.read_process_mem(pi.hProcess,p,200)
                        if raw:
                            if de.u.LoadDll.fUnicode:
                                name=raw.split(b"\0\0")[0].decode("utf-16-le","replace")
                            else:
                                name=raw.split(b"\0")[0].decode("ascii","replace")
            except: pass
        if name and ("w2k" in name.lower() or "shim" in name.lower() or "cmd" in name.lower()):
            print(f"DLL {name} base={base:#x}")
            mods[name]=base
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        print("exe base", hex(de.u.CreateProcessInfo.lpBaseOfImage or 0))
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff
        if code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip))
            # check if 0x18001010c0 readable
            b=df.read_process_mem(pi.hProcess, 0x18001010c0, 16)
            print("handler mem", b.hex() if b else None)
            k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000374:
            print("HEAP"); k32.TerminateProcess(pi.hProcess,1); break
        elif code not in (0x80000003,0x80000004):
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
print("mods", mods)
