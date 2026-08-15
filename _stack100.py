import sys, ctypes as C
from pathlib import Path
sys.path.insert(0,'.')
import dbg_fault as df
exe=str(Path('build_univ176/cmd_pure_h.exe').resolve())
k32=df.k32
si=df.STARTUPINFO(); si.cb=C.sizeof(si)
pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer('\"%s\" /c echo w2ktest'%exe)
assert k32.CreateProcessW(None,cmd,None,None,False,df.DEBUG_PROCESS,None,str(Path(exe).parent),C.byref(si),C.byref(pi))
IB=0x80000000
ev=df.DEBUG_EVENT()
while True:
    k32.WaitForDebugEvent(C.byref(ev), 5000)
    if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord
        if er.ExceptionCode in (0xC0000005,0xC00000FD):
            ctx=df.CONTEXT(); ctx.ContextFlags=df.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print('FAULT rip=%#x rsp=%#x rbx=%#x rax=%#x'%(ctx.Rip,ctx.Rsp,ctx.Rbx,ctx.Rax))
            buf=(C.c_ulonglong*32)(); n=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(ctx.Rsp),buf,32*8,C.byref(n))
            for i,v in enumerate(buf):
                if IB<=v<IB+0x80000:
                    print('  rsp+%#x %#x'%(i*8,v-IB))
            break
        k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_EXCEPTION_NOT_HANDLED); continue
    if ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT: break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
k32.TerminateProcess(pi.hProcess,1)