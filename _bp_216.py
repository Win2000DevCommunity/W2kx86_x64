import ctypes as C, sys, time, struct
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ216/cmd_pure.exe").resolve())
cwd = str(Path("build_univ216").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
k32.CreateProcessW(exe, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd, C.byref(si), C.byref(pi))
base=None; de=DEBUG_EVENT(); t0=time.time()
bps={
 0x1ea90:"after_parse",
 0x1d7f4:"disp",
 0x1d61a:"call_disp",
 0x1d83d:"echo_iat",
 0x14e25:"ret4000",
}
orig={}; rearm=None; hits=0
while time.time()-t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(de), 400):
        continue
    st=DBG_CONTINUE
    if de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage
        for rva in bps:
            o=C.c_ubyte(); n=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+rva),C.byref(o),1,C.byref(n))
            orig[rva]=o.value
            k32.WriteProcessMemory(pi.hProcess,C.c_void_p(base+rva),C.byref(C.c_ubyte(0xCC)),1,C.byref(n))
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; ecode=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL; k32.GetThreadContext(pi.hThread,C.byref(ctx))
        if ecode==0x80000003 and base and (addr-base) in bps:
            rva=addr-base; hits+=1
            n=C.c_size_t(); fa=C.c_uint32(); stv=C.c_uint32()
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5bae0),C.byref(fa),4,C.byref(n))
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5be00),C.byref(stv),4,C.byref(n))
            print("%d %s sticky=%d fae0=%#x eax=%#x rdx=%#x"%(hits,bps[rva],stv.value,fa.value,ctx.Rax&0xffffffff,ctx.Rdx&0xffffffff))
            k32.WriteProcessMemory(pi.hProcess,C.c_void_p(addr),C.byref(C.c_ubyte(orig[rva])),1,C.byref(n))
            ctx.Rip=addr; ctx.EFlags|=0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); rearm=rva
            if hits>=30: break
            continue
        if ecode==0x80000004 and rearm is not None:
            n=C.c_size_t()
            for rva in bps:
                k32.WriteProcessMemory(pi.hProcess,C.c_void_p(base+rva),C.byref(C.c_ubyte(0xCC)),1,C.byref(n))
            ctx.EFlags&=~0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); rearm=None
        elif ecode in (0xC00000FD,0xC0000005):
            print("fault",hex(ecode),hex(addr-base if base else addr)); break
        elif ecode not in (0x80000003,0x80000004):
            st=DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
k32.TerminateProcess(pi.hProcess,1)
print("hits",hits)
