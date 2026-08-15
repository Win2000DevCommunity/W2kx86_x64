import ctypes as C, os, sys
from ctypes import wintypes
from dbg_fault import *

probes = [0x12b58, 0x12b64, 0x12b80, 0x12bad, 0x12bce, 0x12bed, 0x12c08, 0x12c36, 0x12c44, 0x12c68, 0x12c99]
exe = os.path.abspath("build_univ168/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base=None; orig={}; hit=[]
rpm=lambda a,n: (lambda b,m: bytes(b[:m.value]) if ReadProcessMemory(pi.hProcess,C.c_void_p(a),b,n,C.byref(m)) else b'')((C.c_char*n)(), C.c_size_t())
ReadProcessMemory=k32.ReadProcessMemory; WriteProcessMemory=k32.WriteProcessMemory
ReadProcessMemory.argtypes=[wintypes.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
WriteProcessMemory.argtypes=[wintypes.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]

def wpm(a,data):
    buf=C.create_string_buffer(data); m=C.c_size_t(0)
    return WriteProcessMemory(pi.hProcess,C.c_void_p(a),buf,len(data),C.byref(m))

def plant():
    for rva in probes:
        addr=base+rva; ob=rpm(addr,1)
        if len(ob)==1:
            orig[rva]=ob; wpm(addr,b"\xcc")

de=DEBUG_EVENT(); first=0
while True:
    assert k32.WaitForDebugEvent(C.byref(de), 60000)
    code=de.dwDebugEventCode; status=DBG_CONTINUE
    if code==CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
        plant()
    elif code==LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code==EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode); break
    elif code==EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; ecode=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        if ecode==0x80000003:
            if first==0: first=1
            elif base and base<=addr<base+0x200000 and (addr-base) in orig:
                rva=addr-base; hit.append(rva); wpm(addr,orig[rva])
                ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL; k32.GetThreadContext(pi.hThread,C.byref(ctx))
                # read [r12+8]
                r12v=ctx.R12; mem=rpm(r12v+8,4) if r12v else b""
                slot=int.from_bytes(mem,"little") if len(mem)==4 else -1
                print("HIT %s rsp=%s rax=%s r12=%s [r12+8]=%s rbp=%s" % (hex(rva),hex(ctx.Rsp),hex(ctx.Rax),hex(r12v),hex(slot),hex(ctx.Rbp)))
                ctx.Rip=addr; k32.SetThreadContext(pi.hThread,C.byref(ctx))
            elif first:
                status=DBG_EXCEPTION_NOT_HANDLED
        elif ecode==0xC0000005:
            ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL; k32.GetThreadContext(pi.hThread,C.byref(ctx))
            op=er.ExceptionInformation[0]; fault=er.ExceptionInformation[1]&0xffffffffffffffff
            kind={0:"read",1:"write",8:"execute"}.get(op,str(op))
            print("CRASH %s@%s rip=%s hits=%s" % (kind,hex(fault),hex(ctx.Rip),[hex(x) for x in hit]))
            print(" rax=%s rcx=%s rdx=%s r8=%s r9=%s r14=%s r15=%s" % (hex(ctx.Rax),hex(ctx.Rcx),hex(ctx.Rdx),hex(ctx.R8),hex(ctx.R9),hex(ctx.R14),hex(ctx.R15)))
            k32.TerminateProcess(pi.hProcess,1); break
        else:
            status=DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
