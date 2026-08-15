import ctypes as C, os, sys, time
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32=df.k32
exe=os.path.abspath(r"C:\Users\win2000\Desktop\univ89\cmd_pure.exe")
cmdline='"%s" /c echo w2ktest'%exe
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
assert k32.CreateProcessW(None,C.create_unicode_buffer(cmdline),None,None,False,
    df.DEBUG_PROCESS|df.DEBUG_ONLY_THIS_PROCESS,None,os.path.dirname(exe),C.byref(si),C.byref(pi))

def read(a,n): return df.read_process_mem(pi.hProcess,a,n) or b""
def u32(b,o=0): return int.from_bytes(b[o:o+4],"little") if len(b)>=o+4 else 0

class CTX(C.Structure):
    _fields_=[("P1Home",C.c_uint64),("P2Home",C.c_uint64),("P3Home",C.c_uint64),
        ("P4Home",C.c_uint64),("P5Home",C.c_uint64),("P6Home",C.c_uint64),
        ("ContextFlags",C.c_uint32),("MxCsr",C.c_uint32),
        ("SegCs",C.c_uint16),("SegDs",C.c_uint16),("SegEs",C.c_uint16),
        ("SegFs",C.c_uint16),("SegGs",C.c_uint16),("SegSs",C.c_uint16),
        ("EFlags",C.c_uint32),
        ("Dr0",C.c_uint64),("Dr1",C.c_uint64),("Dr2",C.c_uint64),
        ("Dr3",C.c_uint64),("Dr6",C.c_uint64),("Dr7",C.c_uint64),
        ("Rax",C.c_uint64),("Rcx",C.c_uint64),("Rdx",C.c_uint64),
        ("Rbx",C.c_uint64),("Rsp",C.c_uint64),("Rbp",C.c_uint64),
        ("Rsi",C.c_uint64),("Rdi",C.c_uint64),
        ("R8",C.c_uint64),("R9",C.c_uint64),("R10",C.c_uint64),
        ("R11",C.c_uint64),("R12",C.c_uint64),("R13",C.c_uint64),
        ("R14",C.c_uint64),("R15",C.c_uint64),("Rip",C.c_uint64)]

bps={}; de=df.DEBUG_EVENT(); t0=time.time(); base=0; n=0
def set_bp(a):
    o=read(a,1)
    if o and k32.WriteProcessMemory(pi.hProcess,C.c_uint64(a),(C.c_char*1)(0xCC),1,C.byref(C.c_size_t())):
        bps[a]=o[0]
def clear_bp(a):
    if a in bps: k32.WriteProcessMemory(pi.hProcess,C.c_uint64(a),(C.c_char*1)(bps[a]),1,C.byref(C.c_size_t()))

while time.time()-t0<8:
    if not k32.WaitForDebugEvent(C.byref(de),500): continue
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        base=int(de.u.CreateProcessInfo.lpBaseOfImage)
        set_bp(base+0x55ef8)  # getchar
        set_bp(base+0x14c93)  # load char
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord
        ec=er.ExceptionCode&0xffffffff
        if ec==0x80000003:
            ctx=CTX(); ctx.ContextFlags=0x10001F
            C.windll.kernel32.GetThreadContext(pi.hThread,C.byref(ctx))
            rip=int(ctx.Rip)
            hit=rip if rip in bps else (rip-1 if rip-1 in bps else None)
            if hit:
                clear_bp(hit); ctx.Rip=hit
                rva=hit-base
                if rva==0x55ef8:
                    cur=u32(read(base+0x6cbc8,4))
                    print("getchar cursor",hex(cur))
                    if cur: print(" ",read(cur,40).decode("utf-16le","replace")[:50])
                    print(" fbe0",read(base+0x6cbe0,20).hex())
                    print(" 71320",read(base+0x71320,40).decode("utf-16le","replace")[:50])
                elif rva==0x14c93:
                    n+=1
                    if n<=5:
                        raw=read(ctx.Rdi,8)
                        ch=int.from_bytes(raw[:2],"little")
                        print("LOAD",n,"rdi",hex(ctx.Rdi),"ch",hex(ch),repr(chr(ch) if 32<=ch<127 else ch))
                    if n>=8:
                        k32.TerminateProcess(pi.hProcess,1); break
                C.windll.kernel32.SetThreadContext(pi.hThread,C.byref(ctx))
                ctx=CTX(); ctx.ContextFlags=0x10001F
                C.windll.kernel32.GetThreadContext(pi.hThread,C.byref(ctx))
                ctx.EFlags|=0x100
                C.windll.kernel32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif ec==0x80000004:
            for a in list(bps): set_bp(a)
        elif ec==0xC0000005:
            print("AV"); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,df.DBG_CONTINUE)
k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)
