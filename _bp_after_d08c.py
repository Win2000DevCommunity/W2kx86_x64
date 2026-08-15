import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix2.exe")
IB=0x80000000
# WriteFile IAT and echo print path c5c0 area
pe=open(exe,"rb").read()
e=struct.unpack_from("<I",pe,0x3C)[0]; opt=e+24
imp_rva=struct.unpack_from("<I",pe,opt+112+8)[0]
def rva_to_off(rva):
    ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
    for i in range(ns):
        o=sec+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
off=rva_to_off(imp_rva); slots={}
while True:
    oft,td,fwd,name,ft=struct.unpack_from("<IIIII",pe,off)
    if oft==0 and name==0: break
    iat,idx=ft,0
    while True:
        io=rva_to_off(iat+idx*8)
        thunk=struct.unpack_from("<Q",pe,io)[0]
        if thunk==0: break
        if not (thunk>>(63)):
            nm=pe[rva_to_off(thunk)+2:].split(b"\0")[0]
            if nm in (b"WriteFile",b"WriteConsoleW",b"WriteConsoleA"):
                slots[nm.decode()]=IB+iat+idx*8
        idx+=1
    off+=20
print("slots", {k:hex(v) for k,v in slots.items()})

# Also BP c5c0 region after d08c returns
NAMES={IB+0xc59c:"after_d08c", IB+0xc631:"c514_alt", IB+0x18b86:"echo_ret"}
for s,n in slots.items():
    # can't BP IAT easily; BP call sites - skip
    pass

si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; hits=[]; de=df.DEBUG_EVENT(); heap_bps=0
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va,nm in NAMES.items():
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
                print("HIT", NAMES[bp], "rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx))
                hits.append(NAMES[bp])
            else:
                # ntdll heap int3 - continue to see if SEH recovers? or capture
                heap_bps+=1
                if heap_bps<=2:
                    ctx=df.get_thread_context(pi.hThread)
                    print("heap_int3", heap_bps, "rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"rax",hex(ctx.Rax))
                    # continue without terminating - might be first-chance
                    cont=df.DBG_CONTINUE
                else:
                    print("too many heap int3"); k32.TerminateProcess(pi.hProcess,1); break
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rip",hex(ctx.Rip),"hits",hits)
            if de.u.Exception.dwFirstChance and code==0xC0000005:
                cont=df.DBG_EXCEPTION_NOT_HANDLED  # let SEH try
            else:
                k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff),hits); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
