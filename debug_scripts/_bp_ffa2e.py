import struct, pathlib, sys, ctypes as C, os
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df
exe=os.path.abspath(r"build_univ228\cmd_combo.exe")
pe=bytearray(open(exe,"rb").read())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]
so=struct.unpack_from("<H",pe,e+20)[0]
sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
out=bytearray(pe[rp:rp+rs])
rva=0x1eb78
orig=out[rva-va]; out[rva-va]=0xCC
# also after homes written - at push rsi
rva2=0x1eb8c
orig2=out[rva2-va]; out[rva2-va]=0xCC
pe2=bytearray(pe); pe2[rp:rp+rs]=out
bp=os.path.abspath(r"build_univ228\ffa2e_bp.exe"); open(bp,"wb").write(pe2)
k32=df.k32
k32.OpenThread.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
k32.OpenThread.restype=wintypes.HANDLE
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmdline=C.create_unicode_buffer(f'"{bp}" /c echo w2ktest')
assert k32.CreateProcessW(None,cmdline,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.path.dirname(bp),C.byref(si),C.byref(pi))
while True:
    ev=df.DEBUG_EVENT()
    if not k32.WaitForDebugEvent(C.byref(ev),20000):
        print("timeout"); break
    cont=df.DBG_CONTINUE
    if ev.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=ev.u.Exception.ExceptionRecord
        if er.ExceptionCode==0x80000003:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            rip=ctx.Rip-1; r=(rip-ib)&0xffffffff
            if r in (rva,rva2):
                o=orig if r==rva else orig2
                buf=(C.c_ubyte*1)(o); wr=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess,C.c_void_p(rip),buf,1,C.byref(wr))
                ctx.Rip=rip; k32.SetThreadContext(ht,C.byref(ctx))
                print(f"hit {r:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} rsp={ctx.Rsp:#x}")
                for off in range(0, 0x30, 8):
                    v=df.read_u64(pi.hProcess, ctx.Rsp+off)
                    print(f"  [rsp+{off:#x}]={v:#x}")
                if r==rva2:
                    break
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            print("AV"); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
