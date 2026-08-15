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
bps={}; 
for rva in [0x17f9d,0x17fb0,0x27204]:
    bps[rva]=out[rva-va]; out[rva-va]=0xCC
pe2=bytearray(pe); pe2[rp:rp+rs]=out
bp=os.path.abspath(r"build_univ228\t0_bp.exe"); open(bp,"wb").write(pe2)
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
            rip=ctx.Rip-1; rva=(rip-ib)&0xffffffff
            if rva in bps:
                buf=(C.c_ubyte*1)(bps[rva]); wr=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess,C.c_void_p(rip),buf,1,C.byref(wr))
                ctx.Rip=rip; k32.SetThreadContext(ht,C.byref(ctx))
                print(f"hit {rva:#x} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} r8={ctx.R8:#x} rsi={ctx.Rsi:#x}")
                if ctx.Rdx>0x10000:
                    s=df.read_process_mem(pi.hProcess, ctx.Rdx, 64)
                    if s:
                        try: print("  rdx str", s.decode("utf-16le","replace").split("\0")[0][:50])
                        except: print("  rdx", s[:32].hex())
                if ctx.Rsi>0x10000:
                    raw=df.read_process_mem(pi.hProcess, ctx.Rsi, 0x40)
                    print("  rsi+0", hex(struct.unpack_from("<I",raw,0)[0]), "rsi+38", hex(struct.unpack_from("<I",raw,0x38)[0]))
                    p=struct.unpack_from("<I",raw,0x38)[0]
                    if p>0x10000:
                        s=df.read_process_mem(pi.hProcess, p, 64)
                        if s:
                            try: print("  [rsi+38]", s.decode("utf-16le","replace").split("\0")[0][:50])
                            except: pass
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            print("AV rip",hex(ctx.Rip),"rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"rdx",hex(ctx.Rdx),"rbp",hex(ctx.Rbp),"acc",hex(er.ExceptionInformation[1] if er.NumberParameters>1 else 0))
            for off in range(0,0x80,8):
                v=df.read_u64(pi.hProcess,ctx.Rsp+off)
                if ib<=v<ib+0x100000:
                    print(f"  [rsp+{off:#x}] text={(v-ib):#x}")
            k32.CloseHandle(ht); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",ev.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
