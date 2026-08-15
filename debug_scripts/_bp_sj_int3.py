import ctypes as C, struct, time, sys, os, pathlib
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32=df.k32
CONTEXT_ALL=df.CONTEXT_FULL|df.CONTEXT_AMD64|0x10

# Patch INT3 at 14974
pe=bytearray(pathlib.Path("build_univ258/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I", pe, 0x3C)[0]
ns=struct.unpack_from("<H", pe, e+6)[0]; so=struct.unpack_from("<H", pe, e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
off=0x14974-va
orig=pe[rp+off]
pe[rp+off]=0xCC
path=pathlib.Path("build_univ258/cmd_probe_sj.exe"); path.write_bytes(pe)

EXE=os.path.abspath(str(path))
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(f'"{EXE}"'),None,None,False,
                    df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True; hits=0
de=df.DEBUG_EVENT(); t0=time.time()
while time.time()-t0<5 and hits<30:
    if not k32.WaitForDebugEvent(C.byref(de),200): continue
    code=de.dwDebugEventCode
    if code==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif code==1:
        er=de.u.Exception.ExceptionRecord
        ec=er.ExceptionCode&0xFFFFFFFF
        ea=er.ExceptionAddress or 0
        rva=(ea-base)&0xffffffffffffffff if base else 0
        if ec==0x80000003:
            if rva==0x14974:
                ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                # read return addr
                buf=(C.c_ubyte*8)(); n=C.c_size_t()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 8, C.byref(n))
                ret=int.from_bytes(bytes(buf),"little")
                ret_rva=(ret-base)&0xffffffffffffffff
                print(f"#{hits} rsp={ctx.Rsp:#x} ret={ret_rva:#x} rcx={ctx.Rcx:#x}")
                hits+=1
                # restore byte, single-step, re-plant
                wb=(C.c_ubyte*1)(orig); wn=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+0x14974), wb, 1, C.byref(wn))
                ctx.EFlags|=0x100  # TF trap flag for single step
                ctx.Dr0=0; ctx.Dr7=0
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif init:
                init=False
        elif ec==0x80000004:
            # re-plant int3
            wb=(C.c_ubyte*1)(0xCC); wn=C.c_size_t()
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+0x14974), wb, 1, C.byref(wn))
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.EFlags&=~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif ec in (0xC00000FD, 0xC0000005):
            print("EX", hex(ec), hex(rva), "after", hits, "hits"); break
    elif code==5:
        print("EXIT"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x10002)
print("total hits", hits)
k32.TerminateProcess(pi.hProcess,1)
