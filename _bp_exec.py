import struct, pathlib, subprocess, sys, ctypes as C, os
from ctypes import wintypes
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, ".")
import dbg_fault as df

# Rebuild combined patch: diamond chain + jne
pe = bytearray(pathlib.Path("build_univ228/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])
chain = {0x3624d:(0x1d35c,0x1d4f4), 0x1d4f4:(0x1d4f4,0x1d534),
         0x1d534:(0x1d534,0x1d574), 0x1d574:(0x1d574,0x1d5b4)}
for e0va,(a,b) in chain.items():
    e0=e0va-va
    struct.pack_into("<Q", blob, e0+19, ib+a)
    struct.pack_into("<Q", blob, e0+29, ib+b)
at=0x17c48-va
struct.pack_into("<i", blob, at+2, 0x17c71-(0x17c48+6))
pe[rp:rp+rs]=blob
outp=pathlib.Path("build_univ228/cmd_combo.exe"); outp.write_bytes(pe)

# BP trace execute path
out=bytearray(pe[rp:rp+rs])
bps={}
watch=[0x17c71,0x17ca2,0x17cdd,0x17d62,0x14e5e,0x149ac,0x1a00c,0xd583,0xc59c]
for rva in watch:
    bps[rva]=out[rva-va]; out[rva-va]=0xCC
pe2=bytearray(pe); pe2[rp:rp+rs]=out
bp_exe=os.path.abspath(r"build_univ228\cmd_combo_bp.exe"); open(bp_exe,"wb").write(pe2)

k32=df.k32
k32.OpenThread.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
k32.OpenThread.restype=wintypes.HANDLE
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmdline=C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
assert k32.CreateProcessW(None,cmdline,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.path.dirname(bp_exe),C.byref(si),C.byref(pi))
hits=[]
while len(hits)<40:
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
                hits.append((rva,ctx.Rax,ctx.Rcx,ctx.Rdx,ctx.Rbx,ctx.Rsi,ctx.Rdi,ctx.Rbp))
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            print("AV rip",hex(ctx.Rip),"rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"rdx",hex(ctx.Rdx))
            print("rbx",hex(ctx.Rbx),"rsi",hex(ctx.Rsi),"rdi",hex(ctx.Rdi),"rbp",hex(ctx.Rbp),"rsp",hex(ctx.Rsp))
            print("info0",hex(er.ExceptionInformation[0] if er.NumberParameters>0 else 0),
                  "info1",hex(er.ExceptionInformation[1] if er.NumberParameters>1 else 0))
            for off in range(0,0x40,8):
                v=df.read_u64(pi.hProcess,ctx.Rsp+off)
                tag=f" t={(v-ib):#x}" if ib<=v<ib+0x100000 else ""
                print(f"  [rsp+{off:#x}]={v:#x}{tag}")
            k32.CloseHandle(ht); break
        else:
            if er.ExceptionCode not in (0x80000004,):
                cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",ev.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
print("---hits---")
for h in hits:
    rva,rax,rcx,rdx,rbx,rsi,rdi,rbp=h
    print(f"hit {rva:#x} rax={rax:#x} rcx={rcx:#x} rdx={rdx:#x} rbx={rbx:#x} rsi={rsi:#x} rdi={rdi:#x}")
