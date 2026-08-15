import struct, pathlib, sys, ctypes as C, os
from ctypes import wintypes
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ228/cmd_combo.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== 18b40 / more echo ====")
for i, insn in enumerate(md.disasm(code[0x18b40-va:0x18b40-va+0xc0], ib+0x18b40)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>45: break

out=bytearray(code)
bps={}
for rva in [0x189c4,0x189ee,0x189f9,0x18b40,0x18a13,0x18c87]:
    bps[rva]=out[rva-va]; out[rva-va]=0xCC
pe2=bytearray(pe); pe2[rp:rp+rs]=out
bp=os.path.abspath(r"build_univ228\echo_bp2.exe"); open(bp,"wb").write(pe2)
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
                print(f"hit {rva:#x} rax={ctx.Rax:#x} rbx={ctx.Rbx:#x} rcx={ctx.Rcx:#x}")
                if rva==0x189c4:
                    node=ctx.Rcx
                    raw=df.read_process_mem(pi.hProcess, node, 0x40)
                    p38=struct.unpack_from("<I", raw, 0x38)[0]
                    print(f"  node={node:#x} [+38]={p38:#x}")
                    if p38>0x10000:
                        s=df.read_process_mem(pi.hProcess, p38, 80)
                        print(f"  argv raw={s[:40].hex()}")
                        try: print(f"  argv={s.decode('utf-16le','replace').split(chr(0))[0]!r}")
                        except: pass
                        # also dump as pointer table?
                        for i in range(0, 32, 4):
                            v=struct.unpack_from("<I", s, i)[0]
                            print(f"  argv+{i}={v:#x}")
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            print("AV",hex(ctx.Rip),"rax",hex(ctx.Rax),"rbx",hex(ctx.Rbx),"rbp",hex(ctx.Rbp),"acc",hex(er.ExceptionInformation[1] if er.NumberParameters>1 else 0))
            k32.CloseHandle(ht); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
