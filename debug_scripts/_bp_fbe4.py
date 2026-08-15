from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib, sys, ctypes as C, os
from ctypes import wintypes
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
print("==== 1e5dd ====")
for i, insn in enumerate(md.disasm(code[0x1e5dd-va:0x1e5dd-va+0x80], ib+0x1e5dd)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>35: break

# BP fbe4 path
out=bytearray(code)
bps={}
for rva in [0x1e2b4, 0x1e31d, 0x1e324, 0x1e5dd, 0x1e352]:
    bps[rva]=out[rva-va]; out[rva-va]=0xCC
pe2=bytearray(pe); pe2[rp:rp+rs]=out
bp=os.path.abspath(r"build_univ228\fbe4_bp.exe"); open(bp,"wb").write(pe2)
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
                print(f"hit {rva:#x} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} rbx={ctx.Rbx:#x} rdi={ctx.Rdi:#x}")
                if rva==0x1e5dd:
                    break
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            ht=k32.OpenThread(0x1F03FF,False,ev.dwThreadId)
            ctx=df.get_thread_context(ht)
            print("AV",hex(ctx.Rip),hex(ctx.Rax),hex(ctx.Rcx))
            k32.CloseHandle(ht); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
