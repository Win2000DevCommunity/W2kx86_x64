from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib, sys, ctypes as C, os
from ctypes import wintypes
from x86x64.pe import PE32Image
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
print("==== 17eea+ in 17eb0 ====")
for i, insn in enumerate(md.disasm(code[0x17eea-va:0x17eea-va+0x100], ib+0x17eea)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>50: break

# dump node at fb2b return
out=bytearray(code)
rva=0x1d963
orig=out[rva-va]; out[rva-va]=0xCC
pe2=bytearray(pe); pe2[rp:rp+rs]=out
bp=os.path.abspath(r"build_univ228\node_bp.exe"); open(bp,"wb").write(pe2)
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
            rip=ctx.Rip-1
            if (rip-ib)&0xffffffff==rva:
                buf=(C.c_ubyte*1)(orig); wr=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess,C.c_void_p(rip),buf,1,C.byref(wr))
                node=ctx.Rax
                print(f"node={node:#x}")
                raw=df.read_process_mem(pi.hProcess, node, 0x80)
                for off in range(0,0x80,8):
                    q=struct.unpack_from("<Q", raw, off)[0]
                    d0=struct.unpack_from("<I", raw, off)[0]
                    d1=struct.unpack_from("<I", raw, off+4)[0]
                    print(f"  +{off:#x}: q={q:#x} dwords={d0:#x},{d1:#x}")
                    # if looks like ptr to unicode
                    if 0x10000 < d0 < 0x90000000:
                        s=df.read_process_mem(pi.hProcess, d0, 32)
                        if s:
                            try:
                                t=s.decode("utf-16le","replace").split("\0")[0]
                                if t.isprintable() and len(t)>0:
                                    print(f"       -> {t!r}")
                            except: pass
                break
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            print("AV"); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
