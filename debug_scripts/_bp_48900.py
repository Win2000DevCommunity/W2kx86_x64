import sys, ctypes as C, struct, os
from ctypes import wintypes
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from x86x64.pe import PE32Image
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df

# x86: find cmp ebx, 10000 pattern near main loop
pe32=PE32Image(Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# search cmp reg, 0x10000 = 81 fb 00 00 01 00
for i in range(len(td)-6):
    if td[i:i+6] == bytes([0x81,0xfb,0x00,0x00,0x01,0x00]):
        rva=sec.vaddr+i
        print(f"cmp ebx,10000 at {rva:#x}")
        for insn in md32.disasm(td[i:i+0x40], pe32.image_base+rva):
            print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
            if insn.address > pe32.image_base+rva+0x30: break

# dump stack at 48900
exe = os.path.abspath(r"build_univ228\full.exe")
pe = bytearray(open(exe,"rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
out=bytearray(pe[rp:rp+rs])
rva=0x48900
orig=out[rva-va]; out[rva-va]=0xCC
pe[rp:rp+rs]=out
bp_exe=os.path.abspath(r"build_univ228\full_bp5.exe"); open(bp_exe,"wb").write(pe)
k32=df.k32
k32.OpenThread.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
k32.OpenThread.restype=wintypes.HANDLE
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmdline=C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
assert k32.CreateProcessW(None,cmdline,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.path.dirname(bp_exe),C.byref(si),C.byref(pi))
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
            if (rip-ib)&0xffffffff == rva:
                print(f"at 48900 rax={ctx.Rax:#x} rbx={ctx.Rbx:#x} rsp={ctx.Rsp:#x} rbp={ctx.Rbp:#x}")
                for off in range(0, 0x80, 8):
                    v=df.read_u64(pi.hProcess, ctx.Rsp+off)
                    tag=""
                    if ib<=v<ib+0x100000: tag=f" text={(v-ib):#x}"
                    print(f"  [rsp+{off:#x}]={v:#x}{tag}")
                # also dump [rbp] chain
                rbp=ctx.Rbp
                print(f"[rbp]={df.read_u64(pi.hProcess,rbp):#x} [rbp+8]={df.read_u64(pi.hProcess,rbp+8):#x}")
                break
            k32.CloseHandle(ht)
        elif er.ExceptionCode==0xC0000005:
            print("AV early"); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,cont)
