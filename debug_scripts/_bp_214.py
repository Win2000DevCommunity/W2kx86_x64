import ctypes as C, sys, time, struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, ".")
from dbg_fault import *

exe = str(Path("build_univ214/cmd_pure.exe").resolve())
cwd = str(Path("build_univ214").resolve())
# find helper / seed store
data = open(exe, "rb").read()
import pefile
pe = pefile.PE(exe)
for s in pe.sections:
    if s.Name.startswith(b".text"):
        text = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
sticky = struct.pack("<Q", 0x8005be00)
# helper starts with movabs sticky; cmp [r11],2
tip = b"\x49\xbb" + sticky + b"\x41\x83\x3b\x02"
hoff = text.find(tip)
print("helper blob", hex(hoff), "rva", hex(0x1000+hoff) if hoff>=0 else None)
md = Cs(CS_ARCH_X86, CS_MODE_64)
if hoff >= 0:
    for i in md.disasm(text[hoff:hoff+0x120], 0x80001000+hoff):
        print(f"  {i.address:x}: {i.mnemonic} {i.op_str}")
        if i.address > 0x80001000+hoff+0x100:
            break

si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
k32.CreateProcessW(exe, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd, C.byref(si), C.byref(pi))
base=None; de=DEBUG_EVENT(); t0=time.time()
bps = {}
if hoff >= 0:
    bps[0x1000+hoff] = "helper"
    # find sticky=1 store: c7 03 01 00 00 00 after seed_done movabs near end of helper
    # and after_parse
bps[0x1ea90] = "after_parse"
bps[0x1d7f4] = "disp"
bps[0x44947] = "movzx"
orig={}; rearm=None; hits=0; chars=[]
while time.time()-t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(de), 400):
        continue
    st = DBG_CONTINUE
    if de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        for rva in list(bps):
            o=C.c_ubyte(); n=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base+rva), C.byref(o),1,C.byref(n))
            orig[rva]=o.value
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+rva), C.byref(C.c_ubyte(0xCC)),1,C.byref(n))
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; ecode=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
        ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL; k32.GetThreadContext(pi.hThread, C.byref(ctx))
        if ecode==0x80000003 and base and (addr-base) in bps:
            rva=addr-base; hits+=1
            n=C.c_size_t(); stv=C.c_uint32(); fa=C.c_uint32(); cur=C.c_uint32()
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5be00),C.byref(stv),4,C.byref(n))
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5bae0),C.byref(fa),4,C.byref(n))
            k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5bbc8),C.byref(cur),4,C.byref(n))
            extra=""
            if rva==0x44947:
                w=C.c_uint16(); k32.ReadProcessMemory(pi.hProcess,C.c_void_p(ctx.Rcx),C.byref(w),2,C.byref(n))
                ch=w.value; chars.append(ch); extra=" ch=%s"%(chr(ch) if 32<=ch<127 else hex(ch))
            if hits<=50 or rva in (0x1ea90,0x1d7f4) or bps[rva]=="helper":
                print("%d %s sticky=%d fae0=%#x fbc8=%#x eax=%#x%s"%(hits,bps[rva],stv.value,fa.value,cur.value,ctx.Rax&0xffffffff,extra))
            if bps[rva]=="helper" and hits<=3:
                raw=(C.c_char*64)(); k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x60320),raw,64,C.byref(n))
                b=bytes(raw); s=""
                for i in range(0,40,2):
                    ch=struct.unpack_from("<H",b,i)[0]
                    if ch==0: break
                    s+=chr(ch) if 32<=ch<127 else "[%#x]"%ch
                print("  buf:",s)
            k32.WriteProcessMemory(pi.hProcess,C.c_void_p(addr),C.byref(C.c_ubyte(orig[rva])),1,C.byref(n))
            ctx.Rip=addr; ctx.EFlags|=0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); rearm=rva
            if hits>=80: break
            continue
        if ecode==0x80000004 and rearm is not None:
            n=C.c_size_t()
            for rva in bps:
                k32.WriteProcessMemory(pi.hProcess,C.c_void_p(base+rva),C.byref(C.c_ubyte(0xCC)),1,C.byref(n))
            ctx.EFlags&=~0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); rearm=None
        elif ecode in (0xC00000FD,0xC0000005):
            print("fault",hex(ecode),hex(addr-base if base else addr)); break
        elif ecode not in (0x80000003,0x80000004):
            st=DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st)
k32.TerminateProcess(pi.hProcess,1)
s="".join(chr(c) if 32<=c<127 else ("[LF]" if c==10 else ("[CR]" if c==13 else "[%#x]"%c)) for c in chars)
print("stream:",s); print("hits",hits)
