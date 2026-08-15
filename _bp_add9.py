import ctypes as C, sys, struct
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as D
D.suppress_fault_ui()
k32 = D.k32

pe = bytearray(Path("build_univ98/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
nsec = struct.unpack_from("<H", pe, e+6)[0]
osz = struct.unpack_from("<H", pe, e+20)[0]
soff = e+24+osz
for i in range(nsec):
    off = soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
rmap={}
for line in Path("build_univ98/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)
add9 = rmap[0xadd9]
file_off = rp + (add9 - va)
orig = pe[file_off]
pe[file_off] = 0xCC
tmp = Path("build_univ98/cmd_bp2.exe")
tmp.write_bytes(pe)

exe=str(tmp.resolve())
si=D.STARTUPINFO(); si.cb=C.sizeof(si); pi=D.PROCESS_INFORMATION()
cmd='"%s" /c echo w2ktest' % exe
assert k32.CreateProcessW(exe, cmd, None,None,False,D.DEBUG_ONLY_THIS_PROCESS,None,str(tmp.parent),C.byref(si),C.byref(pi))
base=0; de=D.DEBUG_EVENT(); out=[]; hits=0
c8d8=0x6a8d8
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 30000):
        out.append("timeout"); break
    code=de.dwDebugEventCode
    if code==D.CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage or 0
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code==D.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code==D.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord
        ecode=er.ExceptionCode & 0xFFFFFFFF
        addr=er.ExceptionAddress or 0
        if ecode==0x80000003 and base and ((addr-base)&0xffffffffffffffff)==add9:
            ctx=D.CONTEXT(); ctx.ContextFlags=D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            hits+=1
            # return addr
            ret=D.read_u64(pi.hProcess, ctx.Rsp)
            out.append("ADD9#%d RCX=%#x RDX=%#x RBX=%#x c8d8=%#x ret=%#x" % (
                hits, ctx.Rcx, ctx.Rdx, ctx.Rbx, D.read_u64(pi.hProcess, base+c8d8), (ret-base) if ret and base else 0))
            written=C.c_size_t(); buf=C.c_ubyte(orig)
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+add9), C.byref(buf), 1, C.byref(written))
            ctx.Rip = base+add9
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            if hits>=8:
                k32.TerminateProcess(pi.hProcess,1); break
        elif ecode==0xC0000005:
            ctx=D.CONTEXT(); ctx.ContextFlags=D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            out.append("AV rip=%#x RSI=%#x rbp10=%#x rbp18=%#x" % (
                addr-base, ctx.Rsi, D.read_u64(pi.hProcess, ctx.Rbp+0x10), D.read_u64(pi.hProcess, ctx.Rbp+0x18)))
            k32.TerminateProcess(pi.hProcess,1); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, D.DBG_CONTINUE)
Path("_bp_out.txt").write_text("\n".join(out), encoding="utf-8")
print("hits", hits, file=sys.stderr)
