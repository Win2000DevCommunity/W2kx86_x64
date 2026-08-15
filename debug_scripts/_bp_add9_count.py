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
tmp = Path("build_univ98/cmd_bp3.exe"); tmp.write_bytes(pe)

exe=str(tmp.resolve())
si=D.STARTUPINFO(); si.cb=C.sizeof(si); pi=D.PROCESS_INFORMATION()
cmd='"%s" /c echo w2ktest' % exe
assert k32.CreateProcessW(exe, cmd, None,None,False,D.DEBUG_ONLY_THIS_PROCESS,None,str(tmp.parent),C.byref(si),C.byref(pi))
base=0; de=D.DEBUG_EVENT(); out=[]; hits=0; nulls=0; nonnulls=0
# Keep BP armed: after continue, re-write INT3 at add9 AFTER single-stepping one insn
# Simpler approach: don't restore permanently — set TF, step one, re-arm INT3

def set_bp():
    written=C.c_size_t(); buf=C.c_ubyte(0xCC)
    k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+add9), C.byref(buf), 1, C.byref(written))

def clear_bp():
    written=C.c_size_t(); buf=C.c_ubyte(orig)
    k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+add9), C.byref(buf), 1, C.byref(written))

while True:
    if not k32.WaitForDebugEvent(C.byref(de), 60000):
        out.append("timeout hits=%d null=%d non=%d" % (hits,nulls,nonnulls)); break
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
            if ctx.Rcx == 0: nulls+=1
            else: nonnulls+=1
            if hits <= 15 or hits % 500 == 0:
                out.append("#%d RCX=%#x RDX=%#x" % (hits, ctx.Rcx, ctx.Rdx))
            clear_bp()
            ctx.Rip = base+add9
            ctx.EFlags |= 0x100  # single step
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif ecode==0x80000004:  # single-step
            set_bp()
            ctx=D.CONTEXT(); ctx.ContextFlags=D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif ecode==0xC0000005:
            out.append("AV after hits=%d null=%d non=%d RSI=%#x" % (hits,nulls,nonnulls, 
                D.CONTEXT() and 0))
            ctx=D.CONTEXT(); ctx.ContextFlags=D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            out.append("AV rip=%#x RSI=%#x" % (addr-base, ctx.Rsi))
            k32.TerminateProcess(pi.hProcess,1); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, D.DBG_CONTINUE)
Path("_bp_out.txt").write_text("\n".join(out), encoding="utf-8")
print("hits", hits, "null", nulls, "non", nonnulls, file=sys.stderr)
