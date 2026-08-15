import ctypes as C, sys
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as D
D.suppress_fault_ui()
k32 = D.k32
exe = str(Path("build_univ98/cmd_pure.exe").resolve())
si = D.STARTUPINFO(); si.cb = C.sizeof(si)
pi = D.PROCESS_INFORMATION()
cmd = '"' + exe + '" /c echo w2ktest'
assert k32.CreateProcessW(exe, cmd, None, None, False, D.DEBUG_ONLY_THIS_PROCESS, None, str(Path("build_univ98").resolve()), C.byref(si), C.byref(pi))
base=0; de=D.DEBUG_EVENT(); status=D.DBG_CONTINUE; out=[]
# discover .data base from pe
pe=Path("build_univ98/cmd_pure.exe").read_bytes()
import struct
e=struct.unpack_from("<I",pe,0x3C)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
data_rva=None
for i in range(nsec):
    off=soff+i*40
    name=pe[off:off+8].split(b"\0",1)[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8)
    if name==b".data": data_rva=va
    if name==b".rsrc": rsrc_rva=va
out.append("data_rva=%#x rsrc=%#x" % (data_rva, rsrc_rva))
def cell(old_rva):
    return data_rva + (old_rva - 0x1c000)
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 20000):
        out.append("timeout"); break
    code=de.dwDebugEventCode
    if code==D.CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage or 0
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code==D.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code==D.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord
        if (er.ExceptionCode & 0xFFFFFFFF)==0xC0000005:
            ctx=D.CONTEXT(); ctx.ContextFlags=D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            out.append("AV rip=%#x fault=%#x RSI=%#x" % ((er.ExceptionAddress or 0)-base, er.ExceptionInformation[1], ctx.Rsi))
            out.append("RAX=%#x RCX=%#x RDX=%#x RBP=%#x" % (ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbp))
            for name,orva in [("c8d8",0x1c8d8),("fbc8",0x1fbc8),("21000",0x21000),("21820",0x21820),("faec",0x1faec)]:
                out.append("  [%s]=%#x" % (name, D.read_u64(pi.hProcess, base+cell(orva))))
            for off in (0x10,0x18):
                out.append("  [rbp%+#x]=%#x" % (off, D.read_u64(pi.hProcess, ctx.Rbp+off)))
            p=D.read_u64(pi.hProcess, base+cell(0x1c8d8))
            if p and p>0x10000:
                buf=(C.c_char*96)(); n=C.c_size_t()
                if k32.ReadProcessMemory(pi.hProcess, C.c_void_p(p), buf, 96, C.byref(n)):
                    raw=bytes(buf[:n.value])
                    out.append("cmdline_hex="+raw[:64].hex())
                    out.append("cmdline_u16="+raw.decode("utf-16-le","replace")[:60])
            # stack returns
            deep=(C.c_char*0x200)(); n=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), deep, 0x200, C.byref(n))
            raw=bytes(deep[:n.value])
            for k in range(0,len(raw)-8,8):
                q=int.from_bytes(raw[k:k+8],"little")
                if base <= q < base+0x200000:
                    out.append("  [rsp+%#x]=rva %#x" % (k, q-base))
                    if len([x for x in out if x.startswith("  [rsp")])>=8: break
            k32.TerminateProcess(pi.hProcess,1); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
Path("_snap_out.txt").write_text("\n".join(out), encoding="utf-8")
print("done", len(out), file=sys.stderr)
