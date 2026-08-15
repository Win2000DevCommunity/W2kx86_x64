import ctypes as C, struct, time, sys, os, pathlib
sys.path.insert(0, ".")
import dbg_fault as df
from x86x64.translator._healing import HealingMixin
import pefile
df.suppress_fault_ui()
k32=df.k32
CONTEXT_ALL=df.CONTEXT_FULL|df.CONTEXT_AMD64|0x10

def dword(h,a):
    b=(C.c_ubyte*4)(); n=C.c_size_t()
    if not k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(n)): return None
    return struct.unpack_from("<I", bytes(b))[0]

class T(HealingMixin): pass
pe_bytes=bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e=struct.unpack_from("<I", pe_bytes, 0x3C)[0]
ns=struct.unpack_from("<H", pe_bytes, e+6)[0]; so=struct.unpack_from("<H", pe_bytes, e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe_bytes[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe_bytes, o+8); break
blob=bytearray(pe_bytes[rp:rp+rs])
t=T(); t._cmd_no_hacks=True; t._pure_cave_cursor=0; t.new_base=0x80000000
ppe=pefile.PE(data=bytes(pe_bytes))
t._iat_name_to_new_rva={}
for exp in ppe.DIRECTORY_ENTRY_IMPORT:
    for imp in exp.imports:
        if imp.name and imp.address:
            t._iat_name_to_new_rva[(exp.dll.decode(errors="replace"), imp.name.decode(errors="replace"))]=imp.address-0x80000000
t._pure_fix_missing_push_ecx_local_before_csr(blob)
t._pure_fix_stale_getlasterror_exitprocess1(blob)
t._pure_fix_exitprocess_wrapper_via_terminate(blob)
off=0x1EA3C-0x1000
orig=blob[off]
blob[off]=0xCC
pe_bytes[rp:rp+rs]=blob[:rs]
path=pathlib.Path("build_univ257/cmd_probe_int3.exe"); path.write_bytes(pe_bytes)

EXE=os.path.abspath(str(path))
cmd=f'"{EXE}" /c echo w2ktest'
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True; hits=0
de=df.DEBUG_EVENT(); t0=time.time()
while time.time()-t0<8 and hits<12:
    if not k32.WaitForDebugEvent(C.byref(de),200): continue
    code=de.dwDebugEventCode
    if code==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif code==1:
        er=de.u.Exception.ExceptionRecord
        ec=er.ExceptionCode&0xFFFFFFFF
        ea=(er.ExceptionAddress or 0)
        rva=(ea-base)&0xffffffffffffffff if base else 0
        if ec==0x80000003:
            if init and rva != 0x1EA3C:
                init=False
            elif rva == 0x1EA3C:
                st=dword(pi.hProcess,base+0x5BE00)
                fa=dword(pi.hProcess,base+0x5BAE0)
                sc=dword(pi.hProcess,base+0x58F64)
                fa_s = hex(fa) if fa is not None else None
                print(f"hit#{hits} sticky={st} fae0={fa_s} SC={sc}", flush=True)
                hits+=1
                # restore orig, set RF, re-plant via after continue using write of CC after step
                buf=(C.c_ubyte*1)(orig); wn=C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+0x1EA3C), buf, 1, C.byref(wn))
                ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
                k32.GetThreadContext(pi.hThread,C.byref(ctx))
                ctx.EFlags |= 0x10000  # RF to skip once? actually for int3 need rip on int3 and restore
                ctx.Dr0 = base+0x1EA3C; ctx.Dr7=0x1
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif ec==0x80000004:
            # HW hit after restore - log if needed, re-plant soft bp
            buf=(C.c_ubyte*1)(0xCC); wn=C.c_size_t()
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+0x1EA3C), buf, 1, C.byref(wn))
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            ctx.Dr6=0; ctx.EFlags|=0x10000
            k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif ec==0xC0000005:
            print("AV", hex(rva)); break
    elif code==5:
        print("EXIT", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,0x10002)
print("done hits", hits)
k32.TerminateProcess(pi.hProcess,1)
