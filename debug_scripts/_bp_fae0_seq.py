import ctypes as C, struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32=df.k32
CONTEXT_ALL=df.CONTEXT_FULL|df.CONTEXT_AMD64|0x10

def dword(h,a):
    b=(C.c_ubyte*4)(); n=C.c_size_t()
    if not k32.ReadProcessMemory(h,C.c_void_p(a),b,4,C.byref(n)): return None
    return struct.unpack_from("<I", bytes(b))[0]

# Use pure with ecx+gle1+exitw only, BP on 4581E
from x86x64.translator._healing import HealingMixin
import pefile, pathlib
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
pe_bytes[rp:rp+rs]=blob[:rs]
path=pathlib.Path("build_univ257/cmd_probe_bp.exe"); path.write_bytes(pe_bytes)

EXE=os.path.abspath(str(path))
cmd=f'"{EXE}" /c echo w2ktest'
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,df.DEBUG_PROCESS,None,os.path.dirname(EXE),C.byref(si),C.byref(pi))
base=0; init=True
de=df.DEBUG_EVENT(); t0=time.time(); n=0
while time.time()-t0<5 and n<20:
    if not k32.WaitForDebugEvent(C.byref(de),100): continue
    code=de.dwDebugEventCode
    if code==3: base=de.u.CreateProcessInfo.lpBaseOfImage or 0
    elif code==1:
        ec=de.u.Exception.ExceptionRecord.ExceptionCode&0xFFFFFFFF
        if ec==0x80000003 and init:
            init=False
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            ctx.Dr0=base+0x4581E; ctx.Dr7=0x1
            k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif ec==0x80000004:
            ctx=df.CONTEXT(); ctx.ContextFlags=CONTEXT_ALL
            k32.GetThreadContext(pi.hThread,C.byref(ctx))
            st=dword(pi.hProcess,base+0x5BE00); fa=dword(pi.hProcess,base+0x5BAE0)
            print(f"waiter hit#{n} sticky={st} fae0={fa:#x}" if fa is not None else f"hit#{n}")
            n+=1
            ctx.Dr6=0; ctx.EFlags|=0x10000; k32.SetThreadContext(pi.hThread,C.byref(ctx))
    elif code==5: print("EXIT"); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,0x10002)
print("total hits", n)
k32.TerminateProcess(pi.hProcess,1)
