import sys, ctypes as C, struct, os
sys.path.insert(0, ".")
import dbg_fault as df
exe = os.path.abspath(r"build_univ225\cmd_both.exe")
pe = bytearray(open(exe,"rb").read())
e=struct.unpack_from("<I",pe,0x3C)[0]; ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
 o=sec+i*40
 if pe[o:o+5]==b".text":
  vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
out=bytearray(pe[rp:rp+rs])
bps={}
for rva in (0x1e643,0x1d7f4,0x1d5b4,0x1c4fe,0x3624d,0x48bea):
 if 0<=rva-va<len(out):
  bps[rva]=out[rva-va]; out[rva-va]=0xCC
pe[rp:rp+rs]=out
open(r"build_univ225\cmd_both_bp.exe","wb").write(pe)
k32=df.k32; si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
assert k32.CreateProcessW(None,C.create_unicode_buffer('"%s" /c echo w2ktest'%os.path.abspath(r"build_univ225\cmd_both_bp.exe")),None,None,False,df.DEBUG_PROCESS,None,os.path.dirname(exe),C.byref(si),C.byref(pi))
class ER(C.Structure):
 pass
ER._fields_=[("ExceptionCode",C.c_ulong),("ExceptionFlags",C.c_ulong),("ExceptionRecord",C.c_void_p),("ExceptionAddress",C.c_void_p),("NumberParameters",C.c_ulong),("ExceptionInformation",C.c_ulonglong*15)]
class EDI(C.Structure):
 _fields_=[("ExceptionRecord",ER),("dwFirstChance",C.c_ulong)]
ev=df.DEBUG_EVENT(); ib=0x80000000; counts={r:0 for r in bps}
try:
 while k32.WaitForDebugEvent(C.byref(ev),20000):
  if ev.dwDebugEventCode==1:
   er=C.cast(C.byref(ev.u),C.POINTER(EDI)).contents
   ec=er.ExceptionRecord.ExceptionCode; ea=er.ExceptionRecord.ExceptionAddress or 0
   if ec==0x80000003 and (ea-ib) in bps:
    rva=ea-ib; counts[rva]+=1
    ctx=df.CONTEXT(); ctx.ContextFlags=0x10001F; k32.GetThreadContext(pi.hThread,C.byref(ctx))
    print("BP %05x #%d rax=%x rcx=%x [rbp+28]?"%(rva,counts[rva],ctx.Rax&0xffffffff,ctx.Rcx))
    # try read [rbp+0x28]
    import ctypes
    buf=(C.c_ubyte*8)(); br=C.c_size_t()
    if k32.ReadProcessMemory(pi.hProcess,C.c_void_p(ctx.Rbp+0x28),buf,8,C.byref(br)):
     print("  [rbp+28]=%x"%struct.unpack_from("<Q",bytes(buf))[0])
    b=(C.c_ubyte*1)(bps[rva]); wr=C.c_size_t()
    k32.WriteProcessMemory(pi.hProcess,C.c_void_p(ea),b,1,C.byref(wr))
    ctx.Rip=ea; k32.SetThreadContext(pi.hThread,C.byref(ctx))
    k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
    k32.WriteProcessMemory(pi.hProcess,C.c_void_p(ea),(C.c_ubyte*1)(0xCC),1,C.byref(wr))
    if sum(counts.values())>15: break
    continue
   if ec==0xC0000005:
    print("AV",hex(ea),{hex(k):v for k,v in counts.items()}); break
   if ec!=0x80000003: print("fault",hex(ec)); break
   k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE); continue
  elif ev.dwDebugEventCode==5: print("exit",counts); break
  k32.ContinueDebugEvent(ev.dwProcessId,ev.dwThreadId,df.DBG_CONTINUE)
finally:
 try: k32.TerminateProcess(pi.hProcess,1)
 except: pass
