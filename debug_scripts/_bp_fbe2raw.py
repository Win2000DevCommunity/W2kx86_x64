import ctypes as C, sys, time
from pathlib import Path
sys.path.insert(0,".")
from dbg_fault import *

exe=str(Path("build_univ201x/cmd_pure.exe").resolve())
cwd=str(Path("build_univ201x").resolve())
si=STARTUPINFO(); si.cb=C.sizeof(si); pi=PROCESS_INFORMATION()
k32.CreateProcessW(exe, C.create_unicode_buffer('"%s" /c echo w2ktest'%exe), None,None,False,
  DEBUG_ONLY_THIS_PROCESS, None, cwd, C.byref(si), C.byref(pi))
base=None; de=DEBUG_EVENT(); hits=0; t0=time.time(); orig=None; rearm=False
while time.time()-t0<8:
  if not k32.WaitForDebugEvent(C.byref(de),500):
    continue
  st=DBG_CONTINUE
  if de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT:
    base=de.u.CreateProcessInfo.lpBaseOfImage
    wrote=C.c_size_t(); o=C.c_ubyte()
    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base+0x448cb), C.byref(o),1,C.byref(wrote)); orig=o.value
    k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+0x448cb), C.byref(C.c_ubyte(0xCC)),1,C.byref(wrote))
    if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
  elif de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT:
    er=de.u.Exception.ExceptionRecord; ecode=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
    ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL; k32.GetThreadContext(pi.hThread, C.byref(ctx))
    if ecode==0x80000003 and base and addr==base+0x448cb:
      hits+=1
      n=C.c_size_t(); buf=(C.c_ubyte*64)()
      k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base+0x5bbe2), buf, 64, C.byref(n))
      raw=bytes(buf)
      dw=C.c_uint32(); k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5bbc8),C.byref(dw),4,C.byref(n))
      stv=C.c_uint32(); k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5be00),C.byref(stv),4,C.byref(n))
      fa=C.c_uint32(); k32.ReadProcessMemory(pi.hProcess,C.c_void_p(base+0x5bae0),C.byref(fa),4,C.byref(n))
      print("hit%d fbc8=%#x sticky=%d fae0=%#x" % (hits, dw.value, stv.value, fa.value))
      print(" raw", raw[:48].hex())
      print(" u16", [raw[i]| (raw[i+1]<<8) for i in range(0,32,2)])
      wrote=C.c_size_t()
      k32.WriteProcessMemory(pi.hProcess,C.c_void_p(base+0x448cb),C.byref(C.c_ubyte(orig)),1,C.byref(wrote))
      ctx.Rip=base+0x448cb; ctx.EFlags|=0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); rearm=True
      if hits>=5: break
    elif ecode==0x80000004 and rearm:
      wrote=C.c_size_t(); k32.WriteProcessMemory(pi.hProcess,C.c_void_p(base+0x448cb),C.byref(C.c_ubyte(0xCC)),1,C.byref(wrote))
      ctx.EFlags&=~0x100; k32.SetThreadContext(pi.hThread,C.byref(ctx)); rearm=False
    elif ecode==0xC00000FD:
      print("SO"); break
    elif ecode==0xC0000005:
      st=DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
      if not de.u.Exception.dwFirstChance: break
    elif ecode not in (0x80000003,0x80000004):
      st=DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
  elif de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT:
    print("exit"); break
  k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,st)
k32.TerminateProcess(pi.hProcess,1)
