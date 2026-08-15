import ctypes as C, os
from ctypes import wintypes
from dbg_fault import *
exe = os.path.abspath("build_univ171_fixed/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base=None; orig={}
ReadProcessMemory=k32.ReadProcessMemory; WriteProcessMemory=k32.WriteProcessMemory
ReadProcessMemory.argtypes=[wintypes.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
WriteProcessMemory.argtypes=[wintypes.HANDLE,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
rpm=lambda a,n:(lambda b,m: bytes(b[:m.value]) if ReadProcessMemory(pi.hProcess,C.c_void_p(a),b,n,C.byref(m)) else b'')((C.c_char*n)(),C.c_size_t())
def wpm(a,d):
  buf=C.create_string_buffer(d); m=C.c_size_t(0); return WriteProcessMemory(pi.hProcess,C.c_void_p(a),buf,len(d),C.byref(m))
# re-plant every time at ret
ret_rva=0x1c783
de=DEBUG_EVENT(); first=0; n=0
while True:
  assert k32.WaitForDebugEvent(C.byref(de),60000)
  code=de.dwDebugEventCode; status=DBG_CONTINUE
  if code==CREATE_PROCESS_DEBUG_EVENT:
    base=de.u.CreateProcessInfo.lpBaseOfImage
    if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    ob=rpm(base+ret_rva,1); orig[ret_rva]=ob; wpm(base+ret_rva,b'\xcc')
    # also 474f4 and 474f9
    for r in (0x474f4, 0x474f9, 0x17c36):
      ob=rpm(base+r,1); orig[r]=ob; wpm(base+r,b'\xcc')
  elif code==LOAD_DLL_DEBUG_EVENT:
    if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
  elif code==EXIT_PROCESS_DEBUG_EVENT:
    print('exit'); break
  elif code==EXCEPTION_DEBUG_EVENT:
    er=de.u.Exception.ExceptionRecord; ecode=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress or 0
    if ecode==0x80000003:
      if first==0: first=1
      elif base and (addr-base) in orig:
        rva=addr-base; wpm(addr,orig[rva])
        ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL; k32.GetThreadContext(pi.hThread,C.byref(ctx))
        print('HIT',hex(rva),'rax',hex(ctx.Rax),'rsi',hex(ctx.Rsi),'rbx',hex(ctx.Rbx))
        n+=1
        ctx.Rip=addr; k32.SetThreadContext(pi.hThread,C.byref(ctx))
        # re-plant ret always
        if rva==ret_rva:
          wpm(base+ret_rva,b'\xcc')
        if n>20: 
          k32.TerminateProcess(pi.hProcess,1); break
    elif ecode==0xC0000005:
      print('AV'); k32.TerminateProcess(pi.hProcess,1); break
    elif ecode!=0x80000003: status=DBG_EXCEPTION_NOT_HANDLED
  k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
