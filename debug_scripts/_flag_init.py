import ctypes as C
from ctypes import wintypes
import time

k32 = C.WinDLL("kernel32", use_last_error=True)
DEBUG_PROCESS=1; CREATE_PROCESS_DEBUG_EVENT=3; EXCEPTION_DEBUG_EVENT=1
EXIT_PROCESS_DEBUG_EVENT=5; EXCEPTION_BREAKPOINT=0x80000003
DBG_CONTINUE=0x10002

class PROCESS_INFORMATION(C.Structure):
    _fields_=[("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),
              ("dwProcessId",wintypes.DWORD),("dwThreadId",wintypes.DWORD)]
class STARTUPINFOW(C.Structure):
    _fields_=[("cb",wintypes.DWORD)]+[("x",wintypes.DWORD)]*8+[
        ("dwFlags",wintypes.DWORD),("wShowWindow",wintypes.WORD),
        ("cbReserved2",wintypes.WORD),("lpReserved2",C.c_void_p),
        ("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),
        ("hStdError",wintypes.HANDLE)]
class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_=[("ExceptionCode",wintypes.DWORD),("ExceptionFlags",wintypes.DWORD),
    ("ExceptionRecord",C.POINTER(EXCEPTION_RECORD)),("ExceptionAddress",C.c_void_p),
    ("NumberParameters",wintypes.DWORD),("ExceptionInformation",C.c_ulonglong*15)]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_=[("ExceptionRecord",EXCEPTION_RECORD),("dwFirstChance",wintypes.DWORD)]
class CREATE_PROCESS_DEBUG_INFO(C.Structure):
    _fields_=[("hFile",wintypes.HANDLE),("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),
              ("lpBaseOfImage",C.c_void_p),("dwDebugInfoFileOffset",wintypes.DWORD),
              ("nDebugInfoSize",wintypes.DWORD),("lpThreadLocalBase",C.c_void_p),
              ("lpStartAddress",C.c_void_p),("lpImageName",C.c_void_p),("fUnicode",wintypes.WORD)]
class DEBUG_EVENT_U(C.Union):
    _fields_=[("Exception",EXCEPTION_DEBUG_INFO),("CreateProcessInfo",CREATE_PROCESS_DEBUG_INFO),("pad",C.c_byte*160)]
class DEBUG_EVENT(C.Structure):
    _fields_=[("dwDebugEventCode",wintypes.DWORD),("dwProcessId",wintypes.DWORD),
              ("dwThreadId",wintypes.DWORD),("u",DEBUG_EVENT_U)]

exe=r"build_univ257\cmd_probe_all.exe"
cmd='"'+exe+'" /c echo w2ktest'
si=STARTUPINFOW(); si.cb=C.sizeof(si); pi=PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,DEBUG_PROCESS,None,None,C.byref(si),C.byref(pi))
base=0; init=True; flagged=False; t0=time.time()
de=DEBUG_EVENT()
while time.time()-t0 < 20:
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    st=DBG_CONTINUE
    if de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage
    elif de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT:
        code=de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
        if code==EXCEPTION_BREAKPOINT and init:
            init=False
            # right after system BP ? set flag before cmd main
            val=(C.c_uint32*1)(1); n=C.c_size_t()
            ok=k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base+0x58F64), val, 4, C.byref(n))
            # also try 0x58F60 (/k)
            print("flag@init", ok, "base", hex(base))
            flagged=True
        elif code==0xC0000005:
            addr=de.u.Exception.ExceptionRecord.ExceptionAddress or 0
            print("AV", hex((addr-base)&0xffffffffffffffff)); break
    elif de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT:
        print("EXITED", round(time.time()-t0,2)); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
else:
    print("TIMEOUT")
    k32.TerminateProcess(pi.hProcess,1)
