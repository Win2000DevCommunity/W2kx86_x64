import ctypes as C
from ctypes import wintypes
import time

k32 = C.WinDLL("kernel32", use_last_error=True)
DEBUG_PROCESS=1; CREATE_PROCESS_DEBUG_EVENT=3; EXCEPTION_DEBUG_EVENT=1
EXIT_PROCESS_DEBUG_EVENT=5; EXCEPTION_BREAKPOINT=0x80000003
EXCEPTION_SINGLE_STEP=0x80000004
DBG_CONTINUE=0x10002; CONTEXT_FULL=0x10001F

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
class CONTEXT(C.Structure):
    _fields_=[("P1Home",C.c_ulonglong),("P2Home",C.c_ulonglong),("P3Home",C.c_ulonglong),
              ("P4Home",C.c_ulonglong),("P5Home",C.c_ulonglong),("P6Home",C.c_ulonglong),
              ("ContextFlags",wintypes.DWORD),("MxCsr",wintypes.DWORD),
              ("SegCs",wintypes.WORD),("SegDs",wintypes.WORD),("SegEs",wintypes.WORD),
              ("SegFs",wintypes.WORD),("SegGs",wintypes.WORD),("SegSs",wintypes.WORD),
              ("EFlags",wintypes.DWORD),
              ("Dr0",C.c_ulonglong),("Dr1",C.c_ulonglong),("Dr2",C.c_ulonglong),
              ("Dr3",C.c_ulonglong),("Dr6",C.c_ulonglong),("Dr7",C.c_ulonglong),
              ("Rax",C.c_ulonglong),("Rcx",C.c_ulonglong),("Rdx",C.c_ulonglong),
              ("Rbx",C.c_ulonglong),("Rsp",C.c_ulonglong),("Rbp",C.c_ulonglong),
              ("Rsi",C.c_ulonglong),("Rdi",C.c_ulonglong),("R8",C.c_ulonglong),
              ("R9",C.c_ulonglong),("R10",C.c_ulonglong),("R11",C.c_ulonglong),
              ("R12",C.c_ulonglong),("R13",C.c_ulonglong),("R14",C.c_ulonglong),
              ("R15",C.c_ulonglong),("Rip",C.c_ulonglong)]

exe=r"build_univ257\cmd_probe_exit2.exe"
cmd='"'+exe+'" /c echo w2ktest'
si=STARTUPINFOW(); si.cb=C.sizeof(si); pi=PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,DEBUG_PROCESS,None,None,C.byref(si),C.byref(pi))
base=0; init=True
de=DEBUG_EVENT()
while k32.WaitForDebugEvent(C.byref(de), 0xFFFFFFFF):
    st=DBG_CONTINUE
    if de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage
        ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        ctx.Dr0=base+0x14818; ctx.Dr7=0x1
        k32.SetThreadContext(pi.hThread, C.byref(ctx))
    elif de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT:
        code=de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
        if code==EXCEPTION_BREAKPOINT and init:
            init=False
        elif code in (EXCEPTION_SINGLE_STEP, EXCEPTION_BREAKPOINT):
            ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if ctx.Dr6 & 1 or ctx.Rip==base+0x14818:
                buf=(C.c_char*8)(); n=C.c_size_t()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 8, C.byref(n))
                ret=int.from_bytes(buf[:8],"little")
                print("AC92 hit rcx=%#x ret=%#x" % (ctx.Rcx, (ret-base)&0xffffffffffffffff))
                k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            print("AV"); break
    elif de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT:
        print("exit without AC92 hit?"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
