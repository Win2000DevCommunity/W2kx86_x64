import ctypes as C
from ctypes import wintypes
import time

k32 = C.WinDLL("kernel32", use_last_error=True)
ntdll = C.WinDLL("ntdll")
DEBUG_PROCESS=1; CREATE_PROCESS_DEBUG_EVENT=3; EXCEPTION_DEBUG_EVENT=1
EXIT_PROCESS_DEBUG_EVENT=5; EXCEPTION_BREAKPOINT=0x80000003
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

exe=r"build_univ256\cmd_probe_echo3.exe"
cmd='"'+exe+'" /c echo w2ktest'
si=STARTUPINFOW(); si.cb=C.sizeof(si); pi=PROCESS_INFORMATION()
k32.CreateProcessW(None,C.create_unicode_buffer(cmd),None,None,False,DEBUG_PROCESS,None,None,C.byref(si),C.byref(pi))
base=0; init=True; t0=time.time()
de=DEBUG_EVENT()
# run 3 seconds
while time.time()-t0 < 3.5:
    if k32.WaitForDebugEvent(C.byref(de), 100):
        st=DBG_CONTINUE
        if de.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT:
            base=de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode==EXCEPTION_DEBUG_EVENT:
            code=de.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            if code==EXCEPTION_BREAKPOINT and init: init=False
            elif code==0xC0000005:
                print("AV"); k32.TerminateProcess(pi.hProcess,1); break
        elif de.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT:
            print("exited!"); break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

# Suspend and dump stack
k32.SuspendThread(pi.hThread)
ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL
k32.GetThreadContext(pi.hThread, C.byref(ctx))
print("RIP", hex(ctx.Rip), "rva", hex((ctx.Rip-base)&0xffffffffffffffff))
print("RCX", hex(ctx.Rcx), "RAX", hex(ctx.Rax), "RSP", hex(ctx.Rsp))
buf=(C.c_char*0x200)(); n=C.c_size_t()
k32.ReadProcessMemory(pi.hProcess, C.c_void_p(ctx.Rsp), buf, 0x200, C.byref(n))
print("stack main-image addrs:")
for off in range(0, 0x200, 8):
    q=int.from_bytes(buf[off:off+8],"little")
    if base <= q < base+0x200000:
        print(f"  rsp+{off:#x} = rva {q-base:#x}")
k32.TerminateProcess(pi.hProcess,1)
