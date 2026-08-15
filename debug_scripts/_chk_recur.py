import ctypes as C, os, sys, time, struct
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df

k32 = df.k32
exe = os.path.abspath(r"build_univ34\cmd_pure.exe")
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(None, cmdline, None, None, False, 1, None, None, C.byref(si), C.byref(pi))

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", C.POINTER(EXCEPTION_RECORD)), ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", wintypes.DWORD), ("ExceptionInformation", C.c_ulonglong * 15),
]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]
class DEBUG_EVENT(C.Structure):
    class U(C.Union):
        _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("raw", C.c_byte * 160)]
    _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD), ("u", U)]

ev = DEBUG_EVENT()
base = None
from collections import Counter
hits = Counter()
deadline = time.time() + 3
# single-step briefly counting main RIP
# simpler: on stack overflow, dump return chain from context

while time.time() < deadline:
    if not k32.WaitForDebugEvent(C.byref(ev), 200):
        continue
    cont = 0x10002
    code = ev.dwDebugEventCode
    if code == 3:
        base = struct.unpack_from("<Q", bytes(ev.u.raw), 24)[0]
        print("base", hex(base))
    elif code == 1:
        er = ev.u.Exception.ExceptionRecord
        ec = er.ExceptionCode
        ea = int(er.ExceptionAddress or 0)
        if ec == 0xC00000FD or ec == 0xC0000005:
            ctx = df.CONTEXT(); ctx.ContextFlags = 0x10001F
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            k32.GetThreadContext(th, C.byref(ctx))
            print(f"FAULT {hex(ec)} RIP={hex(ctx.Rip)} RSP={hex(ctx.Rsp)}")
            # walk stack for main-image returns
            for i in range(0, 0x800, 8):
                v = df.read_u64(pi.hProcess, ctx.Rsp + i)
                if v and base <= v < base + 0x100000:
                    print(f"  rsp+{i:#x} = main+{v-base:#x}")
            k32.CloseHandle(th)
            break
        if ec == 0x80000003 and base and base <= ea < base + 0x100000:
            pass
    elif code == 5:
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

k32.TerminateProcess(pi.hProcess, 1)
