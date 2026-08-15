import ctypes as C, os, sys, time, struct
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df
k32 = df.k32

def write_mem(proc, addr, data: bytes):
    n = C.c_size_t()
    buf = (C.c_char * len(data)).from_buffer_copy(data)
    return bool(k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, len(data), C.byref(n)))

exe = os.path.abspath(r"build_univ30\cmd_pure.exe")
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

ev = DEBUG_EVENT(); bp = orig = None; hit = False
deadline = time.time() + 12
while time.time() < deadline:
    if not k32.WaitForDebugEvent(C.byref(ev), 500):
        continue
    cont = 0x10002; code = ev.dwDebugEventCode
    if code == 3:
        base = struct.unpack_from("<Q", bytes(ev.u.raw), 24)[0]
        bp = base + 0x48de5
        orig = df.read_process_mem(pi.hProcess, bp, 1)
        print(f"base={base:#x} bp={bp:#x}")
        write_mem(pi.hProcess, bp, b"\xcc")
    elif code == 1:
        er = ev.u.Exception.ExceptionRecord
        ea = int(er.ExceptionAddress or 0); ec = er.ExceptionCode
        if ec == 0x80000003 and bp and ea == bp:
            ctx = df.CONTEXT(); ctx.ContextFlags = 0x10001F
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            k32.GetThreadContext(th, C.byref(ctx))
            print(f"HIT RCX={ctx.Rcx:#x} RAX={ctx.Rax:#x} RBP={ctx.Rbp:#x}")
            print(f"  low32(rcx)={ctx.Rcx & 0xffffffff:#x}")
            blob = df.read_process_mem(pi.hProcess, ctx.Rcx, 64) if ctx.Rcx else b""
            print("mem64", (blob[:32].hex() if blob else None))
            low = ctx.Rcx & 0xffffffff
            blob2 = df.read_process_mem(pi.hProcess, low, 64) if low else b""
            print("mem32", (blob2[:32].hex() if blob2 else None))
            if blob:
                print("utf16", blob.decode("utf-16-le", errors="replace")[:50])
            write_mem(pi.hProcess, bp, orig)
            ctx.Rip = bp
            k32.SetThreadContext(th, C.byref(ctx))
            k32.CloseHandle(th); hit = True
        elif ec == 0xC0000005:
            print(f"AV at {ea:#x}"); hit = True; cont = 0x80010001
    elif code == 5:
        print("exit"); break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
    if hit: break
k32.TerminateProcess(pi.hProcess, 1)
print("done", hit)
