import sys, ctypes as C, struct, os
sys.path.insert(0, ".")
import dbg_fault as df

exe = os.path.abspath(r"build_univ225\cmd_pure.exe")
k32 = df.k32
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
assert k32.CreateProcessW(
    None, cmdline, None, None, False, df.DEBUG_PROCESS, None,
    os.path.dirname(exe), C.byref(si), C.byref(pi))

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", C.c_ulong), ("ExceptionFlags", C.c_ulong),
    ("ExceptionRecord", C.c_void_p), ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", C.c_ulong), ("ExceptionInformation", C.c_ulonglong * 15),
]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", C.c_ulong)]

ev = df.DEBUG_EVENT()
ib = 0x80000000
DATA = {
    "c8d8": ib + 0x588d8,
    "fae0": ib + 0x5BAE0,
    "fbc8": ib + 0x5BBC8,
    "fbe0": ib + 0x5BBE0,
    "fbe2": ib + 0x5BBE2,
    "sticky": ib + 0x5BE00,
    "shadow": ib + 0x5BE04,
    "buf": ib + 0x60320,
}

def read(h, addr, n):
    buf = (C.c_ubyte * n)()
    br = C.c_size_t()
    if not k32.ReadProcessMemory(h, C.c_void_p(addr), buf, n, C.byref(br)):
        return None
    return bytes(buf)

def dump_state(h, label):
    print("===", label)
    for name, a in DATA.items():
        if name in ("sticky", "shadow", "fae0", "c8d8", "fbc8"):
            b = read(h, a, 8)
            if b:
                print("  %s @%x: dword=%08x qword=%016x" % (
                    name, a, struct.unpack_from("<I", b)[0],
                    struct.unpack_from("<Q", b)[0]))
        elif name == "fbe2":
            b = read(h, a, 0x40)
            if b:
                ws = b.decode("utf-16le", errors="replace")
                print("  fbe2 raw:", b[:40].hex())
                print("  fbe2 ws:", repr(ws[:48]))
        elif name == "buf":
            b = read(h, a, 0x40)
            if b:
                ws = b.decode("utf-16le", errors="replace")
                print("  c8d8 buf:", repr(ws[:48]))

try:
    while k32.WaitForDebugEvent(C.byref(ev), 20000):
        code = ev.dwDebugEventCode
        if code == 1:
            er = C.cast(C.byref(ev.u), C.POINTER(EXCEPTION_DEBUG_INFO)).contents
            ec = er.ExceptionRecord.ExceptionCode
            ea = er.ExceptionRecord.ExceptionAddress or 0
            if ec == 0x80000003:
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            print("FAULT code=0x%08X addr=0x%X" % (ec, ea))
            dump_state(pi.hProcess, "on fault")
            ctx = df.CONTEXT()
            ctx.ContextFlags = 0x10001F
            assert k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("  rip=%x rsp=%x" % (ctx.Rip, ctx.Rsp))
            stk = read(pi.hProcess, ctx.Rsp, 0x400)
            if stk:
                addrs = []
                for i in range(0, len(stk), 8):
                    v = struct.unpack_from("<Q", stk, i)[0]
                    if 0x80001000 <= v < 0x80080000:
                        addrs.append("%05x" % (v - ib))
                print("  text rets:", " ".join(addrs[:60]))
            break
        elif code == 5:
            print("exit")
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
finally:
    try:
        k32.TerminateProcess(pi.hProcess, 1)
    except Exception:
        pass
