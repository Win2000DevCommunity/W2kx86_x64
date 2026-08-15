import sys, ctypes as C, struct, os
sys.path.insert(0, ".")
import dbg_fault as df

exe = os.path.abspath(r"build_univ225\cmd_f4eb.exe")
pe = bytearray(open(exe, "rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
out = bytearray(pe[rp:rp+rs])
bps = {}
for rva in (0x3498d, 0x260fc, 0x26bf4, 0x1d7f4, 0x34a30):
    if 0 <= rva-va < len(out):
        bps[rva] = out[rva-va]
        out[rva-va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ225\cmd_ex_bp.exe")
open(bp_exe, "wb").write(pe)

k32 = df.k32
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer('"%s" /c echo w2ktest' % bp_exe)
assert k32.CreateProcessW(None, cmdline, None, None, False, df.DEBUG_PROCESS, None,
                          os.path.dirname(bp_exe), C.byref(si), C.byref(pi))

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

def read(h, addr, n):
    buf = (C.c_ubyte * n)()
    br = C.c_size_t()
    if not k32.ReadProcessMemory(h, C.c_void_p(addr), buf, n, C.byref(br)):
        return None
    return bytes(buf)

try:
    while k32.WaitForDebugEvent(C.byref(ev), 20000):
        if ev.dwDebugEventCode == 1:
            er = C.cast(C.byref(ev.u), C.POINTER(EXCEPTION_DEBUG_INFO)).contents
            ec = er.ExceptionRecord.ExceptionCode
            ea = er.ExceptionRecord.ExceptionAddress or 0
            if ec == 0x80000003 and (ea - ib) in bps:
                rva = ea - ib
                ctx = df.CONTEXT(); ctx.ContextFlags = 0x10001F
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                c8 = struct.unpack_from("<I", read(pi.hProcess, ib+0x588d8, 4))[0]
                buf = read(pi.hProcess, c8, 64) if c8 else None
                ws = buf.decode("utf-16le","replace")[:40] if buf else None
                fae0 = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BAE0, 4))[0]
                print("BP %05x rcx=%x rdx=%x fae0=%x c8=%r" % (
                    rva, ctx.Rcx, ctx.Rdx, fae0, ws))
                b = (C.c_ubyte * 1)(bps[rva]); wr = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ea), b, 1, C.byref(wr))
                ctx.Rip = ea
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ea), (C.c_ubyte * 1)(0xCC), 1, C.byref(wr))
                continue
            if ec == 0xC0000005:
                ctx = df.CONTEXT(); ctx.ContextFlags = 0x10001F
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print("AV rip=%x rcx=%x rdx=%x r8=%x r9=%x rbx=%x" % (
                    ctx.Rip, ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9, ctx.Rbx))
                info0 = er.ExceptionRecord.ExceptionInformation[0]
                info1 = er.ExceptionRecord.ExceptionInformation[1]
                print("  type", info0, "addr", hex(info1))
                break
            if ec != 0x80000003:
                print("fault", hex(ec), hex(ea)); break
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            continue
        elif ev.dwDebugEventCode == 5:
            print("exit"); break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
finally:
    try: k32.TerminateProcess(pi.hProcess, 1)
    except: pass
