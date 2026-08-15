import sys, ctypes as C, struct, os
sys.path.insert(0, ".")
import dbg_fault as df

exe = os.path.abspath(r"build_univ225\cmd_pure.exe")
# patch INT3 at 1ea93 (store fae0)
pe = bytearray(open(exe, "rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o+5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
out = bytearray(pe[rp:rp+rs])
bp_rva = 0x1ea93
saved = out[bp_rva - va]
out[bp_rva - va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ225\cmd_bp_fae0.exe")
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

hits = 0
try:
    while k32.WaitForDebugEvent(C.byref(ev), 20000):
        if ev.dwDebugEventCode == 1:
            er = C.cast(C.byref(ev.u), C.POINTER(EXCEPTION_DEBUG_INFO)).contents
            ec = er.ExceptionRecord.ExceptionCode
            ea = er.ExceptionRecord.ExceptionAddress or 0
            if ec == 0x80000003 and (ea & 0xFFFFFFFF) == (ib + bp_rva) & 0xFFFFFFFF:
                hits += 1
                ctx = df.CONTEXT()
                ctx.ContextFlags = 0x10001F
                assert k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print("HIT%d eax=%08x rip=%x" % (hits, ctx.Rax & 0xFFFFFFFF, ctx.Rip))
                for name, a in [("sticky", ib+0x5BE00), ("shadow", ib+0x5BE04),
                                ("fbc8", ib+0x5BBC8), ("fae0", ib+0x5BAE0)]:
                    b = read(pi.hProcess, a, 8)
                    print("  %s=%08x" % (name, struct.unpack_from("<I", b)[0]))
                b = read(pi.hProcess, ib+0x5BBE2, 0x30)
                print("  fbe2:", repr(b.decode("utf-16le", "replace")[:40]))
                fbc8 = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BBC8, 4))[0]
                if fbc8:
                    nb = read(pi.hProcess, fbc8, 16)
                    print("  @fbc8:", repr(nb.decode("utf-16le", "replace")[:20]) if nb else None)
                # restore and continue once
                C.memmove
                written = C.c_size_t()
                buf = (C.c_ubyte * 1)(saved)
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ea), buf, 1, C.byref(written))
                ctx.Rip = ea
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                if hits >= 3:
                    break
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0xC00000FD:
                print("SO after %d hits" % hits)
                break
            if ec != 0x80000003:
                print("other fault", hex(ec), hex(ea))
                break
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            continue
        elif ev.dwDebugEventCode == 5:
            print("exit")
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
finally:
    try: k32.TerminateProcess(pi.hProcess, 1)
    except: pass
print("done hits", hits)
