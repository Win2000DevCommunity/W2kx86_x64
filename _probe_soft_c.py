"""Soft-INT3 on /c stores + CheckSwitches /c cmp; dump flags; kill."""
import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
df.suppress_fault_ui()
k32 = df.k32

EXE = os.path.abspath(r"build_univ256\cmd_probe_echo3.exe")
pe = bytearray(open(EXE, "rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
num = struct.unpack_from("<H", pe, e + 6)[0]
opt = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + opt
for i in range(num):
    o = sec + i * 40
    if pe[o:o+5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
out = bytearray(pe[rp:rp+rs])
# INT3 at /c stores and at cmp before /c handler (need find pe64 of a61a)
BPS = {
    0x13ECC: "c_store_a",
    0x44170: "c_store_b",
    0x1EA9D: "fae0_wr",
    0x45828: "waiter",
}
saved = {}
for rva, name in BPS.items():
    off = rva - va
    saved[rva] = out[off]
    out[off] = 0xCC
    print(f"patch {name} {rva:#x} was {saved[rva]:02x}")
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ256\cmd_bp_cflag.exe")
open(bp_exe, "wb").write(pe)

def rpm(h, addr, n):
    buf = (C.c_ubyte * n)()
    br = C.c_size_t()
    if not k32.ReadProcessMemory(h, C.c_void_p(addr), buf, n, C.byref(br)):
        return None
    return bytes(buf)

def dword(h, a):
    b = rpm(h, a, 4)
    return struct.unpack_from("<I", b)[0] if b else None

def dump(h, base, lab):
    print(f"=== {lab} ===")
    for n, o in [("/c",0x58F64),("/k",0x58F60),("fae0",0x5BAE0),("sticky",0x5BE00),("fbc8",0x5BBC8)]:
        print(f"  {n}={dword(h, base+o):#x}")

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
assert k32.CreateProcessW(None, cmd, None, None, False, df.DEBUG_PROCESS, None,
                          os.path.dirname(bp_exe), C.byref(si), C.byref(pi))

class ER(C.Structure):
    pass
ER._fields_ = [("ExceptionCode", C.c_ulong), ("ExceptionFlags", C.c_ulong),
    ("ExceptionRecord", C.c_void_p), ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", C.c_ulong), ("ExceptionInformation", C.c_ulonglong * 15)]
class EDI(C.Structure):
    _fields_ = [("ExceptionRecord", ER), ("dwFirstChance", C.c_ulong)]

ev = df.DEBUG_EVENT()
ib = 0
hits = 0
init = True
try:
    while k32.WaitForDebugEvent(C.byref(ev), 8000):
        if ev.dwDebugEventCode == 3:
            ib = ev.u.CreateProcessInfo.lpBaseOfImage or 0
            print("base", hex(ib))
        elif ev.dwDebugEventCode == 1:
            er = C.cast(C.byref(ev.u), C.POINTER(EDI)).contents
            ec = er.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionRecord.ExceptionAddress or 0
            if ec == 0x80000003:
                if init:
                    init = False
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                    continue
                rva = (ea - ib) & 0xFFFFFFFF
                name = BPS.get(rva, "?")
                ctx = df.CONTEXT(); ctx.ContextFlags = df.CONTEXT_FULL
                k32.GetThreadContext(pi.hThread, C.byref(ctx))
                print(f"HIT {name} rva={rva:#x} rax={ctx.Rax:#x} rip={ctx.Rip:#x}")
                dump(pi.hProcess, ib, name)
                hits += 1
                # restore
                buf = (C.c_ubyte * 1)(saved.get(rva, 0x90))
                wr = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ea), buf, 1, C.byref(wr))
                ctx.Rip = ea
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                if hits >= 8:
                    break
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            if ec == 0xC0000005:
                rva = (ea - ib) & 0xFFFFFFFF
                print(f"AV rva={rva:#x}")
                dump(pi.hProcess, ib, "AV")
                break
            if ec != 0x80000003:
                print("exc", hex(ec), hex(ea))
        elif ev.dwDebugEventCode == 5:
            print("exit")
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
finally:
    try: k32.TerminateProcess(pi.hProcess, 1)
    except: pass
    print("KILLED hits", hits)
