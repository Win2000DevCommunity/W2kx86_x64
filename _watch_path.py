"""First-hit watcher for setjmp / helper / longjmp / c8d8-related sites on univ14."""
import ctypes, struct, sys, time
from ctypes import wintypes
from pathlib import Path

WATCH = {
    0x1AC92: "setjmp_fb40_setup",   # movabs rcx, fb40
    0x1ACAC: "setjmp_call",
    0x1D03C: "helper_caller_old",   # may have moved
    0x1397C: "helper_add9_old",
    0x33B94: "longjmp_setup",       # from univ14 trace
    0x33BB5: "longjmp_call",
}

# Also resolve from rva map
def load_map(p):
    m = {}
    for line in Path(p).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace("->", " ").replace(",", " ").split()
        if len(parts) >= 2:
            try:
                m[int(parts[0], 16)] = int(parts[1], 16)
            except Exception:
                pass
    return m

rmap = load_map("build_univ14/rva.txt")
for xa, name in [(0xEF42, "x86_setjmp_fn"), (0xEF69, "x86_setjmp_call"),
                 (0xFF31, "x86_helper_caller"), (0xADD9, "x86_helper"),
                 (0xF01A, "x86_longjmp"), (0xEFD6, "x86_efd6")]:
    if xa in rmap:
        WATCH[rmap[xa]] = name
        print(f"map {name}: x86 {xa:#x} -> {rmap[xa]:#x}")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

class EXCEPTION_RECORD(ctypes.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p), ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15)]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]

class DEBUG_EVENT(ctypes.Structure):
    class U(ctypes.Union):
        _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("pad", ctypes.c_byte * 160)]
    _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD), ("u", U)]

class CONTEXT(ctypes.Structure):
    _fields_ = [("P1Home", ctypes.c_ulonglong), ("P2Home", ctypes.c_ulonglong),
                ("P3Home", ctypes.c_ulonglong), ("P4Home", ctypes.c_ulonglong),
                ("P5Home", ctypes.c_ulonglong), ("P6Home", ctypes.c_ulonglong),
                ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
                ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
                ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
                ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
                ("EFlags", wintypes.DWORD),
                ("Dr0", ctypes.c_ulonglong), ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong), ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong), ("Dr7", ctypes.c_ulonglong),
                ("Rax", ctypes.c_ulonglong), ("Rcx", ctypes.c_ulonglong),
                ("Rdx", ctypes.c_ulonglong), ("Rbx", ctypes.c_ulonglong),
                ("Rsp", ctypes.c_ulonglong), ("Rbp", ctypes.c_ulonglong),
                ("Rsi", ctypes.c_ulonglong), ("Rdi", ctypes.c_ulonglong),
                ("R8", ctypes.c_ulonglong), ("R9", ctypes.c_ulonglong),
                ("R10", ctypes.c_ulonglong), ("R11", ctypes.c_ulonglong),
                ("R12", ctypes.c_ulonglong), ("R13", ctypes.c_ulonglong),
                ("R14", ctypes.c_ulonglong), ("R15", ctypes.c_ulonglong),
                ("Rip", ctypes.c_ulonglong), ("rest", ctypes.c_byte * 2000)]

exe = sys.argv[1] if len(sys.argv) > 1 else "build_univ14\\cmd_pure.exe"
seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 22.0
si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
pi = PROCESS_INFORMATION()
cmd = f'"{str(Path(exe).resolve())}" /c echo w2ktest'
ok = k32.CreateProcessW(None, ctypes.c_wchar_p(cmd), None, None, False,
                        0x1, None, str(Path(exe).resolve().parent),
                        ctypes.byref(si), ctypes.byref(pi))
if not ok:
    print("CreateProcess failed", ctypes.get_last_error()); sys.exit(1)

base = 0x80000000
first = {}
steps = 0
t0 = time.time()
ev = DEBUG_EVENT()
thr = {}
CONTEXT_ALL = 0x10001F
hit_longjmp = False

while time.time() - t0 < seconds:
    if not k32.WaitForDebugEvent(ctypes.byref(ev), 500):
        continue
    cont = 0x00010002
    code = ev.dwDebugEventCode
    if code == 1:  # EXCEPTION
        er = ev.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        if ec in (0x80000003, 0x80000004):
            hthr = thr.get(ev.dwThreadId)
            if hthr is None:
                hthr = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
                thr[ev.dwThreadId] = hthr
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(hthr, ctypes.byref(ctx))
            if base <= ctx.Rip < base + 0x200000:
                rva = ctx.Rip - base
                steps += 1
                for w, name in WATCH.items():
                    if w <= rva < w + 0x10 and name not in first:
                        first[name] = (steps, rva, ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbp)
                        print(f"FIRST {name} @ step {steps} rva={rva:#x} "
                              f"rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} rbp={ctx.Rbp:#x}")
                        if "longjmp" in name:
                            hit_longjmp = True
                ctx.EFlags |= 0x100
                k32.SetThreadContext(hthr, ctypes.byref(ctx))
            if ec == 0xC0000005 or (hit_longjmp and steps > first.get("longjmp_call", (0,))[0] + 50):
                if ec == 0xC0000005:
                    print(f"FAULT rip={ctx.Rip:#x} steps={steps}")
                    break
        elif ec == 0xC0000005:
            print(f"AV steps={steps}")
            break
    elif code == 5:
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
else:
    print(f"TIMEOUT steps={steps}")

print("HITS:", {k: (v[0], hex(v[1])) for k, v in first.items()})
k32.TerminateProcess(pi.hProcess, 1)
