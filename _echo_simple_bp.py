# Minimal Echo nested-call probe -> _echo_findings.txt
import ctypes as C
from ctypes import wintypes
import sys, time

OUT = open("_echo_findings.txt", "w", encoding="utf-8", buffering=1)

def log(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    OUT.write(s + "\n")
    OUT.flush()

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except Exception as e:
    log("IMPORT_ERR", e)
    OUT.close()
    sys.exit(1)

EXE = r"build_univ256\cmd_probe_pushrcx.exe"
pe = pefile.PE(EXE)
base_pref = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
log("EXE", EXE, "ImageBase", hex(base_pref))

def dis_rva(rva, n=40, title=""):
    log("=== DIS", title or hex(rva), "===")
    data = pe.get_data(rva, n * 16)
    c = 0
    for insn in md.disasm(data, base_pref + rva):
        log("  %06X: %-8s %s" % (insn.address - base_pref, insn.mnemonic, insn.op_str))
        c += 1
        if c >= n:
            break

dis_rva(0x260fc, 40, "callee_260fc")
dis_rva(0x25d2c, 40, "callee_25d2c")
dis_rva(0x42850, 55, "path_42862_region")
for rva in (0x18E53, 0x427A0, 0x427F6, 0x4282F, 0x42855, 0x42862, 0x42886, 0x428B7, 0x428C9, 0x428D7):
    dis_rva(rva, 12, "site_%X" % rva)
log("=== DIS DONE ===")

k32 = C.WinDLL("kernel32", use_last_error=True)
DEBUG_PROCESS = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
DBG_CONTINUE = 0x10002
CONTEXT_FULL = 0x100017

class PROCESS_INFORMATION(C.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

class STARTUPINFOW(C.Structure):
    _fields_ = [("cb", wintypes.DWORD)] + [("x", wintypes.DWORD)] * 8 + [
        ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD), ("lpReserved2", C.c_void_p),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE)]

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", C.POINTER(EXCEPTION_RECORD)), ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", wintypes.DWORD), ("ExceptionInformation", C.c_ulonglong * 15)]

class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]

class CREATE_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [("hFile", wintypes.HANDLE), ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("lpBaseOfImage", C.c_void_p), ("dwDebugInfoFileOffset", wintypes.DWORD),
                ("nDebugInfoSize", wintypes.DWORD), ("lpThreadLocalBase", C.c_void_p),
                ("lpStartAddress", C.c_void_p), ("lpImageName", C.c_void_p), ("fUnicode", wintypes.WORD)]

class DEBUG_EVENT_U(C.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("pad", C.c_byte * 160)]

class DEBUG_EVENT(C.Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD), ("u", DEBUG_EVENT_U)]

class CONTEXT(C.Structure):
    _fields_ = [
        ("P1Home", C.c_ulonglong), ("P2Home", C.c_ulonglong), ("P3Home", C.c_ulonglong),
        ("P4Home", C.c_ulonglong), ("P5Home", C.c_ulonglong), ("P6Home", C.c_ulonglong),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD), ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD), ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", C.c_ulonglong), ("Dr1", C.c_ulonglong), ("Dr2", C.c_ulonglong),
        ("Dr3", C.c_ulonglong), ("Dr6", C.c_ulonglong), ("Dr7", C.c_ulonglong),
        ("Rax", C.c_ulonglong), ("Rcx", C.c_ulonglong), ("Rdx", C.c_ulonglong),
        ("Rbx", C.c_ulonglong), ("Rsp", C.c_ulonglong), ("Rbp", C.c_ulonglong),
        ("Rsi", C.c_ulonglong), ("Rdi", C.c_ulonglong), ("R8", C.c_ulonglong),
        ("R9", C.c_ulonglong), ("R10", C.c_ulonglong), ("R11", C.c_ulonglong),
        ("R12", C.c_ulonglong), ("R13", C.c_ulonglong), ("R14", C.c_ulonglong),
        ("R15", C.c_ulonglong), ("Rip", C.c_ulonglong)]

HIT_RVAS = [0x427A0, 0x427F6, 0x4282F, 0x42855, 0x42886, 0x428C9, 0x428D7]
EXTRA = [0x42862, 0x428B7]

cmd = '"' + EXE + '" /c echo w2ktest'
log("CMDLINE", cmd)
si = STARTUPINFOW(); si.cb = C.sizeof(si)
pi = PROCESS_INFORMATION()
ok = k32.CreateProcessW(None, C.create_unicode_buffer(cmd), None, None, False,
                        DEBUG_PROCESS, None, None, C.byref(si), C.byref(pi))
if not ok:
    log("CreateProcess FAIL", C.get_last_error())
    OUT.close()
    sys.exit(1)
log("pid", pi.dwProcessId)

base = 0
init = True
armed = False
softs = {}
hits = []
phase_addrs = []

def set_hw(ctx, addrs):
    addrs = list(addrs)[:4]
    for i in range(4):
        setattr(ctx, "Dr%d" % i, addrs[i] if i < len(addrs) else 0)
    dr7 = 0
    for i in range(len(addrs)):
        dr7 |= (1 << (2 * i))
    ctx.Dr7 = dr7
    ctx.Dr6 = 0

de = DEBUG_EVENT()
t0 = time.time()
while time.time() - t0 < 45:
    if not k32.WaitForDebugEvent(C.byref(de), 1000):
        continue
    st = DBG_CONTINUE
    if de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        log("base", hex(base))
        arm_va = base + 0x18E53
        saved = C.c_ubyte()
        nr = C.c_size_t()
        k32.ReadProcessMemory(pi.hProcess, C.c_void_p(arm_va), C.byref(saved), 1, C.byref(nr))
        int3 = C.c_ubyte(0xCC)
        old = wintypes.DWORD()
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(arm_va), 1, 0x40, C.byref(old))
        k32.WriteProcessMemory(pi.hProcess, C.c_void_p(arm_va), C.byref(int3), 1, C.byref(nr))
        softs[arm_va] = saved
        log("softARM", hex(arm_va), "saved", hex(saved.value))
    elif de.dwDebugEventCode == 1:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress
        if not isinstance(addr, int):
            addr = C.cast(addr, C.c_void_p).value or 0
        ht = k32.OpenThread(0x1F03FF, False, de.dwThreadId) or pi.hThread
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        k32.GetThreadContext(ht, C.byref(ctx))

        if code == EXCEPTION_BREAKPOINT and init:
            init = False
            log("initialBP", hex(addr))
        elif code == EXCEPTION_BREAKPOINT and addr in softs:
            rva = (addr - base) & 0xFFFFFFFF
            log("SOFT rva=%#x rip=%#x rbp=%#x rax=%#x rsp=%#x" % (
                rva, ctx.Rip, ctx.Rbp, ctx.Rax, ctx.Rsp))
            hits.append((rva, ctx.Rbp, ctx.Rax))
            if ctx.Rbp == 3 or (ctx.Rbp and ctx.Rbp < 0x10000):
                log("***RBP_BAD***", hex(ctx.Rbp))
            nr = C.c_size_t()
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(softs[addr]), 1, C.byref(nr))
            ctx.Rip = addr
            if rva == 0x18E53 and not armed:
                phase_addrs[:] = [base + r for r in HIT_RVAS[:4]]
                set_hw(ctx, phase_addrs)
                armed = True
                log("armed HW", [hex(a - base) for a in phase_addrs])
                for r in HIT_RVAS[4:] + EXTRA:
                    va = base + r
                    if va in softs:
                        continue
                    saved = C.c_ubyte(); nr2 = C.c_size_t()
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(va), C.byref(saved), 1, C.byref(nr2))
                    int3 = C.c_ubyte(0xCC)
                    old = wintypes.DWORD()
                    k32.VirtualProtectEx(pi.hProcess, C.c_void_p(va), 1, 0x40, C.byref(old))
                    k32.WriteProcessMemory(pi.hProcess, C.c_void_p(va), C.byref(int3), 1, C.byref(nr2))
                    softs[va] = saved
                log("extra soft", [hex(r) for r in HIT_RVAS[4:] + EXTRA])
                del softs[addr]
            else:
                del softs[addr]
            k32.SetThreadContext(ht, C.byref(ctx))
        elif code == EXCEPTION_SINGLE_STEP:
            rva = (ctx.Rip - base) & 0xFFFFFFFF
            log("HW rva=%#x rip=%#x rbp=%#x rax=%#x rsp=%#x dr6=%#x" % (
                rva, ctx.Rip, ctx.Rbp, ctx.Rax, ctx.Rsp, ctx.Dr6 & 0xF))
            hits.append((rva, ctx.Rbp, ctx.Rax))
            if ctx.Rbp == 3 or (ctx.Rbp and ctx.Rbp < 0x10000):
                log("***RBP_BAD***", hex(ctx.Rbp))
            set_hw(ctx, phase_addrs if phase_addrs else [base + r for r in HIT_RVAS[:4]])
            ctx.EFlags |= 0x10000
            k32.SetThreadContext(ht, C.byref(ctx))
        elif code == 0xC0000005:
            rva = (ctx.Rip - base) & 0xFFFFFFFF
            log("AV rva=%#x rip=%#x rbp=%#x rax=%#x rsp=%#x" % (
                rva, ctx.Rip, ctx.Rbp, ctx.Rax, ctx.Rsp))
            if er.NumberParameters >= 2:
                log("AVinfo", hex(er.ExceptionInformation[0]), hex(er.ExceptionInformation[1]))
            k32.TerminateProcess(pi.hProcess, 1)
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
            if ht and ht != pi.hThread:
                k32.CloseHandle(ht)
            break
        if ht and ht != pi.hThread:
            k32.CloseHandle(ht)
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        log("EXIT")
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

log("hits", hits)
log("DONE_PROBE")
try:
    k32.TerminateProcess(pi.hProcess, 0)
except Exception:
    pass
k32.CloseHandle(pi.hProcess)
k32.CloseHandle(pi.hThread)
OUT.close()

