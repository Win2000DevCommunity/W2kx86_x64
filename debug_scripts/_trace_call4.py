
from __future__ import annotations
import ctypes as C
import sys
from ctypes import wintypes
from pathlib import Path

k32 = C.WinDLL("kernel32", use_last_error=True)
DEBUG_ONLY_THIS_PROCESS = 0x2
INFINITE = 0xFFFFFFFF
EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
DBG_CONTINUE = 0x00010002
CONTEXT_AMD64 = 0x00100000
CONTEXT_FULL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x4
CONTEXT_DEBUG = CONTEXT_AMD64 | 0x10
CONTEXT_ALL = CONTEXT_FULL | CONTEXT_DEBUG

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", C.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", C.c_ulonglong * 15),
]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]
class CREATE_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE), ("lpBaseOfImage", C.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD), ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", C.c_void_p), ("lpStartAddress", C.c_void_p),
        ("lpImageName", C.c_void_p), ("fUnicode", wintypes.WORD),
    ]
class LOAD_DLL_DEBUG_INFO(C.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE), ("lpBaseOfDll", C.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD), ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", C.c_void_p), ("fUnicode", wintypes.WORD),
    ]
class EXIT_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]
class DEBUG_EVENT_U(C.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("pad", C.c_byte * 160),
    ]
class DEBUG_EVENT(C.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_U),
    ]
class CONTEXT(C.Structure):
    _fields_ = [
        ("P1Home", C.c_ulonglong), ("P2Home", C.c_ulonglong),
        ("P3Home", C.c_ulonglong), ("P4Home", C.c_ulonglong),
        ("P5Home", C.c_ulonglong), ("P6Home", C.c_ulonglong),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", C.c_ulonglong), ("Dr1", C.c_ulonglong), ("Dr2", C.c_ulonglong),
        ("Dr3", C.c_ulonglong), ("Dr6", C.c_ulonglong), ("Dr7", C.c_ulonglong),
        ("Rax", C.c_ulonglong), ("Rcx", C.c_ulonglong), ("Rdx", C.c_ulonglong),
        ("Rbx", C.c_ulonglong), ("Rsp", C.c_ulonglong), ("Rbp", C.c_ulonglong),
        ("Rsi", C.c_ulonglong), ("Rdi", C.c_ulonglong), ("R8", C.c_ulonglong),
        ("R9", C.c_ulonglong), ("R10", C.c_ulonglong), ("R11", C.c_ulonglong),
        ("R12", C.c_ulonglong), ("R13", C.c_ulonglong), ("R14", C.c_ulonglong),
        ("R15", C.c_ulonglong), ("Rip", C.c_ulonglong),
        ("FltSave", C.c_byte * 512),
        ("VectorRegister", C.c_byte * (26 * 16)),
        ("VectorControl", C.c_ulonglong),
        ("DebugControl", C.c_ulonglong),
        ("LastBranchToRip", C.c_ulonglong),
        ("LastBranchFromRip", C.c_ulonglong),
        ("LastExceptionToRip", C.c_ulonglong),
        ("LastExceptionFromRip", C.c_ulonglong),
    ]
class STARTUPINFO(C.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", C.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]
class PROCESS_INFORMATION(C.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]

ReadProcessMemory = k32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]

def read_mem(proc, addr, size):
    buf = (C.c_char * size)()
    n = C.c_size_t(0)
    if ReadProcessMemory(proc, C.c_void_p(addr), buf, size, C.byref(n)):
        return bytes(buf[:n.value])
    return b""

def insn_len_and_kind(b):
    """Return (length, kind, target_reg_or_None) for common encodings. kind: call_reg/call_rel/jmp_reg/other"""
    if not b:
        return 1, "other", None
    i = 0
    rex = 0
    if b[0] in range(0x40, 0x50):
        rex = b[0]; i = 1
    if i >= len(b):
        return 1, "other", None
    op = b[i]
    if op == 0xE8 and i + 5 <= len(b):
        return i + 5, "call_rel", None
    if op == 0xE9 and i + 5 <= len(b):
        return i + 5, "jmp_rel", None
    if op == 0xFF and i + 1 < len(b):
        modrm = b[i+1]
        reg = (modrm >> 3) & 7
        mod = (modrm >> 6) & 3
        rm = modrm & 7
        # length rough
        ln = i + 2
        if rm == 4 and mod != 3:
            ln += 1  # sib
        if mod == 1:
            ln += 1
        elif mod == 2 or (mod == 0 and rm == 5):
            ln += 4
        if reg == 2:
            return ln, "call_rm", (rex, modrm)
        if reg == 4:
            return ln, "jmp_rm", (rex, modrm)
    if op == 0xC3:
        return i + 1, "ret", None
    return max(1, i + 1), "other", None

def reg_from_modrm(rex, modrm, ctx):
    rm = modrm & 7
    if rex & 1:
        rm += 8
    names = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]
    vals = [ctx.Rax,ctx.Rcx,ctx.Rdx,ctx.Rbx,ctx.Rsp,ctx.Rbp,ctx.Rsi,ctx.Rdi,ctx.R8,ctx.R9,ctx.R10,ctx.R11,ctx.R12,ctx.R13,ctx.R14,ctx.R15]
    mod = (modrm >> 6) & 3
    if mod == 3:
        return names[rm], vals[rm]
    return "mem", None

def main():
    exe = Path(sys.argv[1]).resolve()
    entry_rva = 0x17568
    run_args = []
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--entry":
            entry_rva = int(sys.argv[i+1], 16); i += 2; continue
        run_args.append(sys.argv[i]); i += 1
    cmd = '"%s" %s' % (exe, " ".join(run_args))
    si = STARTUPINFO(); si.cb = C.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(str(exe), C.c_wchar_p(cmd), None, None, False,
                            DEBUG_ONLY_THIS_PROCESS, None, str(exe.parent), C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error()); return 1
    base = 0
    lo = hi = 0
    stepping = False
    skip_until = 0
    events = []
    de = DEBUG_EVENT()
    while True:
        if not k32.WaitForDebugEvent(C.byref(de), INFINITE):
            break
        status = DBG_CONTINUE
        code = de.dwDebugEventCode
        if code == CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage or 0
            lo, hi = base + entry_rva, base + entry_rva + 0x900
            print("[base] %#x range %#x..%#x" % (base, lo, hi))
            h = de.u.CreateProcessInfo.hFile
            if h: k32.CloseHandle(h)
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = base + entry_rva
            ctx.Dr7 = 0x1
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif code == LOAD_DLL_DEBUG_EVENT:
            h = de.u.LoadDll.hFile
            if h: k32.CloseHandle(h)
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print("[exit]", de.u.ExitProcess.dwExitCode); break
        elif code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            addr = er.ExceptionAddress or 0
            ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if ecode == 0x80000003 and not stepping:
                pass
            elif (ecode in (0x80000004, 0x80000003)) and (stepping or ctx.Rip == base + entry_rva):
                if not stepping:
                    print("[hit] enter %#x" % ctx.Rip)
                    stepping = True
                    ctx.Dr0 = 0; ctx.Dr7 = 0
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                else:
                    rip = ctx.Rip
                    if skip_until and rip != skip_until:
                        ctx.EFlags |= 0x100
                        k32.SetThreadContext(pi.hThread, C.byref(ctx))
                        status = DBG_CONTINUE
                        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                        continue
                    skip_until = 0
                    if rip < 0x10000:
                        print("LOW RIP", hex(rip))
                        for e in events[-30]: print(e)
                        print("rax=%#x rcx=%#x rdx=%#x rbx=%#x rbp=%#x rsi=%#x rdi=%#x" % (ctx.Rax,ctx.Rcx,ctx.Rdx,ctx.Rbx,ctx.Rbp,ctx.Rsi,ctx.Rdi))
                        print("r11=%#x r14=%#x r15=%#x rsp=%#x" % (ctx.R11,ctx.R14,ctx.R15,ctx.Rsp))
                        k32.TerminateProcess(pi.hProcess, 1); break
                    b = read_mem(pi.hProcess, rip, 16)
                    ln, kind, meta = insn_len_and_kind(b)
                    rva = rip - base if base <= rip < base + 0x200000 else None
                    if ctx.Rbp < 0x10000 or ctx.Rsp < 0x10000:
                        line = "RBP/RSP LOW rva=%s rbp=%#x rsp=%#x rax=%#x rbx=%#x bytes=%s" % (
                            hex(rva) if rva else None, ctx.Rbp, ctx.Rsp, ctx.Rax, ctx.Rbx, b[:8].hex())
                        print(line); events.append(line)
                        if ctx.Rip < 0x10000 or (ctx.Rbp < 0x10000 and kind in ("call_rm","jmp_rm","ret")):
                            for e in events[-40:]: print(e)
                            k32.TerminateProcess(pi.hProcess, 1); break
                    if kind in ("call_rm", "jmp_rm"):
                        name, tgt = reg_from_modrm(meta[0], meta[1], ctx) if meta else ("?", None)
                        # if memory form, try read [rax] style when modrm is simple
                        if name == "mem":
                            # handle FF 20 = jmp [rax], FF 10 = call [rax] etc
                            modrm = meta[1]
                            if (modrm & 0xC7) == 0x00:  # [rax]
                                tgt = ctx.Rax
                                ptr = read_mem(pi.hProcess, tgt, 8)
                                tgt = int.from_bytes(ptr, "little") if len(ptr)==8 else None
                                name = "[rax]"
                            elif (modrm & 0xC7) == 0x20:  # [rax] jmp
                                pass
                        line = "rva=%s %s %s -> %s bytes=%s rbp=%#x rax=%#x r14=%#x" % (
                            hex(rva) if rva is not None else None, kind, name,
                            hex(tgt) if isinstance(tgt, int) else tgt, b[:ln].hex(), ctx.Rbp, ctx.Rax, ctx.R14)
                        print(line)
                        events.append(line)
                        if isinstance(tgt, int) and tgt < 0x10000:
                            print("*** TARGET LOW ***", line)
                            for e in events[-40:]: print(e)
                            k32.TerminateProcess(pi.hProcess, 1); break
                        # step over calls that leave the function window
                        if kind == "call_rm" and isinstance(tgt, int) and not (lo <= tgt < hi):
                            skip_until = rip + ln
                            ctx.Dr0 = skip_until
                            ctx.Dr7 = 0x1
                            ctx.EFlags &= ~0x100
                            k32.SetThreadContext(pi.hThread, C.byref(ctx))
                            status = DBG_CONTINUE
                            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                            continue
                    elif kind == "call_rel":
                        rel = int.from_bytes(b[1:5] if b[0]==0xE8 else b[2:6], "little", signed=True)
                        # account for rex
                        off = 1 + (1 if b[0] in range(0x40,0x50) else 0)
                        if b[0] in range(0x40,0x50):
                            rel = int.from_bytes(b[2:6], "little", signed=True); ln = 6
                        else:
                            rel = int.from_bytes(b[1:5], "little", signed=True); ln = 5
                        tgt = rip + ln + rel
                        line = "rva=%s call_rel -> %s rbp=%#x" % (hex(rva) if rva else None, hex(tgt), ctx.Rbp)
                        events.append(line)
                        if not (lo <= tgt < hi):
                            skip_until = rip + ln
                            ctx.Dr0 = skip_until
                            ctx.Dr7 = 0x1
                            ctx.EFlags &= ~0x100
                            k32.SetThreadContext(pi.hThread, C.byref(ctx))
                            status = DBG_CONTINUE
                            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                            continue
                    # continue single-step inside function
                    if not (lo <= rip < hi) and stepping:
                        # left function without catching — keep stepping briefly
                        pass
                    ctx.EFlags |= 0x100
                    # clear DR if we used it
                    ctx.Dr0 = 0; ctx.Dr7 = 0
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
            else:
                print("EXCEPTION %#x addr=%#x rip=%#x rbp=%#x rax=%#x r14=%#x" % (
                    ecode, addr, ctx.Rip, ctx.Rbp, ctx.Rax, ctx.R14))
                if ecode == 0xC0000005 and er.NumberParameters >= 2:
                    print("AV op=%s fault=%#x" % (er.ExceptionInformation[0], er.ExceptionInformation[1]))
                for e in events[-40:]: print(e)
                k32.TerminateProcess(pi.hProcess, 1); break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
    k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
