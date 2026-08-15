"""Minimal Win32 debug-loop to capture the first crash in a child process.

Reports faulting address, RVA within the main module, register context and
the raw bytes at the faulting RIP. Usage:

    python dbg_fault.py <exe> [args...]
"""
import ctypes as C
import os
import sys
import shutil
import tempfile
from dataclasses import dataclass, field
from ctypes import wintypes

k32 = C.WinDLL("kernel32", use_last_error=True)

SEM_NOGPFAULTERRORBOX = 0x0002
SEM_FAILCRITICALERRORS = 0x0001
SEM_NOOPENFILEERRORBOX = 0x8000


def suppress_fault_ui() -> None:
    """Stop Windows / Visual Studio JIT debugger dialogs on crash."""
    k32.SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS
                     | SEM_NOOPENFILEERRORBOX)
    try:
        wer = C.WinDLL("wer")
        wer.WerSetFlags(0x30)  # NO_UI | DISABLE_THREAD_TERMINATION
    except Exception:
        pass
    # Best-effort: disable JIT attach (VS "debug this process?" prompt).
    try:
        import winreg
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(
                    hive,
                    r"Software\Microsoft\Windows NT\CurrentVersion\AeDebug",
                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "Auto", 0, winreg.REG_SZ, "0")
                winreg.CloseKey(key)
            except OSError:
                pass
    except ImportError:
        pass

DEBUG_ONLY_THIS_PROCESS = 0x00000002
DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
INFINITE = 0xFFFFFFFF

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_FULL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x4

EXCEPTION_MAXIMUM_PARAMETERS = 15


class STARTUPINFO(C.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", C.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class EXCEPTION_RECORD(C.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", C.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", C.c_ulonglong * EXCEPTION_MAXIMUM_PARAMETERS),
]


class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]


class CREATE_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", C.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", C.c_void_p),
        ("lpStartAddress", C.c_void_p),
        ("lpImageName", C.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class LOAD_DLL_DEBUG_INFO(C.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", C.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", C.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class OUTPUT_DEBUG_STRING_INFO(C.Structure):
    _fields_ = [
        ("lpDebugStringData", C.c_void_p),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class DEBUG_EVENT_U(C.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("_pad", C.c_byte * 160),
    ]


class DEBUG_EVENT(C.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_U),
    ]


class M128A(C.Structure):
    _fields_ = [("Low", C.c_ulonglong), ("High", C.c_longlong)]


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
        ("VectorRegister", M128A * 26), ("VectorControl", C.c_ulonglong),
        ("DebugControl", C.c_ulonglong), ("LastBranchToRip", C.c_ulonglong),
        ("LastBranchFromRip", C.c_ulonglong), ("LastExceptionToRip", C.c_ulonglong),
        ("LastExceptionFromRip", C.c_ulonglong),
    ]


# ── Shared helpers for dbg_root / dbg_break ───────────────────────────────────

W2KSHIM_BASE = 0x1800100000
MAIN_IMAGE_MAX = 0x400000


def read_process_mem(proc, addr: int, size: int) -> bytes:
    buf = (C.c_char * size)()
    n = C.c_size_t(0)
    if k32.ReadProcessMemory(proc, C.c_void_p(addr), buf, size, C.byref(n)):
        return bytes(buf[: n.value])
    return b""


def get_thread_context(h_thread) -> CONTEXT:
    ctx = CONTEXT()
    ctx.ContextFlags = CONTEXT_FULL
    k32.GetThreadContext(h_thread, C.byref(ctx))
    return ctx


def set_trace_flag(h_thread, on: bool = True) -> None:
    ctx = get_thread_context(h_thread)
    if on:
        ctx.EFlags |= 0x100
    else:
        ctx.EFlags &= ~0x100
    k32.SetThreadContext(h_thread, C.byref(ctx))


def fmt_module_addr(addr: int, main_base: int | None,
                    shim_base: int = W2KSHIM_BASE) -> str:
    if main_base and main_base <= addr < main_base + MAIN_IMAGE_MAX:
        return f"main+0x{addr - main_base:X}"
    if shim_base <= addr < shim_base + 0x200000:
        return f"shim+0x{addr - shim_base:X}"
    if 0x7FF000000000 <= addr < 0x800000000000:
        return f"sys+0x{addr:X}"
    return f"0x{addr:016X}"


def module_owner(addr: int, main_base: int | None,
                 dll_bases: dict) -> tuple[int, str]:
    best = None
    if main_base and main_base <= addr < main_base + MAIN_IMAGE_MAX:
        best = (main_base, "<main>")
    for base, name in dll_bases.items():
        if addr >= base and (best is None or base > best[0]):
            best = (base, name)
    return best or (0, "?")


def is_probably_stack(addr: int, rsp: int, rbp: int = 0) -> bool:
    if addr < 0x10000:
        return False
    lo = min(rsp, rbp or rsp) - 0x2000
    hi = max(rsp, rbp or rsp) + 0x8000
    return lo <= addr <= hi


def scan_image_returns(proc, rsp: int, main_base: int | None,
                       limit: int = 24, depth: int = 0x800) -> list[tuple[int, int]]:
    """Return (stack_offset, return_va) pairs pointing into the main image."""
    if not main_base:
        return []
    raw = read_process_mem(proc, rsp, depth)
    out = []
    img_lo = main_base
    img_hi = main_base + MAIN_IMAGE_MAX
    for off in range(0, len(raw) - 8, 8):
        q = int.from_bytes(raw[off:off + 8], "little")
        if img_lo <= q < img_hi:
            out.append((off, q))
            if len(out) >= limit:
                break
    return out


def disasm_range(proc, rip: int, before: int = 24, after: int = 16) -> list:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        return []
    start = max(0, rip - before)
    raw = read_process_mem(proc, start, before + after)
    if not raw:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(raw, start))


def find_callsite_before(proc, ret_addr: int, window: int = 48):
    """Best-effort: instruction ending at *ret_addr* (the call/jmp site)."""
    insns = disasm_range(proc, ret_addr, before=window, after=4)
    if not insns:
        return None
    best = None
    for ins in insns:
        end = ins.address + ins.size
        if end == ret_addr:
            best = ins
    if best:
        return best
    # Fall back: last call/jmp/indirect in the window before ret_addr.
    for ins in reversed(insns):
        if ins.address >= ret_addr:
            continue
        if ins.mnemonic in ("call", "jmp") or ins.op_str.startswith("qword ptr"):
            return ins
    return insns[-1] if insns else None


# ── Call-root analysis (used by dbg_root --probe / --crt) ─────────────────────

PAGE_EXECUTE_READWRITE = 0x40


def patch_byte(proc, addr: int, val: int) -> bool:
    """Write one byte at *addr* (VirtualProtectEx + WriteProcessMemory)."""
    old = wintypes.DWORD(0)
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000,
                         PAGE_EXECUTE_READWRITE, C.byref(old))
    buf = (C.c_ubyte * 1)(val & 0xFF)
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), buf, 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return bool(ok and n.value == 1)


def read_u64(proc, addr: int) -> int | None:
    raw = read_process_mem(proc, addr, 8)
    return int.from_bytes(raw, "little") if len(raw) == 8 else None


class PeImportMap:
    """Map IAT slot RVAs in the on-disk PE to ``DLL!name`` strings."""

    def __init__(self, exe_path: str | None):
        self.slot_names: dict[int, str] = {}
        if exe_path and os.path.isfile(exe_path):
            self._load(exe_path)

    def _load(self, exe_path: str) -> None:
        try:
            import pefile
            pe = pefile.PE(exe_path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                dll = entry.dll.decode(errors="replace") if entry.dll else "?"
                for imp in entry.imports or []:
                    if imp.address:
                        if imp.name:
                            sym = imp.name.decode(errors="replace")
                        else:
                            sym = f"ord#{imp.ordinal}"
                        self.slot_names[imp.address] = f"{dll}!{sym}"
        except Exception:
            pass

    def name_for_slot(self, slot_rva: int) -> str:
        return self.slot_names.get(slot_rva, "")


@dataclass
class CallRoot:
    """One resolved call site (racine) with argument / target values."""
    callsite_rva: int
    return_rva: int = 0
    mnemonic: str = ""
    op_str: str = ""
    kind: str = ""           # direct | iat | indirect-reg | ret-chain
    target_va: int = 0
    target_label: str = ""
    iat_slot_rva: int = 0
    iat_slot_value: int = 0
    iat_name: str = ""
    args: dict[str, int] = field(default_factory=dict)
    note: str = ""


def _ctx_args(ctx: CONTEXT) -> dict[str, int]:
    return {
        "rax": ctx.Rax, "rcx": ctx.Rcx, "rdx": ctx.Rdx, "rbx": ctx.Rbx,
        "rsi": ctx.Rsi, "rdi": ctx.Rdi, "r8": ctx.R8, "r9": ctx.R9,
        "r10": ctx.R10, "r11": ctx.R11, "r12": ctx.R12, "r13": ctx.R13,
    }


def analyze_insn_call(proc, rip: int, ctx: CONTEXT, main_base: int | None,
                      imp: PeImportMap | None = None) -> CallRoot | None:
    """Decode the instruction at *rip* if it is a call/jmp; resolve target + args."""
    insns = disasm_range(proc, rip, 0, 16)
    if not insns or insns[0].address != rip:
        return None
    ins = insns[0]
    m = ins.mnemonic.lower()
    op = ins.op_str
    op_l = op.lower()
    rva = (rip - main_base) if main_base and main_base <= rip else rip
    root = CallRoot(
        callsite_rva=rva if main_base and main_base <= rip else 0,
        mnemonic=ins.mnemonic,
        op_str=op,
        args=_ctx_args(ctx),
    )
    if m not in ("call", "jmp"):
        return None

    # FF 15 / FF 25  rip-relative IAT
    if op_l.startswith("qword ptr [rip"):
        raw = read_process_mem(proc, rip, ins.size)
        if len(raw) >= 6 and raw[0:2] in (b"\xff\x15", b"\xff\x25"):
            rel = int.from_bytes(raw[2:6], "little", signed=True)
            slot_va = rip + ins.size + rel
            slot_rva = slot_va - main_base if main_base else slot_va
            slot_val = read_u64(proc, slot_va) or 0
            root.kind = "iat"
            root.target_va = slot_val
            root.target_label = fmt_module_addr(slot_val, main_base)
            root.iat_slot_rva = slot_rva
            root.iat_slot_value = slot_val
            if imp:
                root.iat_name = imp.name_for_slot(slot_rva)
            if slot_rva < 0x6D000 or slot_rva >= 0x70000:
                root.note = "IAT slot outside .idata — likely bad rip target"
            elif slot_val < 0x10000:
                root.note = "IAT slot empty or unresolved"
            return root

    # E8 rel32
    if m == "call" and not op_l.startswith("qword") and not op_l.startswith("0x"):
        raw = read_process_mem(proc, rip, 5)
        if len(raw) == 5 and raw[0] == 0xE8:
            rel = int.from_bytes(raw[1:5], "little", signed=True)
            tgt = rip + 5 + rel
            root.kind = "direct"
            root.target_va = tgt
            root.target_label = fmt_module_addr(tgt, main_base)
            head = read_process_mem(proc, tgt, 3)
            if head != b"\x55\x48\x89" and head[:2] != b"\x41\x55":
                root.note = "mid-function entry? run scan_call_targets.py"
            return root

    # call/jmp reg
    reg_vals = _ctx_args(ctx)
    if op_l in reg_vals:
        val = reg_vals[op_l]
        root.kind = "indirect-reg"
        root.target_va = val
        root.target_label = fmt_module_addr(val, main_base)
        if val < 0x10000:
            root.note = f"{op} is NULL — common CRT/IAT bug"
        elif is_probably_stack(val, ctx.Rsp, ctx.Rbp):
            root.note = f"{op} points into stack"
        return root

    # Capstone immediate target
    if op_l.startswith("0x"):
        try:
            tgt = int(op, 16)
            root.kind = "direct"
            root.target_va = tgt
            root.target_label = fmt_module_addr(tgt, main_base)
            return root
        except ValueError:
            pass
    return root


def callroot_from_return(proc, ret_va: int, ctx: CONTEXT, main_base: int | None,
                         imp: PeImportMap | None = None) -> CallRoot | None:
    """Resolve the call/jmp at *ret_va* (return address = byte after call)."""
    cs = find_callsite_before(proc, ret_va)
    if not cs:
        return None
    root = analyze_insn_call(proc, cs.address, ctx, main_base, imp)
    if root and main_base:
        root.return_rva = ret_va - main_base
        root.callsite_rva = cs.address - main_base
    return root


def build_return_chain(proc, ctx: CONTEXT, main_base: int | None,
                       imp: PeImportMap | None = None,
                       limit: int = 12) -> list[CallRoot]:
    """Stack return addresses in the main image → call roots with register snapshot."""
    if not main_base:
        return []
    out: list[CallRoot] = []
    for off, ra in scan_image_returns(proc, ctx.Rsp, main_base, limit=limit):
        root = callroot_from_return(proc, ra, ctx, main_base, imp)
        if root:
            root.kind = root.kind or "ret-chain"
            out.append(root)
    return out


def format_call_root(root: CallRoot, main_base: int | None = None) -> str:
    """Single-line summary of a call root."""
    site = f"main+0x{root.callsite_rva:X}" if root.callsite_rva else "?"
    ret = f"ret=main+0x{root.return_rva:X}" if root.return_rva else ""
    insn = f"{root.mnemonic} {root.op_str}".strip()
    parts = [f"  [{root.kind or '?'}] {site}  {insn}"]
    if ret:
        parts.append(ret)
    if root.iat_slot_rva:
        name = f" ({root.iat_name})" if root.iat_name else ""
        parts.append(f"slot=main+0x{root.iat_slot_rva:X}{name}")
        parts.append(f"slot_val=0x{root.iat_slot_value:X}")
    if root.target_label:
        parts.append(f"-> {root.target_label}")
    if root.args:
        arg_s = " ".join(f"{k}=0x{v:X}" for k, v in (
            ("rcx", root.args.get("rcx", 0)),
            ("rdx", root.args.get("rdx", 0)),
            ("r8", root.args.get("r8", 0)),
            ("rax", root.args.get("rax", 0)),
            ("rdi", root.args.get("rdi", 0)),
            ("rsi", root.args.get("rsi", 0)),
        ) if v)
        if arg_s:
            parts.append(f"args: {arg_s}")
    if root.note:
        parts.append(f"({root.note})")
    return "  ".join(parts)


def print_call_roots(title: str, roots: list[CallRoot],
                     main_base: int | None = None) -> None:
    if not roots:
        return
    print(f"\n--- {title} ({len(roots)}) ---")
    for i, root in enumerate(roots, 1):
        print(f"  #{i} {format_call_root(root, main_base)}")


def print_register_block(ctx: CONTEXT, prefix: str = "  ") -> None:
    print(f"{prefix}RAX=0x{ctx.Rax:016X} RBX=0x{ctx.Rbx:016X} "
          f"RCX=0x{ctx.Rcx:016X} RDX=0x{ctx.Rdx:016X}")
    print(f"{prefix}RSI=0x{ctx.Rsi:016X} RDI=0x{ctx.Rdi:016X} "
          f"R8 =0x{ctx.R8:016X} R9 =0x{ctx.R9:016X}")
    print(f"{prefix}RBP=0x{ctx.Rbp:016X} RSP=0x{ctx.Rsp:016X}")


EXCEPTION_NAMES = {
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000096: "PRIV_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000409: "STACK_BUFFER_OVERRUN",
    0x80000003: "BREAKPOINT",
    0x80000004: "SINGLE_STEP",
}


def main():
    suppress_fault_ui()
    raw = sys.argv[1:]
    TRACE = "--trace" in raw
    raw = [a for a in raw if a != "--trace"]
    if not raw:
        print("usage: dbg_fault.py [--trace] <exe> [args...]")
        return 2
    exe = raw[0]
    args = raw[1:]

    # Run in an isolated temp dir alongside the shim DLL so imports resolve.
    cmdline = '"%s" %s' % (exe, " ".join(args))
    si = STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = PROCESS_INFORMATION()

    CreateProcessW = k32.CreateProcessW
    CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, C.c_void_p,
                               C.c_void_p, wintypes.BOOL, wintypes.DWORD,
                               C.c_void_p, wintypes.LPCWSTR,
                               C.POINTER(STARTUPINFO), C.POINTER(PROCESS_INFORMATION)]
    ok = CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
                        DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe) or None,
                        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    dll_bases = {}
    ReadProcessMemory = k32.ReadProcessMemory
    ReadProcessMemory.argtypes = [wintypes.HANDLE, C.c_void_p, C.c_void_p,
                                  C.c_size_t, C.POINTER(C.c_size_t)]

    def read_mem(proc, addr, size):
        buf = (C.c_char * size)()
        n = C.c_size_t(0)
        if ReadProcessMemory(proc, C.c_void_p(addr), buf, size, C.byref(n)):
            return bytes(buf[:n.value])
        return b""

    trace_ring = []  # last RIPs (rva if in main image else absolute)
    trace_steps = 0
    TRACE_MAX = 500_000

    def set_trace_flag():
        ctx = CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL
        if k32.GetThreadContext(pi.hThread, C.byref(ctx)):
            ctx.EFlags |= 0x100  # TF
            k32.SetThreadContext(pi.hThread, C.byref(ctx))

    de = DEBUG_EVENT()
    first_chance_seen = 0
    while True:
        if not k32.WaitForDebugEvent(C.byref(de), INFINITE):
            break
        code = de.dwDebugEventCode
        status = DBG_CONTINUE
        if code == CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"[base] main image @ 0x{base:016X}")
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
        elif code == LOAD_DLL_DEBUG_EVENT:
            b = de.u.LoadDll.lpBaseOfDll
            namep = de.u.LoadDll.lpImageName
            nm = "?"
            if namep:
                ptr = read_mem(pi.hProcess, namep, 8)
                if len(ptr) == 8:
                    strptr = int.from_bytes(ptr, "little")
                    if strptr:
                        raw = read_mem(pi.hProcess, strptr, 260 * 2)
                        try:
                            nm = raw.decode("utf-16-le", "ignore").split("\x00")[0]
                        except Exception:
                            nm = "?"
            dll_bases[b] = nm
            h = de.u.LoadDll.hFile
            if h:
                k32.CloseHandle(h)
        elif code == OUTPUT_DEBUG_STRING_INFO if False else code == OUTPUT_DEBUG_STRING_EVENT:
            pass
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print(f"[exit] code=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08X}")
            break
        elif code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            first = de.u.Exception.dwFirstChance
            addr = er.ExceptionAddress or 0
            # Ignore the initial breakpoint (ntdll) — let it continue.
            if ecode == 0x80000003 and first_chance_seen == 0:
                first_chance_seen = 1
                status = DBG_CONTINUE
                if TRACE:
                    set_trace_flag()
            elif TRACE and ecode == 0x80000004:  # single-step
                trace_steps += 1
                ctx = CONTEXT()
                ctx.ContextFlags = CONTEXT_FULL
                if k32.GetThreadContext(pi.hThread, C.byref(ctx)):
                    rip = ctx.Rip
                    if base and base <= rip < base + 0x200000:
                        trace_ring.append(("img", rip - base, ctx.Rsp))
                    else:
                        trace_ring.append(("ext", rip, ctx.Rsp))
                    if len(trace_ring) > 80:
                        trace_ring.pop(0)
                if trace_steps < TRACE_MAX:
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                status = DBG_CONTINUE
            else:
                print("\n===== EXCEPTION =====")
                print(f"code=0x{ecode:08X} firstchance={first} addr=0x{addr:016X}")
                if base:
                    print(f"main base=0x{base:016X} rva=0x{(addr-base)&0xFFFFFFFFFFFFFFFF:X}")
                print("--- loaded modules ---")
                for b, nm in sorted(dll_bases.items()):
                    print(f"  0x{b:016X}  {nm}")
                # which module
                owner = None
                for b, nm in sorted(dll_bases.items()):
                    if addr >= b:
                        owner = (b, nm)
                if base and addr >= base and (owner is None or base > owner[0]):
                    owner = (base, "<main>")
                if owner:
                    print(f"module={owner[1]} modbase=0x{owner[0]:016X} "
                          f"off=0x{addr-owner[0]:X}")
                if ecode == 0xC0000005 and er.NumberParameters >= 2:
                    op = er.ExceptionInformation[0]
                    fault = er.ExceptionInformation[1] & 0xFFFFFFFFFFFFFFFF
                    kind = {0: "read", 1: "write", 8: "execute"}.get(op, str(op))
                    print(f"access-violation: {kind} @ 0x{fault:016X}")
                # registers
                ctx = CONTEXT()
                ctx.ContextFlags = CONTEXT_FULL
                if k32.GetThreadContext(pi.hThread, C.byref(ctx)):
                    print(f"RIP=0x{ctx.Rip:016X} RSP=0x{ctx.Rsp:016X} RBP=0x{ctx.Rbp:016X}")
                    print(f"RAX=0x{ctx.Rax:016X} RCX=0x{ctx.Rcx:016X} "
                          f"RDX=0x{ctx.Rdx:016X} RBX=0x{ctx.Rbx:016X}")
                    print(f"RSI=0x{ctx.Rsi:016X} RDI=0x{ctx.Rdi:016X} "
                          f"R8=0x{ctx.R8:016X} R9=0x{ctx.R9:016X}")
                    code_bytes = read_mem(pi.hProcess, ctx.Rip, 24)
                    print("bytes@RIP:", code_bytes.hex())
                    stack = read_mem(pi.hProcess, ctx.Rsp, 64)
                    print("stack@RSP:", stack.hex())
                    # IAT / runtime table slots of interest (cmd pure).
                    for slot, label in (
                            (0x800A63E0, "GetProcessHeap"),
                            (0x800A63D8, "HeapAlloc?"),
                            (0x800A6590, "FormatMessageW"),
                            (0x800A6490, "GetEnvStringsW"),
                            (0x8007AFB8, "bump-table@afb8"),
                            (0x8007AFBC, "bump-table@afbc"),
                            (0x8007AFC0, "bump-table@afc0")):
                        q = read_mem(pi.hProcess, slot, 8)
                        v = int.from_bytes(q, "little") if len(q) == 8 else None
                        print(f"mem[{slot:#x}] ({label}) = "
                              f"{('0x%016X' % v) if v is not None else '?'}")
                    # Walk the stack for return addresses inside the main image.
                    img_lo = base or 0
                    img_hi = img_lo + 0x200000
                    deep = read_mem(pi.hProcess, ctx.Rsp, 0x600)
                    print("--- stack return addrs in main image ---")
                    seen_ra = 0
                    for k in range(0, len(deep) - 8, 8):
                        q = int.from_bytes(deep[k:k + 8], "little")
                        if img_lo <= q < img_hi:
                            print(f"  [rsp+0x{k:03x}] = 0x{q:016X}  rva=0x{q-img_lo:X}")
                            seen_ra += 1
                            if seen_ra >= 12:
                                break
                if TRACE:
                    print(f"--- last {len(trace_ring)} instrs (steps={trace_steps}) ---")
                    for kind, val, sp in trace_ring[-40:]:
                        if kind == "img":
                            print(f"  img rva=0x{val:X}  rsp=0x{sp:X}")
                        else:
                            print(f"  ext 0x{val:016X}  rsp=0x{sp:X}")
                status = DBG_EXCEPTION_NOT_HANDLED
                # Kill after first real exception.
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                k32.TerminateProcess(pi.hProcess, 1)
                break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
