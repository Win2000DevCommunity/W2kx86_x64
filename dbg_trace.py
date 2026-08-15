"""Smart step-over tracer for the x86->x64 translator output.

Unlike ``dbg_fault --trace`` (which single-steps EVERY instruction, including
the millions inside ntdll/kernel32 and therefore never reaches the real fault),
this tracer single-steps ONLY the main translated image and runs system DLLs at
full speed.

Technique (classic "step over"): while RIP is inside the main image we keep the
trap flag (TF) set and record each instruction. As soon as RIP leaves the main
image (e.g. right after ``call qword [iat]``), the return address sits at [RSP];
we drop a one-shot INT3 breakpoint there, clear TF and let the system code run
free. When the breakpoint fires we restore the byte, re-arm TF and continue.

On the first real exception it prints:
  * faulting RIP / access info / registers
  * the last N main-image instructions (disassembled) leading into the fault
  * the call/return chain inside the main image

Usage:
    python dbg_trace.py <exe> [args...] [--ring=120] [--seconds=20]
"""
from __future__ import annotations

import ctypes as C
import os
import sys
import time
from ctypes import wintypes

import dbg_fault as df

k32 = df.k32


def _disasm_one(proc, rip: int):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        return None
    raw = df.read_process_mem(proc, rip, 16)
    if not raw:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(raw, rip):
        return ins
    return None


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little") if len(b) >= o + 4 else 0


def _dll_name_from_handle(h) -> str:
    try:
        GetFinalPathNameByHandleW = k32.GetFinalPathNameByHandleW
        buf = C.create_unicode_buffer(520)
        n = GetFinalPathNameByHandleW(h, buf, 520, 0)
        if n:
            return os.path.basename(buf.value.rstrip("\x00"))
    except Exception:
        pass
    return "?"


def _build_exports(proc, base: int):
    """Return (size_of_image, sorted[(abs_addr, name)]) for a loaded module."""
    hdr = df.read_process_mem(proc, base, 0x40)
    if len(hdr) < 0x40 or hdr[:2] != b"MZ":
        return 0x100000, []
    e_lfanew = _u32(hdr, 0x3C)
    nt = df.read_process_mem(proc, base + e_lfanew, 0x108)
    if len(nt) < 0x100 or nt[:4] != b"PE\x00\x00":
        return 0x100000, []
    # OptionalHeader starts at nt+24; PE32+ SizeOfImage @ +0x38, export dir @ +0x70
    size_img = _u32(nt, 24 + 0x38) or 0x100000
    exp_rva = _u32(nt, 24 + 0x70)
    exp_size = _u32(nt, 24 + 0x74)
    if not exp_rva or not exp_size:
        return size_img, []
    ed = df.read_process_mem(proc, base + exp_rva, 0x28)
    if len(ed) < 0x28:
        return size_img, []
    n_names = _u32(ed, 0x18)
    aof = _u32(ed, 0x1C)      # AddressOfFunctions
    aon = _u32(ed, 0x20)      # AddressOfNames
    aoo = _u32(ed, 0x24)      # AddressOfNameOrdinals
    if n_names <= 0 or n_names > 0x8000:
        return size_img, []
    names_rva = df.read_process_mem(proc, base + aon, 4 * n_names)
    ords = df.read_process_mem(proc, base + aoo, 2 * n_names)
    out = []
    for i in range(n_names):
        nr = _u32(names_rva, i * 4)
        if not nr:
            continue
        nm = df.read_process_mem(proc, base + nr, 64)
        nm = nm.split(b"\x00", 1)[0].decode("latin1", "replace")
        ordi = int.from_bytes(ords[i * 2:i * 2 + 2], "little")
        fr = _u32(df.read_process_mem(proc, base + aof + ordi * 4, 4), 0)
        if fr:
            out.append((base + fr, nm))
    out.sort()
    return size_img, out


def _wstr(proc, ptr: int, maxlen: int = 80) -> str:
    """Preview a wide (UTF-16LE) string at *ptr*; '' if it doesn't look like one."""
    if not (0x10000 <= ptr < 0x7FFF_FFFF_FFFF):
        return ""
    raw = df.read_process_mem(proc, ptr, maxlen * 2) or b""
    if not raw:
        return ""
    s = raw.decode("utf-16le", "replace")
    nul = s.find("\x00")
    if nul >= 0:
        s = s[:nul]
    if not s:
        return ""
    # Reject buffers that are mostly non-text (likely not a string pointer).
    printable = sum(1 for c in s if 0x20 <= ord(c) < 0x7F or c in "\t")
    if printable < max(1, len(s) - 1):
        return ""
    return s


def _resolve_addr(modules, addr: int) -> str:
    """addr -> 'dll!Export(+off)' using sorted module export tables."""
    import bisect
    for lo, hi, name, exps in modules:
        if lo <= addr < hi:
            if exps:
                idx = bisect.bisect_right(exps, (addr, "\xff")) - 1
                if 0 <= idx < len(exps):
                    ea, en = exps[idx]
                    d = addr - ea
                    if d == 0:
                        return f"{name}!{en}"
                    if d < 0x800:
                        return f"{name}!{en}+0x{d:X}"
            return f"{name}+0x{addr - lo:X}"
    return f"0x{addr:X}"


def _load_rva_revmap(path: str) -> dict[int, int]:
    """Build translated_rva -> x86_rva from rva.txt."""
    rev: dict[int, int] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                pp = ln.replace(",", " ").split()
                if len(pp) < 2:
                    continue
                try:
                    x86 = int(pp[0], 16)
                    tr = int(pp[1], 16)
                except ValueError:
                    continue
                rev[tr] = x86
    except OSError:
        pass
    return rev


_HEAP_MD = None
_HEAP_REGMAP: dict = {}


def _heap_md():
    """Lazily build a detailed 64-bit capstone decoder + reg->CONTEXT map."""
    global _HEAP_MD, _HEAP_REGMAP
    if _HEAP_MD is not None:
        return _HEAP_MD
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone import x86 as _x
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    _HEAP_REGMAP = {
        _x.X86_REG_RAX: "Rax", _x.X86_REG_RBX: "Rbx", _x.X86_REG_RCX: "Rcx",
        _x.X86_REG_RDX: "Rdx", _x.X86_REG_RSI: "Rsi", _x.X86_REG_RDI: "Rdi",
        _x.X86_REG_RBP: "Rbp", _x.X86_REG_RSP: "Rsp", _x.X86_REG_R8: "R8",
        _x.X86_REG_R9: "R9", _x.X86_REG_R10: "R10", _x.X86_REG_R11: "R11",
        _x.X86_REG_R12: "R12", _x.X86_REG_R13: "R13", _x.X86_REG_R14: "R14",
        _x.X86_REG_R15: "R15", _x.X86_REG_RIP: "Rip",
    }
    _HEAP_MD = md
    return md


def _decode_write(code: bytes, addr: int):
    """Return a write descriptor for the instruction at *addr*, or None.

    Descriptor: (base_ctx, index_ctx, scale, disp, wsize, is_string, mnemonic).
    ``base_ctx``/``index_ctx`` are CONTEXT attribute names or None.
    ``is_string`` marks rep-able string stores (stos/movs) writing to [rdi]."""
    from capstone import x86 as _x
    md = _heap_md()
    for ins in md.disasm(code, addr):
        mn = ins.mnemonic
        if mn.startswith("stos") or mn.startswith("movs"):
            sz = {"b": 1, "w": 2, "d": 4, "q": 8}.get(mn[-1], 1)
            return ("Rdi", None, 1, 0, sz, True, mn)
        try:
            for op in ins.operands:
                if op.type != _x.X86_OP_MEM:
                    continue
                if not (op.access & _x.CS_AC_WRITE):
                    continue
                m = op.mem
                base = _HEAP_REGMAP.get(m.base)
                index = _HEAP_REGMAP.get(m.index)
                if m.base and base is None:
                    return None  # segment/unknown base (gs:, rip already mapped)
                return (base, index, m.scale, m.disp, op.size or 8, False, mn)
        except Exception:
            return None
        return None
    return None


def _x86_hint(rev: dict[int, int], tr_rva: int) -> str:
    """Nearest x86 RVA for a translated offset (exact or floor in rev map)."""
    if tr_rva in rev:
        return f"x86 0x{rev[tr_rva]:X}"
    if not rev:
        return ""
    keys = sorted(rev)
    import bisect
    j = bisect.bisect_right(keys, tr_rva) - 1
    if j < 0:
        return ""
    k = keys[j]
    return f"x86 0x{rev[k]:X}+0x{tr_rva - k:X}"


def main() -> int:
    df.suppress_fault_ui()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = sys.argv[1:]
    ring_max = 160
    seconds = 25.0
    show = 48
    watch = None
    guard_rva = None        # arm a stack-relative memory watch when RIP hits this RVA
    guard_off = 0x68        # watch [rsp_at_entry - guard_off] (saved-rbp slot)
    rva_map_path = None
    apilog = False
    apilog_max = 4000
    heapguard = False       # track heap allocs/frees + flag OOB / use-after-free writes
    heap_report_max = 40
    # First-chance exception codes to pass through (debugger-only artifacts).
    pass_codes = {0xC0000008}  # STATUS_INVALID_HANDLE (NtClose under debugger)
    rest = []
    for a in argv:
        if a.startswith("--ring="):
            ring_max = int(a.split("=", 1)[1])
        elif a.startswith("--seconds="):
            seconds = float(a.split("=", 1)[1])
        elif a.startswith("--show="):
            show = int(a.split("=", 1)[1])
        elif a.startswith("--watch="):
            watch = [int(t, 0) for t in a.split("=", 1)[1].split(",") if t.strip()]
        elif a.startswith("--guardrva="):
            guard_rva = int(a.split("=", 1)[1], 0)
        elif a.startswith("--guardoff="):
            guard_off = int(a.split("=", 1)[1], 0)
        elif a.startswith("--rva-map="):
            rva_map_path = a.split("=", 1)[1]
        elif a == "--apilog":
            apilog = True
        elif a == "--heapguard":
            heapguard = True
        elif a.startswith("--heapmax="):
            heap_report_max = int(a.split("=", 1)[1])
        elif a.startswith("--apimax="):
            apilog_max = int(a.split("=", 1)[1])
        elif a.startswith("--pass="):
            for tok in a.split("=", 1)[1].split(","):
                tok = tok.strip()
                if tok:
                    pass_codes.add(int(tok, 0) & 0xFFFFFFFF)
        elif a == "--no-pass":
            pass_codes = set()
        else:
            rest.append(a)
    if not rest:
        print("usage: dbg_trace.py <exe> [args...] [--ring=N] [--seconds=S]")
        return 2
    exe = os.path.abspath(rest[0])
    args = rest[1:]
    cmdline = '"%s" %s' % (exe, " ".join(args))

    entry_rva = 0
    try:
        import pefile
        _pe = pefile.PE(exe, fast_load=True)
        entry_rva = _pe.OPTIONAL_HEADER.AddressOfEntryPoint
        _pe.close()
    except Exception:
        pass

    si = df.STARTUPINFO()
    si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    CreateProcessW = k32.CreateProcessW
    CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, C.c_void_p,
                               C.c_void_p, wintypes.BOOL, wintypes.DWORD,
                               C.c_void_p, wintypes.LPCWSTR,
                               C.POINTER(df.STARTUPINFO),
                               C.POINTER(df.PROCESS_INFORMATION)]
    ok = CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS | df.CREATE_NEW_CONSOLE,
                        None, os.path.dirname(exe) or None,
                        C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", C.get_last_error())
        return 1

    base = None
    img_lo = img_hi = 0
    dll_bases: dict[int, str] = {}
    modules: list = []          # (lo, hi, name, sorted_exports) for --apilog
    api_count = [0]
    guard_state = [0, None, 0, 0]   # [watch_addr, last_val, entry_count, report_count]
    # Heap-guard state.
    live_allocs: dict[int, int] = {}       # ptr -> requested size
    freed_blocks: list[tuple[int, int]] = []   # recent (ptr, size) for UAF detection
    pending_alloc = [None]                 # requested size awaiting the return value
    heap_reports = [0]
    heap_decode_cache: dict[int, object] = {}   # rva -> write descriptor or None
    rva_rev = _load_rva_revmap(rva_map_path) if rva_map_path else {}
    ring: list[tuple[int, int, int]] = []     # (rva, rsp, rbp)
    rbp_corrupt_at: list[tuple[int, int, int]] = []  # (rva, prev_rbp, new_rbp)
    prev_rbp = [0]
    callchain: list[str] = []
    tf_on = False
    bp_addr = 0
    bp_orig = b""
    entry_bp = 0
    entry_orig = b""
    tracing = False
    steps = 0
    started = time.time()

    def in_main(addr: int) -> bool:
        return bool(base) and img_lo <= addr < img_hi

    def set_tf(on: bool) -> None:
        nonlocal tf_on
        ctx = df.CONTEXT()
        ctx.ContextFlags = df.CONTEXT_FULL
        if not k32.GetThreadContext(pi.hThread, C.byref(ctx)):
            return
        if on:
            ctx.EFlags |= 0x100
        else:
            ctx.EFlags &= ~0x100
        k32.SetThreadContext(pi.hThread, C.byref(ctx))
        tf_on = on

    def write_mem(addr: int, data: bytes) -> bool:
        old = wintypes.DWORD(0)
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(addr & ~0xFFF), 0x1000,
                             0x40, C.byref(old))
        n = C.c_size_t(0)
        buf = (C.c_char * len(data))(*data)
        ok2 = k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), buf,
                                     len(data), C.byref(n))
        k32.VirtualProtectEx(pi.hProcess, C.c_void_p(addr & ~0xFFF), 0x1000,
                             old.value, C.byref(old))
        return bool(ok2)

    def arm_bp(addr: int) -> None:
        nonlocal bp_addr, bp_orig
        orig = df.read_process_mem(pi.hProcess, addr, 1)
        if len(orig) == 1:
            bp_orig = orig
            bp_addr = addr
            write_mem(addr, b"\xCC")

    def clear_bp() -> None:
        nonlocal bp_addr, bp_orig
        if bp_addr and bp_orig:
            write_mem(bp_addr, bp_orig)
        bp_addr = 0
        bp_orig = b""

    def report(ctx, ecode, fault_info) -> None:
        print("\n===== FAULT =====")
        rip = ctx.Rip
        print(f"code=0x{ecode:08X} RIP=0x{rip:016X} "
              f"({df.fmt_module_addr(rip, base)})")
        if fault_info:
            op, fa = fault_info
            kind = {0: "read", 1: "write", 8: "execute"}.get(op, str(op))
            print(f"access-violation: {kind} @ 0x{fa:016X}")
        df.print_register_block(ctx)
        ins = _disasm_one(pi.hProcess, rip)
        if ins:
            print(f"insn@RIP: {ins.mnemonic} {ins.op_str}")
        if ring:
            cs = ring[-1][0]
            hint = _x86_hint(rva_rev, cs)
            if hint:
                print(f"last main insn: main+0x{cs:X}  ({hint})")
        s1 = _wstr(pi.hProcess, ctx.Rcx)
        s2 = _wstr(pi.hProcess, ctx.Rdx)
        if s1 or s2:
            parts = []
            if s1:
                parts.append(f"rcx={s1!r}")
            if s2:
                parts.append(f"rdx={s2!r}")
            print("string-args: " + " ".join(parts))
        if rva_rev and ring:
            print("\n--- x86 reverse map (last main insns) ---")
            for rva, sp, bp in ring[-min(len(ring), show):]:
                print(f"  main+0x{rva:X}  {_x86_hint(rva_rev, rva)}")
        if rbp_corrupt_at:
            print("\n--- RBP corruption events (stack -> garbage) ---")
            for rva, pr, cur in rbp_corrupt_at[-6:]:
                di = _disasm_one(pi.hProcess, base + rva)
                txt = f"{di.mnemonic} {di.op_str}" if di else "?"
                print(f"  main+0x{rva:<6X}  RBP 0x{pr:X} -> 0x{cur:X}   {txt}")
        print(f"\n--- last {min(len(ring), show)} main-image instructions "
              f"(steps={steps}) ---")
        for rva, sp, bp in ring[-show:]:
            di = _disasm_one(pi.hProcess, base + rva)
            txt = f"{di.mnemonic} {di.op_str}" if di else "?"
            print(f"  main+0x{rva:<6X} rsp=0x{sp:X} rbp=0x{bp:X}  {txt}")
        # main-image return chain
        deep = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x400)
        print("--- stack return addrs (main image) ---")
        seen = 0
        for kk in range(0, len(deep) - 8, 8):
            q = int.from_bytes(deep[kk:kk + 8], "little")
            if in_main(q):
                di = _disasm_one(pi.hProcess, q)
                txt = f"{di.mnemonic} {di.op_str}" if di else "?"
                print(f"  [rsp+0x{kk:03X}] main+0x{q-base:<6X}  {txt}")
                seen += 1
                if seen >= 12:
                    break

    de = df.DEBUG_EVENT()
    first_bp_seen = False
    while True:
        if time.time() - started > seconds:
            print(f"\n[timeout after {seconds}s, steps={steps}] no fault — "
                  f"process still running")
            ctx = df.get_thread_context(pi.hThread)
            print(f"  RIP=0x{ctx.Rip:016X} ({df.fmt_module_addr(ctx.Rip, base)})")
            print(f"  RAX=0x{ctx.Rax:X} RBX=0x{ctx.Rbx:X} RCX=0x{ctx.Rcx:X} "
                  f"RDX=0x{ctx.Rdx:X}")
            print(f"  RSI=0x{ctx.Rsi:X} RDI=0x{ctx.Rdi:X} RSP=0x{ctx.Rsp:X} "
                  f"RBP=0x{ctx.Rbp:X} R8=0x{ctx.R8:X} R9=0x{ctx.R9:X}")
            for lbl, addr in (("RAX", ctx.Rax), ("RBP", ctx.Rbp),
                              ("RCX", ctx.Rcx)):
                mem = df.read_process_mem(pi.hProcess, addr, 0x40)
                if mem:
                    print(f"  mem@{lbl}: {mem[:0x40].hex()}")
            for slot in (0x800A6490, 0x800A6590, 0x800A63E0):
                q = df.read_process_mem(pi.hProcess, slot, 8)
                if q:
                    print(f"  slot[{slot:#x}] = "
                          f"{int.from_bytes(q, 'little'):#x}")
            print(f"\n--- last {min(len(ring), show)} main-image instructions ---")
            for rva, sp, bp in ring[-show:]:
                di = _disasm_one(pi.hProcess, base + rva)
                txt = f"{di.mnemonic} {di.op_str}" if di else "?"
                print(f"  main+0x{rva:<6X} rsp=0x{sp:X} rbp=0x{bp:X}  {txt}")
            k32.TerminateProcess(pi.hProcess, 0)
            break
        if not k32.WaitForDebugEvent(C.byref(de), 200):
            continue
        code = de.dwDebugEventCode
        status = df.DBG_CONTINUE
        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            img_lo, img_hi = base, base + 0x200000
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
            print(f"[base] 0x{base:016X} entry=main+0x{entry_rva:X}")
            if entry_rva:
                entry_bp = base + entry_rva
                orig = df.read_process_mem(pi.hProcess, entry_bp, 1)
                if len(orig) == 1:
                    entry_orig = orig
                    write_mem(entry_bp, b"\xCC")
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            dbase = de.u.LoadDll.lpBaseOfDll
            h = de.u.LoadDll.hFile
            nm = _dll_name_from_handle(h) if (apilog and h) else "?"
            dll_bases[dbase] = nm
            if apilog and dbase:
                try:
                    sz, exps = _build_exports(pi.hProcess, dbase)
                    modules.append((dbase, dbase + sz, nm, exps))
                except Exception:
                    pass
            if h:
                k32.CloseHandle(h)
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"[exit] 0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08X} "
                  f"steps={steps}")
            if ring:
                print(f"\n--- last {min(len(ring), show)} main-image instructions "
                      f"(exit ring) ---")
                for rva, sp, bp in ring[-show:]:
                    di = _disasm_one(pi.hProcess, base + rva)
                    txt = f"{di.mnemonic} {di.op_str}" if di else "?"
                    print(f"  main+0x{rva:<6X} rsp=0x{sp:X} rbp=0x{bp:X}  {txt}")
            break
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            first = de.u.Exception.dwFirstChance
            addr = er.ExceptionAddress or 0
            if ecode == 0x80000003:  # breakpoint
                if not first_bp_seen:
                    first_bp_seen = True
                    # If we have an entry breakpoint, wait for it; otherwise trace now.
                    if not entry_bp:
                        tracing = True
                        set_tf(True)
                    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                    continue
                # main entry breakpoint → begin tracing here
                if entry_bp and addr == entry_bp:
                    write_mem(entry_bp, entry_orig)
                    ctx = df.get_thread_context(pi.hThread)
                    ctx.Rip = addr
                    ctx.ContextFlags = df.CONTEXT_FULL
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                    entry_bp = 0
                    tracing = True
                    set_tf(True)
                    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                    continue
                # our one-shot step-over breakpoint?
                if bp_addr and addr == bp_addr:
                    clear_bp()
                    ctx = df.get_thread_context(pi.hThread)
                    ctx.Rip = addr  # rewind past int3
                    ctx.ContextFlags = df.CONTEXT_FULL
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                    if tracing:
                        set_tf(True)
                    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                    continue
                # foreign breakpoint
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                continue
            if ecode == 0x80000004:  # single step
                steps += 1
                ctx = df.get_thread_context(pi.hThread)
                rip = ctx.Rip
                if in_main(rip):
                    ring.append((rip - base, ctx.Rsp, ctx.Rbp))
                    if len(ring) > ring_max:
                        ring.pop(0)
                    # Detect RBP corruption: stack-like -> non-stack-like.
                    pr = prev_rbp[0]
                    cur = ctx.Rbp
                    if (pr and 0x10000 <= pr < 0x10000000
                            and not (0x10000 <= cur < 0x10000000)):
                        rbp_corrupt_at.append((rip - base, pr, cur))
                    prev_rbp[0] = cur
                    # --- Universal JCC / epilogue integrity diagnostics ---
                    # Detect Jcc taken to a short pop-ret island (the class of
                    # bug fixed by _pure_fix_jcc_short_pop_ret_to_local_leave_epi).
                    # If the previous insn was a taken conditional jump, check
                    # whether rip lands on a bare pop*; ret sequence.
                    if len(ring) >= 2:
                        prev_rva, prev_rsp, prev_rbp2 = ring[-2]
                        prev_raw = df.read_process_mem(pi.hProcess, base + prev_rva, 8) or b""
                        if prev_raw:
                            is_jcc = (
                                (prev_raw[0] == 0x0F and prev_raw[1] in range(0x80, 0x90))
                                or prev_raw[0] in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
                                                   0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B,
                                                   0x7C, 0x7D, 0x7E, 0x7F)
                                or prev_raw[0] == 0xE3
                            )
                            if is_jcc:
                                jcc_rva = rip - base
                                jcc_raw = df.read_process_mem(
                                    pi.hProcess, rip, 12) or b""
                                # Check if landing on a short pop*; ret island:
                                # pop(s) then ret, with no mov eax,* or leave.
                                if jcc_raw:
                                    pops = 0
                                    scan = 0
                                    while scan < min(len(jcc_raw), 6):
                                        b = jcc_raw[scan]
                                        if 0x58 <= b <= 0x5F:
                                            pops += 1; scan += 1; continue
                                        if b == 0x41 and scan + 1 < len(jcc_raw) and 0x58 <= jcc_raw[scan + 1] <= 0x5F:
                                            pops += 1; scan += 2; continue
                                        if b in (0xC3, 0xC2) and pops >= 1:
                                            hint = _x86_hint(rva_rev, jcc_rva)
                                            print(f"[SHORT-EPI-JCC] main+0x{prev_rva:X} "
                                                  f"jcc->main+0x{jcc_rva:X} {hint} "
                                                  f"lands on pop*{pops};ret "
                                                  f"(rbp=0x{ctx.Rbp:X} rsp=0x{ctx.Rsp:X})")
                                            break
                                        break
                    # Detect ret with broken RBP / RSP alignment
                    cur_raw = df.read_process_mem(pi.hProcess, rip, 2) or b""
                    if cur_raw and cur_raw[0] in (0xC3, 0xC2, 0xCA, 0xCB):
                        if ctx.Rsp & 0xF:
                            hint = _x86_hint(rva_rev, rip - base)
                            print(f"[RET-MISALIGN] main+0x{rip-base:X} {hint} "
                                  f"ret with RSP=0x{ctx.Rsp:X} (misaligned)")
                        if ctx.Rbp and not (0x10000 <= ctx.Rbp < 0x10000000):
                            hint = _x86_hint(rva_rev, rip - base)
                            print(f"[RET-BAD-RBP] main+0x{rip-base:X} {hint} "
                                  f"ret with RBP=0x{ctx.Rbp:X} (non-stack)")
                    # Detect suspicious register values common in translation bugs
                    # 0x4000 is the Win2K image base sentinel; -11/-1 are common
                    # error returns used as pointers.
                    for reg_name, reg_val in [("RBX", ctx.Rbx), ("RBP", ctx.Rbp),
                                              ("R8", ctx.R8), ("R9", ctx.R9)]:
                        if reg_val in (0x4000, 0xFFFFFFFFFFFFFFF5, 0xFFFFFFFFFFFFFFFF):
                            hint = _x86_hint(rva_rev, rip - base)
                            print(f"[SUSPICIOUS-REG] main+0x{rip-base:X} {hint} "
                                  f"{reg_name}=0x{reg_val:X}")
                    if heapguard:
                        # Capture the pointer returned by a just-completed alloc
                        # (rax holds it on the first main insn after return).
                        if pending_alloc[0] is not None:
                            p = ctx.Rax
                            if p:
                                live_allocs[p] = pending_alloc[0]
                                freed_blocks[:] = [(fp, fs) for (fp, fs)
                                                   in freed_blocks if fp != p]
                            pending_alloc[0] = None
                        if live_allocs or freed_blocks:
                            rva = rip - base
                            desc = heap_decode_cache.get(rva, 0)
                            if desc == 0:
                                raw = df.read_process_mem(pi.hProcess, rip, 16) or b""
                                desc = _decode_write(raw, rip) if raw else None
                                heap_decode_cache[rva] = desc
                            if desc is not None:
                                base_ctx, idx_ctx, scale, disp, wsize, is_str, mn = desc
                                ea = disp & 0xFFFFFFFFFFFFFFFF
                                if base_ctx:
                                    ea = (ea + getattr(ctx, base_ctx)) & 0xFFFFFFFFFFFFFFFF
                                if idx_ctx:
                                    ea = (ea + getattr(ctx, idx_ctx) * scale) & 0xFFFFFFFFFFFFFFFF
                                span = wsize
                                if is_str:
                                    pfx = df.read_process_mem(pi.hProcess, rip, 1) or b""
                                    if pfx[:1] in (b"\xf2", b"\xf3"):
                                        # rep string store: [rdi .. rdi+rcx*elem)
                                        span = max(wsize, (ctx.Rcx & 0xFFFFF) * wsize)
                                # Fast pre-filter: only heap-range writes can hit a
                                # heap block (skip stack/image/global stores).
                                if (span and heap_reports[0] < heap_report_max
                                        and 0x40000 <= ea < 0x7FF00000):
                                    w_lo, w_hi = ea, ea + span
                                    hit = False
                                    for p, sz in live_allocs.items():
                                        rz_lo = p + ((sz + 15) & ~15)
                                        if w_lo < rz_lo + 16 and w_hi > rz_lo:
                                            heap_reports[0] += 1
                                            hint = _x86_hint(rva_rev, rva)
                                            print(f"[heapguard OOB] main+0x{rva:X} {hint} "
                                                  f"{mn} write [0x{ea:X}+0x{span:X}] past "
                                                  f"alloc 0x{p:X} size 0x{sz:X} "
                                                  f"(end 0x{p+sz:X}) rcx=0x{ctx.Rcx:X}")
                                            hit = True
                                            break
                                    if not hit:
                                        for fp, fs in freed_blocks[-64:]:
                                            if w_lo < fp + fs and w_hi > fp:
                                                heap_reports[0] += 1
                                                hint = _x86_hint(rva_rev, rva)
                                                print(f"[heapguard UAF] main+0x{rva:X} "
                                                      f"{hint} {mn} write [0x{ea:X}] into "
                                                      f"freed 0x{fp:X} size 0x{fs:X}")
                                                break
                    if watch is not None and (rip - base) in watch:
                        w = rip - base
                        print(f"[watch main+0x{w:X}] "
                              f"RAX=0x{ctx.Rax:X} RBX=0x{ctx.Rbx:X} "
                              f"RCX=0x{ctx.Rcx:X} RDX=0x{ctx.Rdx:X} "
                              f"RSI=0x{ctx.Rsi:X} RDI=0x{ctx.Rdi:X} "
                              f"R8=0x{ctx.R8:X} RBP=0x{ctx.Rbp:X} RSP=0x{ctx.Rsp:X}")
                    # Stack-relative guard watch: arm on entering guard_rva,
                    # then report whenever the saved-reg slot value changes.
                    if guard_rva is not None:
                        rva = rip - base
                        if rva == guard_rva:
                            ga = ctx.Rsp - guard_off
                            gv = df.read_process_mem(pi.hProcess, ga, 8)
                            guard_state[0] = ga
                            guard_state[1] = (int.from_bytes(gv, "little")
                                              if len(gv) == 8 else None)
                            guard_state[2] += 1
                        elif guard_state[0]:
                            ga = guard_state[0]
                            if ctx.Rsp > ga + 0x18:
                                guard_state[0] = 0   # function returned past slot
                            else:
                                gv = df.read_process_mem(pi.hProcess, ga, 8)
                                cur = (int.from_bytes(gv, "little")
                                       if len(gv) == 8 else None)
                                if cur is not None and cur != guard_state[1]:
                                    if guard_state[3] < 4000:
                                        print(f"[guard #{guard_state[2]} @0x{ga:X}] "
                                              f"main+0x{rva:X} wrote 0x{guard_state[1]:X}"
                                              f" -> 0x{cur:X}  rsp=0x{ctx.Rsp:X}")
                                    guard_state[3] += 1
                                    guard_state[1] = cur
                    set_tf(True)
                    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                    continue
                # Left the main image: optionally log the API call (name+args).
                if apilog and api_count[0] < apilog_max:
                    api_count[0] += 1
                    callsite = ring[-1][0] if ring else 0
                    sym = _resolve_addr(modules, rip)
                    extra = ""
                    low = sym.lower()
                    if ("writeconsole" in low or "writefile" in low
                            or "outputdebug" in low):
                        buf = ctx.Rdx
                        n = ctx.R8 & 0xFFFF
                        raw = df.read_process_mem(pi.hProcess, buf,
                                                  min(n * 2 + 2, 160)) or b""
                        if "writefile" in low:
                            txt = raw[:80].decode("latin1", "replace")
                        else:
                            txt = raw.decode("utf-16le", "replace")[:80]
                        extra = f"  buf={txt!r}"
                    else:
                        # Preview wide-string pointer args (rcx/rdx) so the trace
                        # shows *what* cmd is parsing/comparing — invaluable for
                        # finding where /c command dispatch goes wrong. Universal:
                        # works for any Win2000 binary's string-heavy APIs.
                        s1 = _wstr(pi.hProcess, ctx.Rcx)
                        s2 = _wstr(pi.hProcess, ctx.Rdx)
                        parts = []
                        if s1:
                            parts.append(f"a1={s1!r}")
                        if s2:
                            parts.append(f"a2={s2!r}")
                        if parts:
                            extra = "  " + " ".join(parts)
                    print(f"  [api] main+0x{callsite:<6X} -> {sym}  "
                          f"rcx=0x{ctx.Rcx:X} rdx=0x{ctx.Rdx:X} "
                          f"r8=0x{ctx.R8:X} r9=0x{ctx.R9:X}{extra}")
                # Heap-guard: record alloc/free calls as they leave the main image.
                if heapguard:
                    hsym = _resolve_addr(modules, rip).lower()
                    if ("rtlallocateheap" in hsym or "heapalloc" in hsym):
                        pending_alloc[0] = ctx.R8 & 0xFFFFFFFFFFFFFFFF
                    elif "rtlreallocateheap" in hsym or "heaprealloc" in hsym:
                        old = ctx.R8 & 0xFFFFFFFFFFFFFFFF
                        if old in live_allocs:
                            freed_blocks.append((old, live_allocs.pop(old)))
                            del freed_blocks[:-128]
                        pending_alloc[0] = ctx.R9 & 0xFFFFFFFFFFFFFFFF
                    elif ("rtlfreeheap" in hsym or "heapfree" in hsym):
                        fp = ctx.R8 & 0xFFFFFFFFFFFFFFFF
                        if fp in live_allocs:
                            freed_blocks.append((fp, live_allocs.pop(fp)))
                            del freed_blocks[:-128]
                    elif heap_reports[0] < heap_report_max and (
                            "memcpy" in hsym or "memmove" in hsym
                            or "wmemcpy" in hsym or "wcsncpy" in hsym
                            or "memset" in hsym or "wcsncat" in hsym):
                        # memcpy(dst=rcx, src=rdx, n=r8). Verify dst+n fits its
                        # allocation — catches copies that overflow a heap buffer
                        # (the SSE movaps crash was a msvcrt copy past a block).
                        dst = ctx.Rcx & 0xFFFFFFFFFFFFFFFF
                        n = ctx.R8 & 0xFFFFFFFFFFFFFFFF
                        if "wcsncpy" in hsym or "wcsncat" in hsym:
                            n *= 2  # count is in wchars
                        for p, sz in live_allocs.items():
                            if p <= dst < p + ((sz + 15) & ~15):
                                if dst + n > p + sz:
                                    heap_reports[0] += 1
                                    cs = ring[-1][0] if ring else 0
                                    hint = _x86_hint(rva_rev, cs)
                                    print(f"[heapguard COPY-OOB] main+0x{cs:X} {hint}"
                                          f" -> {hsym} dst=0x{dst:X} n=0x{n:X} "
                                          f"overflows alloc 0x{p:X} size 0x{sz:X} "
                                          f"(end 0x{p+sz:X})")
                                break
                # Left the main image: if RIP is in NO loaded module this is a
                # wild indirect branch (translation bug) — dump the ring and
                # stop BEFORE the execute-fault so the culprit call is visible.
                if not any(b <= rip < b + sz for b, sz, _n, _e in modules):
                    print(f"\n[WILD-BRANCH] RIP=0x{rip:X} not in any module "
                          f"after {steps} steps")
                    print(f"  RAX=0x{ctx.Rax:X} RBX=0x{ctx.Rbx:X} "
                          f"RCX=0x{ctx.Rcx:X} RDX=0x{ctx.Rdx:X}")
                    print(f"  RSI=0x{ctx.Rsi:X} RDI=0x{ctx.Rdi:X} "
                          f"RSP=0x{ctx.Rsp:X} RBP=0x{ctx.Rbp:X} "
                          f"R8=0x{ctx.R8:X} R9=0x{ctx.R9:X}")
                    print(f"--- last {min(len(ring), show)} main-image "
                          f"instructions ---")
                    for rva, sp, bp in ring[-show:]:
                        di = _disasm_one(pi.hProcess, base + rva)
                        txt = f"{di.mnemonic} {di.op_str}" if di else "?"
                        print(f"  main+0x{rva:<6X} rsp=0x{sp:X} rbp=0x{bp:X}  "
                              f"{txt}")
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
                # Left the main image into a module: step OVER by breakpointing
                # the return address ([RSP]) and running free.
                retq = df.read_process_mem(pi.hProcess, ctx.Rsp, 8)
                ret = int.from_bytes(retq, "little") if len(retq) == 8 else 0
                if in_main(ret):
                    set_tf(False)
                    arm_bp(ret)
                    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                    continue
                # Unknown caller: just run free until next event.
                set_tf(False)
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
                continue
            # Benign first-chance exceptions that only surface under a debugger
            # (e.g. NtClose on an invalid handle raises 0xC0000008 ONLY when a
            # debugger is attached; without one it just returns an error and the
            # app keeps running). Mark handled and keep tracing so we reach the
            # real fault. The step-over breakpoint at the main return address is
            # still armed, so tracing resumes when the syscall returns.
            if first and ecode in pass_codes:
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId,
                                       df.DBG_CONTINUE)
                continue
            # Real exception.
            fault_info = None
            if ecode == 0xC0000005 and er.NumberParameters >= 2:
                fault_info = (er.ExceptionInformation[0],
                              er.ExceptionInformation[1] & 0xFFFFFFFFFFFFFFFF)
            ctx = df.get_thread_context(pi.hThread)
            report(ctx, ecode, fault_info)
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId,
                                   df.DBG_EXCEPTION_NOT_HANDLED)
            k32.TerminateProcess(pi.hProcess, 1)
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
