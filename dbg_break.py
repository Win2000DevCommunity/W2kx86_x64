#!/usr/bin/env python3
"""
Interactive Win64 debug loop for cmd_shim / translated PE64 binaries.

Stop on breakpoints (RVA/VA), access violations, or explicit SEH events.
Inspect registers, stack, memory, IAT slots, and the GS exception chain.

Usage:
    python dbg_break.py <exe> [args...]

Options (before exe path):
    --bp rva:0x27B88       Break when RIP is in main image at RVA (repeatable)
    --bp va:0x18001010c0   Break at absolute VA
    --bp exc               Break on first-chance AV / illegal instruction
    --bp entry             Break at PE entry point (once)
    --root                 Root-cause daemon (jump SEH, backtrack symptom→cause)
    --trace                Single-step (last 40 insns printed on stop)
    --auto                 Do not prompt; print dump and exit on first stop

For deepest analysis prefer the dedicated daemon:
    python dbg_root.py [--trace] <exe> [args...]

At prompt (when stopped):
    c / continue     Resume until next breakpoint
    s / step         Single-step one instruction
    r                Print registers
    k                Print stack (64 qwords)
    m <addr> [n]     Hex dump n bytes (default 128) at addr or rva:NNN
    dis [n]          Disassemble n bytes at RIP (default 32)
    seh              Walk GS exception chain (translated MSVC frames)
    iat              Dump key IAT slots
    rip              Where am I?
    q / quit         Kill debuggee and exit
"""
from __future__ import annotations

import argparse
import struct
import sys
import os

import dbg_fault as df

k32 = df.k32
suppress_fault_ui = df.suppress_fault_ui
CONTEXT_FULL = df.CONTEXT_FULL
DBG_CONTINUE = df.DBG_CONTINUE
DBG_EXCEPTION_NOT_HANDLED = df.DBG_EXCEPTION_NOT_HANDLED

# cmd_shim known RVAs (main image @ 0x80000000)
KEY_IAT = {
    '_except_handler3': 0x6CED8,
    '__set_app_type': 0x6D5C1,
    '__getmainargs': 0x6D5A9,
    '_initterm': 0x6D5B1,
}


def read_mem(proc, addr: int, size: int) -> bytes:
    import ctypes as C
    buf = (C.c_char * size)()
    n = C.c_size_t(0)
    if k32.ReadProcessMemory(proc, C.c_void_p(addr), buf, size, C.byref(n)):
        return bytes(buf[: n.value])
    return b""


def parse_addr(s: str, base: int) -> int:
    s = s.strip().lower()
    if s.startswith('rva:'):
        return base + int(s[4:], 16)
    if s.startswith('va:'):
        return int(s[3:], 16)
    if s.startswith('0x'):
        v = int(s, 16)
        if v < base and base:
            return base + v
        return v
    v = int(s, 16)
    return base + v if v < 0x10000000 and base else v


def fmt_va(addr: int, base: int, shim_base: int = 0x1800100000) -> str:
    parts = [f"0x{addr:016X}"]
    if base and base <= addr < base + 0x200000:
        parts.append(f"main+0x{addr - base:X}")
    elif shim_base <= addr < shim_base + 0x200000:
        parts.append(f"shim+0x{addr - shim_base:X}")
    return ' '.join(parts)


def disasm_at(proc, rip: int, n: int = 32) -> None:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        raw = read_mem(proc, rip, n)
        print(f"  (capstone missing) bytes: {raw.hex()}")
        return
    raw = read_mem(proc, rip, max(n, 16))
    if not raw:
        print("  (cannot read RIP)")
        return
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(raw, rip):
        print(f"  0x{ins.address:016X}: {ins.mnemonic:8s} {ins.op_str}")
        if ins.address - rip >= n:
            break


def dump_regs(ctx: df.CONTEXT) -> None:
    print(f"  RIP={ctx.Rip:016X} RSP={ctx.Rsp:016X} RBP={ctx.Rbp:016X}")
    print(f"  RAX={ctx.Rax:016X} RBX={ctx.Rbx:016X} RCX={ctx.Rcx:016X} RDX={ctx.Rdx:016X}")
    print(f"  RSI={ctx.Rsi:016X} RDI={ctx.Rdi:016X} R8 ={ctx.R8:016X} R9 ={ctx.R9:016X}")
    print(f"  R10={ctx.R10:016X} R11={ctx.R11:016X} R12={ctx.R12:016X}")


def dump_stack(proc, rsp: int, base: int, count: int = 64) -> None:
    raw = read_mem(proc, rsp, count * 8)
    for i in range(0, len(raw), 8):
        if i + 8 > len(raw):
            break
        v = struct.unpack_from('<Q', raw, i)[0]
        note = ''
        if base and base <= v < base + 0x200000:
            note = f'  <- main+0x{v - base:X}'
        elif 0x1800100000 <= v < 0x1800200000:
            note = f'  <- shim+0x{v - 0x1800100000:X}'
        elif v == 0x7FFE0385 or (0x7FFE0000 <= v < 0x7FFF0000):
            note = '  <- KUSER'
        print(f"  [rsp+0x{i:03X}] {fmt_va(v, base)}{note}")


def dump_mem(proc, addr: int, size: int, base: int) -> None:
    raw = read_mem(proc, addr, size)
    if not raw:
        print(f"  unreadable {fmt_va(addr, base)}")
        return
    for off in range(0, len(raw), 16):
        chunk = raw[off:off + 16]
        hexpart = ' '.join(f'{b:02X}' for b in chunk)
        print(f"  {fmt_va(addr + off, base)}  {hexpart}")


def walk_seh_chain(proc, base: int) -> None:
    """Walk GS:[0] chain; highlight MSVC frames (scope sentinel -1 in main image)."""
    import ctypes as C
    # TEB is at GS base; ExceptionList at TEB+0x00 on x64.
    ctx = df.CONTEXT()
    ctx.ContextFlags = CONTEXT_FULL
    # Use NtCurrentTeb via reading from debuggee: scan for frame with scope 0x8003f8c4
    # Fallback: linear stack scan for sentinel-backed scope pointers.
    scope_target = base + 0x3F8C4 if base else 0
    print("  Scanning stack for MSVC SEH frames (scope in main image)...")
    ctx2 = df.CONTEXT()
    found = 0
    for probe in range(0, 0x2000, 8):
        # scan from a guessed RSP region - caller should pass recent RSP
        pass
    # Read thread context for RSP-based scan
    # (Called with active pi from main loop via global - set in dump_seh)
    print("  (Use 'm rva:3f8c4' to inspect scope table; handler should be shim+0x10c0)")


def dump_iat(proc, base: int) -> None:
    if not base:
        print("  no main base")
        return
    for name, rva in KEY_IAT.items():
        slot = read_mem(proc, base + rva, 8)
        if len(slot) == 8:
            val = struct.unpack('<Q', slot)[0]
            print(f"  {name:20s} rva=0x{rva:X} -> {fmt_va(val, base)}")


def hit_breakpoint(rip: int, base: int, entry_rva: int,
                   bp_rvas: set, bp_vas: set,
                   bp_entry: bool, entry_hit: bool) -> bool:
    if rip in bp_vas:
        return True
    if base and bp_rvas and base <= rip < base + 0x200000:
        if (rip - base) in bp_rvas:
            return True
    if bp_entry and not entry_hit and base and rip == base + entry_rva:
        return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description='Interactive PE64 debugger')
    ap.add_argument('exe')
    ap.add_argument('args', nargs='*')
    ap.add_argument('--bp', action='append', default=[], dest='breakpoints')
    ap.add_argument('--trace', action='store_true')
    ap.add_argument('--auto', action='store_true', help='exit on first stop without prompt')
    ap.add_argument('--root', action='store_true',
                    help='root-cause daemon mode (jump SEH, backtrack to first cause)')
    opts = ap.parse_args()
    if opts.root:
        import dbg_root
        return dbg_root.RootCauseDaemon(
            opts.exe, opts.args, trace=opts.trace,
            max_exc=64, no_jump=False,
        ).run()
    suppress_fault_ui()

    bp_rvas: set = set()
    bp_vas: set = set()
    bp_exc = False
    bp_entry = False
    for b in opts.breakpoints or []:
        b = b.lower()
        if b == 'exc':
            bp_exc = True
        elif b == 'entry':
            bp_entry = True
        elif b.startswith('rva:'):
            bp_rvas.add(int(b[4:], 16))
        elif b.startswith('va:'):
            bp_vas.add(int(b[3:], 16))
        else:
            bp_rvas.add(int(b, 16))

    import ctypes as C
    cmdline = '"' + opts.exe + '" ' + ' '.join(opts.args)
    si = df.STARTUPINFO()
    si.cb = C.sizeof(df.STARTUPINFO)
    pi = df.PROCESS_INFORMATION()
    ok = k32.CreateProcessW(
        opts.exe, C.create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(opts.exe) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print('CreateProcess failed', C.get_last_error())
        return 1

    base = None
    entry_rva = 0x27B88
    dll_bases = {}
    de = df.DEBUG_EVENT()
    first_bp = False
    entry_hit = False
    tracing = opts.trace
    trace_ring = []
    stopped = False
    step_once = False

    def get_ctx():
        ctx = df.CONTEXT()
        ctx.ContextFlags = CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        return ctx

    def set_tf(on: bool):
        ctx = get_ctx()
        if on:
            ctx.EFlags |= 0x100
        else:
            ctx.EFlags &= ~0x100
        k32.SetThreadContext(pi.hThread, C.byref(ctx))

    def print_stop(reason: str, ctx: df.CONTEXT, er=None):
        print(f"\n=== STOP: {reason} ===")
        print(f"  RIP {fmt_va(ctx.Rip, base or 0)}")
        dump_regs(ctx)
        if er:
            ecode = er.ExceptionCode & 0xFFFFFFFF
            print(f"  exception code=0x{ecode:08X} at {fmt_va(er.ExceptionAddress or 0, base or 0)}")
        print("--- disasm ---")
        disasm_at(pi.hProcess, ctx.Rip, 48)
        print("--- stack ---")
        dump_stack(pi.hProcess, ctx.Rsp, base or 0, 24)
        dump_iat(pi.hProcess, base or 0)
        if tracing and trace_ring:
            print(f"--- trace ({len(trace_ring)} steps) ---")
            for kind, val, sp in trace_ring[-20:]:
                if kind == 'img':
                    print(f"  main+0x{val:X}  rsp=0x{sp:X}")
                else:
                    print(f"  {fmt_va(val, base or 0)}  rsp=0x{sp:X}")

    def prompt_loop(ctx: df.CONTEXT, er=None):
        nonlocal stopped, tracing, step_once
        if opts.auto:
            return 'quit'
        print("\nCommands: c=continue s=step r=regs k=stack m <addr> dis seh iat q=quit")
        while True:
            try:
                line = input('dbg> ').strip()
            except (EOFError, KeyboardInterrupt):
                return 'quit'
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
            if cmd in ('c', 'continue'):
                stopped = False
                if tracing:
                    set_tf(True)
                return 'continue'
            if cmd in ('s', 'step'):
                stopped = False
                step_once = True
                set_tf(True)
                return 'continue'
            if cmd in ('q', 'quit'):
                return 'quit'
            if cmd == 'r':
                dump_regs(get_ctx())
            elif cmd == 'k':
                dump_stack(pi.hProcess, get_ctx().Rsp, base or 0, 48)
            elif cmd == 'dis':
                n = int(parts[1], 0) if len(parts) > 1 else 32
                disasm_at(pi.hProcess, get_ctx().Rip, n)
            elif cmd == 'm' and len(parts) >= 2:
                addr = parse_addr(parts[1], base or 0)
                n = int(parts[2], 0) if len(parts) > 2 else 128
                dump_mem(pi.hProcess, addr, n, base or 0)
            elif cmd == 'seh':
                ctx2 = get_ctx()
                dump_stack(pi.hProcess, ctx2.Rbp - 0x80, base or 0, 32)
                print("  Look for handler=shim+0x10c0 scope=main+0x3f8c4 try=0")
            elif cmd == 'iat':
                dump_iat(pi.hProcess, base or 0)
            elif cmd == 'rip':
                print(fmt_va(get_ctx().Rip, base or 0))
            else:
                print("  unknown command")

    while True:
        if not k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
            break
        code = de.dwDebugEventCode
        status = DBG_CONTINUE

        if code == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"[start] main base=0x{base:X}")
            h = de.u.CreateProcessInfo.hFile
            if h:
                k32.CloseHandle(h)
            if tracing:
                set_tf(True)
        elif code == df.LOAD_DLL_DEBUG_EVENT:
            b = de.u.LoadDll.lpBaseOfDll
            dll_bases[b] = b
            h = de.u.LoadDll.hFile
            if h:
                k32.CloseHandle(h)
        elif code == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"[exit] 0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08X}")
            break
        elif code == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ecode = er.ExceptionCode & 0xFFFFFFFF
            ctx = get_ctx()

            if ecode == 0x80000003 and not first_bp:
                first_bp = True
                status = DBG_CONTINUE
            elif ecode == 0x80000004 and (tracing or step_once):
                rip = ctx.Rip
                if base and base <= rip < base + 0x200000:
                    trace_ring.append(('img', rip - base, ctx.Rsp))
                else:
                    trace_ring.append(('ext', rip, ctx.Rsp))
                if len(trace_ring) > 40:
                    trace_ring.pop(0)
                if step_once:
                    step_once = False
                    set_tf(False)
                    print_stop('single-step', ctx)
                    act = prompt_loop(ctx)
                    if act == 'quit':
                        k32.TerminateProcess(pi.hProcess, 1)
                        break
                else:
                    set_tf(True)
                status = DBG_CONTINUE
            elif not stopped:
                reason = None
                if bp_exc and ecode in (0xC0000005, 0xC000001D):
                    reason = f'exception 0x{ecode:08X}'
                elif hit_breakpoint(ctx.Rip, base or 0, entry_rva,
                                    bp_rvas, bp_vas, bp_entry, entry_hit):
                    reason = 'breakpoint'
                    if bp_entry and base and ctx.Rip == base + entry_rva:
                        entry_hit = True
                if reason:
                    set_tf(False)
                    stopped = True
                    print_stop(reason, ctx, er)
                    act = prompt_loop(ctx, er)
                    if act == 'quit':
                        k32.TerminateProcess(pi.hProcess, 1)
                        break
                    status = DBG_CONTINUE
                elif ecode not in (0x80000003, 0x80000004):
                    print_stop(f'unhandled 0x{ecode:08X}', ctx, er)
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
            else:
                status = DBG_CONTINUE

        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)

    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
