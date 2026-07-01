#!/usr/bin/env python3
"""
Root-cause exception daemon for translated PE64 binaries (cmd_shim / w2kshim64).

Unlike plain ``--bp exc`` debuggers that stop on the first visible fault, this
daemon *jumps through* handled first-chance exceptions (SEH / vectored handlers)
and, when the process finally breaks, backtracks from *symptoms* (RIP on stack,
RIP=0/1, illegal insn mid-stream) to the last trustworthy instruction in the
main image that caused the bad transfer.

Usage:
    python dbg_root.py <exe> [args...]
    python dbg_root.py --trace <exe> [args...]   # longer instruction ring
    python dbg_root.py --crt <exe> [args...]      # probe key CRT/cmd RVAs
    python dbg_root.py --interactive <exe>        # probes for Explorer double-click path
    python dbg_root.py --watch 0x8EB9:main <exe> [args...]

Options (before exe):
    --trace          Record last 512 single-steps (slower, sharper backtrack)
    --crt            INT3-probe preset CRT→main path (cmd_shim); log call roots
    --watch RVA[:label]  Repeatable: breakpoint + register/call-root dump
    --exit-report    On clean exit, print return chain + traced calls
    --max-exc N      Log up to N first-chance exceptions before giving up (default 64)
    --no-jump        Stop on first exception like dbg_break --bp exc
"""
from __future__ import annotations

import argparse
import ctypes as C
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import dbg_fault as df

k32 = df.k32
suppress_fault_ui = df.suppress_fault_ui

# Fault kinds we treat as potentially handled on first chance (jump through).
JUMP_THROUGH = {
    0xC0000005, 0xC000001D, 0xC0000096, 0xC000008C, 0xC000008D,
    0x80000002,  # DATATYPE_MISALIGNMENT
}

TERMINAL = JUMP_THROUGH | {0xC00000FD, 0xC0000409}

# cmd_shim CRT→main probe sites (label → printed on hit).
CRT_PROBE: dict[int, str] = {
    0x8778: "CRT entry SetErrorMode hook",
    0x877B: "CRT entry (push rbp)",
    0x8A44: "CRT wcslen/fn6314 call",
    0x8A51: "CRT cmp esi,ebx after wcslen",
    0x8A7B: "CRT second wcslen IAT",
    0x8AAC: "CRT malloc IAT",
    0x8AC8: "CRT malloc-result jne->fn6314",
    0x8AF4: "CRT fn6314 (GetStartupInfo path)",
    0x8CD4: "CRT fn6314 (copycmd)",
    0x8D56: "CRT init-loop jne (was 2D9A9)",
    0x8DF1: "CreateProcess fail stub",
    0x8E26: "jmp cmd main",
    0x8EB9: "cmd main entry",
    0x8EEE: "main GetCommandLineW",
    0x8F06: "main wcslen",
    0x9040: "main early exit",
    0x8FEB: "main token wcsncpy IAT",
    0x91AC: "main batch helper call",
    0x92EC: "win10 echo WriteFile stub",
    0x92A1: "exec /c switch call",
    0x92CC: "exec rbx=cmdline buf",
    0x932F: "echo tail entry",
    0x935E: "echo wcslen rcx",
    0x938F: "pre-CreateProcess helper",
    0x1314F: "CreateProcessW IAT",
    0x1D371: "GetVolumeInformationW IAT",
}

INTERACTIVE_PIPELINE: list[int] = [
    0x8778, 0x8EB9, 0x8EEE, 0x8FED, 0x9040, 0x91B5, 0x91AC, 0x2E4B2,
    0x2EAD6, 0x2EAE9, 0x3D196, 0x90D0, 0x1D371,
]

# Ordered pipeline — gap before next probe ⇒ hardest stuck stage.
CRT_PIPELINE: list[int] = [
    0x8778, 0x877B, 0x8EB9, 0x8EEE, 0x92A1, 0x92CC, 0x92EC, 0x932F, 0x935E, 0x938F, 0x1314F,
]

# x86 RVAs used by --crt/--interactive (remapped via rva_map in --pure mode).
PURE_CRT_X86: list[int] = list(CRT_PIPELINE)


def load_rva_map(path: str) -> dict[int, int]:
    """Load ``old_rva new_rva`` lines written by DUMP_RVA_MAP."""
    rmap: dict[int, int] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) != 2:
                continue
            try:
                rmap[int(parts[0], 16)] = int(parts[1], 16)
            except ValueError:
                continue
    return rmap


def remap_x86_probes(x86_rvas: list[int], rmap: dict[int, int]) -> dict[int, str]:
    """Map x86 probe RVAs to shim RVAs using *rmap* (skip unmapped)."""
    out: dict[int, str] = {}
    for x86 in x86_rvas:
        shim = rmap.get(x86)
        if shim is None:
            continue
        label = CRT_PROBE.get(x86, f"x86 0x{x86:X}")
        out[shim] = f"{label} (pure 0x{x86:X})"
    return out


def find_rva_map_for_exe(exe: str) -> str | None:
    """Locate DUMP_RVA_MAP output beside *exe* or from env."""
    env = os.environ.get("DUMP_RVA_MAP")
    if env and os.path.isfile(env):
        return env
    base = os.path.splitext(os.path.basename(exe))[0]
    d = os.path.dirname(os.path.abspath(exe)) or "."
    for name in (f"rva_{base}.txt", f"rva_pure_{base}.txt", "rva_pure.txt",
                 "rva_map.txt"):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    for fn in sorted(os.listdir(d), reverse=True):
        if fn.startswith("rva") and fn.endswith(".txt"):
            return os.path.join(d, fn)
    return None


def _rva_jmp_target(img: bytes, rva: int, text_rva: int = 0x1000) -> int | None:
    """Follow 5-byte E9 at *rva*; return destination RVA or None."""
    off = rva - text_rva
    if off < 0 or off + 5 > len(img) or img[off] != 0xE9:
        return None
    rel = struct.unpack_from("<i", img, off + 1)[0]
    return rva + 5 + rel


def discover_interactive_watch(exe: str) -> tuple[dict[int, str], list[int]]:
    """Build probe map from live PE bytes (jmp/call targets), not fixed RVAs only."""
    import pefile

    pe = pefile.PE(exe)
    img = pe.get_memory_mapped_image()
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    trva = text.VirtualAddress
    watch: dict[int, str] = dict(CRT_PROBE)
    static = {
        0x8EB9: "cmd main entry",
        0x8EEE: "GetCommandLineW",
        0x9040: "interactive guard",
        0x9072: "drive-letter path",
        0x91B5: "banner gate",
        0x2E4B2: "banner root",
        0x2E541: "banner WriteConsole",
        0x2D813: "banner print stub",
        0x2EAD6: "REPL gate",
        0x2EAE9: "REPL prompt",
        0x3D196: "ReadConsole helper",
    }
    watch.update(static)
    for rva, label in (
        (0x90BA, "drive->banner jmp"),
        (0x3D196, "ReadConsole hook"),
        (0x2D813, "banner print entry"),
        (0x8F32, "SEH route"),
    ):
        tgt = _rva_jmp_target(img, rva, trva)
        if tgt is not None:
            watch.setdefault(rva, label)
            if rva == 0x3D196:
                watch[tgt] = "prompt cave (dynamic)"
            elif rva == 0x90BA:
                watch[tgt] = "post-drive target (dynamic)"
            elif rva == 0x2D813:
                watch[tgt] = "banner WriteConsole cave"
    pipe = sorted(set(watch.keys()) | set(INTERACTIVE_PIPELINE))
    return watch, pipe

@dataclass
class ProbeHit:
    rva: int
    label: str
    ctx: df.CONTEXT
    call_at_rip: Optional[df.CallRoot] = None


@dataclass
class TraceFrame:
    rip: int
    rsp: int
    rax: int = 0
    rcx: int = 0
    rdx: int = 0
    rsi: int = 0
    rdi: int = 0
    in_main: bool = False
    call_root: Optional[df.CallRoot] = None


@dataclass
class ExcNote:
    n: int
    code: int
    first_chance: bool
    rip: int
    fault_addr: int
    rsp: int
    tag: str
    action: str


@dataclass
class RootVerdict:
    kind: str
    summary: str
    site_rip: int = 0
    site_label: str = ""
    callsite_label: str = ""
    callsite_mnemonic: str = ""
    hint: str = ""
    trace_tail: List[TraceFrame] = field(default_factory=list)
    returns: List[Tuple[int, int]] = field(default_factory=list)


class RootCauseDaemon:
    """Debug loop that jumps handled faults and synthesizes root cause."""

    def __init__(self, exe: str, args: list[str], trace: bool, max_exc: int,
                 no_jump: bool, watch: dict[int, str] | None = None,
                 exit_report: bool = False,
                 pipeline: list[int] | None = None,
                 new_console: bool = False):
        self.exe = exe
        self.args = args
        self.trace = trace
        self.max_exc = max_exc
        self.no_jump = no_jump
        self.watch = watch or {}
        self.exit_report = exit_report
        self.pipeline = pipeline or CRT_PIPELINE
        self.new_console = new_console
        self.main_base: Optional[int] = None
        self.dll_bases: dict = {}
        self.trace_ring: List[TraceFrame] = []
        self.call_log: List[df.CallRoot] = []
        self.probe_hits: List[ProbeHit] = []
        self.exc_log: List[ExcNote] = []
        self.trace_steps = 0
        self.trace_cap = 512 if trace else 128
        self.pi = None
        self._stuck: dict[tuple, int] = {}
        self._watch_orig: dict[int, int] = {}
        self._loader_bp_done = False
        self.imp = df.PeImportMap(exe)

    def _read(self, addr: int, size: int) -> bytes:
        return df.read_process_mem(self.pi.hProcess, addr, size)

    def _ctx(self) -> df.CONTEXT:
        return df.get_thread_context(self.pi.hThread)

    def _in_main(self, rip: int) -> bool:
        return bool(self.main_base and self.main_base <= rip <
                    self.main_base + df.MAIN_IMAGE_MAX)

    def _label(self, addr: int) -> str:
        return df.fmt_module_addr(addr, self.main_base)

    def _record_step(self, ctx: df.CONTEXT) -> None:
        self.trace_steps += 1
        rip, rsp = ctx.Rip, ctx.Rsp
        in_main = self._in_main(rip)
        call_root = None
        if in_main:
            call_root = df.analyze_insn_call(
                self.pi.hProcess, rip, ctx, self.main_base, self.imp)
            if call_root:
                self.call_log.append(call_root)
                if len(self.call_log) > 256:
                    self.call_log.pop(0)
        # Keep external tail + all main-image steps.
        if in_main or (self.trace_ring and not self.trace_ring[-1].in_main):
            fr = TraceFrame(
                rip=rip, rsp=rsp,
                rax=ctx.Rax, rcx=ctx.Rcx, rdx=ctx.Rdx,
                rsi=ctx.Rsi, rdi=ctx.Rdi,
                in_main=in_main,
                call_root=call_root,
            )
            self.trace_ring.append(fr)
            if len(self.trace_ring) > self.trace_cap:
                self.trace_ring.pop(0)

    def _rsp_cliff(self) -> Optional[TraceFrame]:
        """Detect __chkstk-style RSP jump in the trace tail."""
        for i in range(1, len(self.trace_ring)):
            a, b = self.trace_ring[i - 1], self.trace_ring[i]
            if a.in_main and b.in_main and a.rsp - b.rsp > 0x400:
                return b
        return None

    def _find_bad_indirect_in_trace(self, ctx: df.CONTEXT) -> Optional[TraceFrame]:
        """Last main-image step that looks like call/jmp through a bad register."""
        bad_regs = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
        if ctx.Rip > 0x10000:
            bad_regs.discard(ctx.Rip & 0xFFFF)  # not used
        for fr in reversed(self.trace_ring):
            if not fr.in_main:
                continue
            insns = df.disasm_range(self.pi.hProcess, fr.rip, 8, 12)
            for ins in insns:
                if ins.address != fr.rip:
                    continue
                m = ins.mnemonic
                op = ins.op_str.lower()
                if m in ("call", "jmp") and op in ("rax", "rcx", "rdx", "rbx",
                                                   "rsi", "rdi", "r8", "r9",
                                                   "r10", "r11", "r12", "r13",
                                                   "r14", "r15"):
                    reg_map = {
                        "rax": fr.rax, "rcx": fr.rcx, "rdx": fr.rdx,
                        "rbx": 0, "rsi": fr.rsi, "rdi": fr.rdi,
                    }
                    val = reg_map.get(op, 0)
                    if val < 0x10000 or df.is_probably_stack(val, fr.rsp):
                        return fr
                if m == "ret" and ctx.Rip < 0x10000:
                    return fr
        return None

    def _analyze(self, ctx: df.CONTEXT, er) -> RootVerdict:
        rip = ctx.Rip
        ecode = er.ExceptionCode & 0xFFFFFFFF
        fault = 0
        if ecode == 0xC0000005 and er.NumberParameters >= 2:
            fault = er.ExceptionInformation[1] & 0xFFFFFFFFFFFFFFFF

        returns = df.scan_image_returns(
            self.pi.hProcess, ctx.Rsp, self.main_base, limit=16)

        # ── A: direct fault inside main image ─────────────────────────────
        if self._in_main(rip):
            insns = df.disasm_range(self.pi.hProcess, rip, 0, 8)
            mnem = insns[0].mnemonic if insns else "?"
            hint = self._hint_for_insn(mnem, insns[0].op_str if insns else "")
            return RootVerdict(
                kind="direct",
                summary=f"Faulting instruction in main image ({df.EXCEPTION_NAMES.get(ecode, hex(ecode))})",
                site_rip=rip,
                site_label=self._label(rip),
                callsite_mnemonic=f"{mnem} {insns[0].op_str}" if insns else "",
                hint=hint,
                trace_tail=self.trace_ring[-20:],
                returns=returns,
            )

        # ── B: execute on stack (return address corruption) ───────────────
        if df.is_probably_stack(rip, ctx.Rsp, ctx.Rbp) or (
                ecode == 0xC0000005 and er.NumberParameters >= 2
                and er.ExceptionInformation[0] == 8  # execute
                and df.is_probably_stack(fault, ctx.Rsp, ctx.Rbp)):
            cliff = self._rsp_cliff()
            for off, ra in returns[:8]:
                cs = df.find_callsite_before(self.pi.hProcess, ra)
                cs_m = f"{cs.mnemonic} {cs.op_str}" if cs else "(callsite unknown)"
                hint = self._hint_for_insn(cs.mnemonic, cs.op_str) if cs else (
                    "Return address on stack points into main — "
                    "walk callers with disw.py at listed RVAs")
                if cs and "rsi" in cs.op_str.lower() and ctx.Rsi == 0:
                    hint = "call [rsi] with RSI=0 — IAT slot empty or bad indirect call"
                elif cs and "rdi" in cs.op_str.lower() and ctx.Rdi == 0:
                    hint = "call [rdi] with RDI=0 — IAT slot empty or bad indirect call"
                extra = ""
                if cliff:
                    extra = (f"; RSP cliff at {self._label(cliff.rip)} "
                             f"(rsp 0x{cliff.rsp:X}) → check __chkstk epilogue")
                return RootVerdict(
                    kind="stack-exec",
                    summary=("Execution on stack — corrupted return or chkstk epilogue"),
                    site_rip=cs.address if cs else ra,
                    site_label=self._label(cs.address if cs else ra),
                    callsite_label=self._label(ra),
                    callsite_mnemonic=cs_m,
                    hint=hint + extra,
                    trace_tail=self.trace_ring[-24:],
                    returns=returns,
                )

        # ── C: null / low RIP ─────────────────────────────────────────────
        if rip < 0x10000:
            bad = self._find_bad_indirect_in_trace(ctx)
            if bad:
                insns = df.disasm_range(self.pi.hProcess, bad.rip, 0, 8)
                mnem = insns[0].mnemonic if insns else "?"
                return RootVerdict(
                    kind="null-rip",
                    summary=f"Execution at RIP={rip:#x} — null or garbage indirect branch",
                    site_rip=bad.rip,
                    site_label=self._label(bad.rip),
                    callsite_mnemonic=f"{mnem} {insns[0].op_str}" if insns else "",
                    hint="Fix indirect call target or mangled ret stub (pop before ret)",
                    trace_tail=self.trace_ring[-24:],
                    returns=returns,
                )
            if returns:
                ra = returns[0][1]
                cs = df.find_callsite_before(self.pi.hProcess, ra)
                if cs:
                    hint = "Trace call at return site — target likely NULL"
                    if cs.mnemonic == "call" and cs.op_str.startswith("0x"):
                        try:
                            tgt = int(cs.op_str, 16)
                            hint = self._call_target_hint(tgt) or hint
                        except ValueError:
                            pass
                    return RootVerdict(
                        kind="null-rip",
                        summary=f"RIP={rip:#x} with return chain through {self._label(ra)}",
                        site_rip=cs.address,
                        site_label=self._label(cs.address),
                        callsite_mnemonic=f"{cs.mnemonic} {cs.op_str}",
                        hint=hint,
                        trace_tail=self.trace_ring[-20:],
                        returns=returns,
                    )

        # ── D: fault in system DLL ────────────────────────────────────────
        mod_base, mod_name = df.module_owner(rip, self.main_base, self.dll_bases)
        if returns:
            ra = returns[0][1]
            cs = df.find_callsite_before(self.pi.hProcess, ra)
            if cs and self._in_main(cs.address):
                return RootVerdict(
                    kind="downstream",
                    summary=f"Fault in {mod_name} — upstream call from main image",
                    site_rip=cs.address,
                    site_label=self._label(cs.address),
                    callsite_label=self._label(ra),
                    callsite_mnemonic=f"{cs.mnemonic} {cs.op_str}",
                    hint="Bug is likely bad args/stack from translated caller",
                    trace_tail=self.trace_ring[-20:],
                    returns=returns,
                )

        return RootVerdict(
            kind="unknown",
            summary=f"Fault at {self._label(rip)} ({df.EXCEPTION_NAMES.get(ecode, hex(ecode))})",
            site_rip=rip,
            site_label=self._label(rip),
            hint="Use --trace for a longer ring; inspect stack returns below",
            trace_tail=self.trace_ring[-16:],
            returns=returns,
        )

    def _call_target_hint(self, tgt: int) -> str:
        """Suggest scan_call_targets.py when a direct call lands mid-function."""
        if not self.main_base or not self._in_main(tgt):
            return ""
        blob = df.read_process_mem(self.pi.hProcess, tgt, 8)
        if len(blob) < 3:
            return ""
        if blob[:3] == b'\x55\x48\x89':
            return ""
        for back in (0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0):
            pos = tgt - back
            if pos < self.main_base:
                break
            head = df.read_process_mem(self.pi.hProcess, pos, 3)
            if head == b'\x55\x48\x89':
                return (f"call target {self._label(tgt)} is mid-function "
                        f"(entry ~{self._label(pos)}) — run scan_call_targets.py")
        return ""

    def _install_watchpoints(self) -> None:
        if not self.main_base or not self.watch:
            return
        for rva in self.watch:
            addr = self.main_base + rva
            orig = df.read_process_mem(self.pi.hProcess, addr, 1)
            if not orig:
                continue
            self._watch_orig[rva] = orig[0]
            df.patch_byte(self.pi.hProcess, addr, 0xCC)
        print(f"[daemon] watch: {len(self._watch_orig)} INT3 sites "
              f"({', '.join(f'0x{r:X}' for r in sorted(self.watch))})")

    def _handle_probe_break(self, ctx: df.CONTEXT, ea: int) -> None:
        if not self.main_base:
            return
        rva = ea - self.main_base
        if rva not in self.watch:
            return
        label = self.watch[rva]
        # Restore original byte before analysis so disasm/call-root sees real insn.
        if rva in self._watch_orig:
            df.patch_byte(self.pi.hProcess, ea, self._watch_orig[rva])
        call = df.analyze_insn_call(
            self.pi.hProcess, ea, ctx, self.main_base, self.imp)
        if not call:
            insns = df.disasm_range(self.pi.hProcess, ea, 0, 8)
            if insns and insns[0].mnemonic.lower() == "int3":
                # Probe on INT3 placeholder — walk back for call/jmp racine.
                back = df.find_callsite_before(self.pi.hProcess, ea + 1)
                if back:
                    call = df.analyze_insn_call(
                        self.pi.hProcess, back.address, ctx,
                        self.main_base, self.imp)
        hit = ProbeHit(rva=rva, label=label, ctx=ctx, call_at_rip=call)
        self.probe_hits.append(hit)
        print(f"\n--- PROBE #{len(self.probe_hits)}: {label} (main+0x{rva:X}) ---")
        df.print_register_block(ctx)
        insns = df.disasm_range(self.pi.hProcess, ea, 0, 12)
        if insns:
            print(f"  insn: {insns[0].mnemonic} {insns[0].op_str}")
        if call:
            print(f"  call-root: {df.format_call_root(call, self.main_base)}")
            if call.kind == "indirect-reg" and call.target_label.endswith("0x0"):
                print("  ** null indirect call — check IAT / movabs+FF15 fix **")
        chain = df.build_return_chain(
            self.pi.hProcess, ctx, self.main_base, self.imp, limit=6)
        df.print_call_roots("return-chain call roots", chain, self.main_base)
        ctx.Rip = ea
        df.k32.SetThreadContext(self.pi.hThread, C.byref(ctx))

    def _print_exit_report(self, ctx: df.CONTEXT, exit_code: int) -> None:
        print("\n" + "=" * 72)
        print(" ROOT CAUSE DAEMON — CLEAN EXIT REPORT")
        print("=" * 72)
        print(f"  exit code: 0x{exit_code:08X}")
        if self.probe_hits:
            print(f"\n--- probe hits ({len(self.probe_hits)}/{len(self.watch)}) ---")
            for i, hit in enumerate(self.probe_hits, 1):
                print(f"  #{i} {hit.label} @ main+0x{hit.rva:X}")
                df.print_register_block(hit.ctx, prefix="      ")
                if hit.call_at_rip:
                    print(f"      {df.format_call_root(hit.call_at_rip, self.main_base)}")
            missed = set(self.watch) - {h.rva for h in self.probe_hits}
            if missed:
                print(f"  NEVER HIT: {', '.join(f'{self.watch[r]} (0x{r:X})' for r in sorted(missed))}")
        else:
            print("  (no probe hits — try --crt or --watch main+0x8EB9:main)")
        if ctx:
            df.print_register_block(ctx, prefix="  ")
            chain = df.build_return_chain(
                self.pi.hProcess, ctx, self.main_base, self.imp, limit=10)
            df.print_call_roots("stack return-chain (call racines)", chain, self.main_base)
        if self.call_log:
            df.print_call_roots("traced calls (last 16)", self.call_log[-16:], self.main_base)
        print("=" * 72)

    @staticmethod
    def _hint_for_insn(mnemonic: str, op_str: str) -> str:
        m = mnemonic.lower()
        op = op_str.lower()
        if m in ("call", "jmp") and op.startswith("qword ptr"):
            return "FF25/IAT tail — check _emit_iat_call and orphan thunks"
        if m in ("call", "jmp") and op in (
                "rax", "rcx", "rdx", "rbx", "rsi", "rdi", "r8", "r9",
                "r10", "r11", "r12", "r13", "r14", "r15"):
            return f"Indirect {m} {op} — verify register before transfer"
        if m == "ret":
            return "Bad return address — check __chkstk epilogue or pop-before-ret stub"
        if m in ("ja", "jb", "jmp", "loop", "jecxz"):
            return "Corrupt branch — often stray x86 bytes in align prologue"
        if m in ("add", "mov") and "rsp" in op:
            return "Stack pointer corruption nearby"
        if m == "illegal" or m == "(bad)":
            return "Mid-instruction entry — run CALL snap / align prologue fixups"
        return ""

    def _print_pipeline_gap(self, ctx: df.CONTEXT) -> None:
        """Show CRT→echo pipeline progress; gap before next probe = stuck stage."""
        if not self.probe_hits:
            return
        hit_rvas = {h.rva for h in self.probe_hits}
        last_hit = None
        next_miss = None
        for rva in self.pipeline:
            if rva in hit_rvas:
                last_hit = rva
            elif last_hit is not None and next_miss is None:
                next_miss = rva
                break
        if last_hit is None:
            return
        last_label = CRT_PROBE.get(last_hit, hex(last_hit))
        print(f"\n--- pipeline (hardest-part hint) ---")
        print(f"  last OK : {last_label} (main+0x{last_hit:X})")
        if next_miss is not None:
            miss_label = CRT_PROBE.get(next_miss, hex(next_miss))
            print(f"  STUCK   : died before {miss_label} (main+0x{next_miss:X})")
        else:
            print(f"  STUCK   : died after last probe in pipeline")
        for hit in self.probe_hits:
            if hit.rva in (0x932F, 0x935E, 0x938F) and hit.ctx.Rbx:
                off = hit.ctx.Rbx - self.main_base if self.main_base else hit.ctx.Rbx
                print(f"  @0x{hit.rva:X} RBX=main+0x{off:X} RCX=0x{hit.ctx.Rcx:X} "
                      f"RDX=0x{hit.ctx.Rdx:X} RSI=0x{hit.ctx.Rsi:X}")

    def _print_verdict(self, ctx: df.CONTEXT, er, verdict: RootVerdict) -> None:
        ecode = er.ExceptionCode & 0xFFFFFFFF
        print("\n" + "=" * 72)
        print(" ROOT CAUSE DAEMON — VERDICT")
        print("=" * 72)
        print(f"  kind     : {verdict.kind}")
        print(f"  summary  : {verdict.summary}")
        print(f"  exception: {df.EXCEPTION_NAMES.get(ecode, hex(ecode))} "
              f"({'second-chance' if not er else ''})")
        print(f"  RIP      : {self._label(ctx.Rip)}  RSP=0x{ctx.Rsp:X}")
        if verdict.site_label:
            print(f"  root site: {verdict.site_label}")
        if verdict.callsite_mnemonic:
            print(f"  insn     : {verdict.callsite_mnemonic}")
        if verdict.callsite_label:
            print(f"  return@  : {verdict.callsite_label}")
        if verdict.hint:
            print(f"  hint     : {verdict.hint}")

        self._print_pipeline_gap(ctx)

        if self.exc_log:
            print(f"\n--- exception journal ({len(self.exc_log)} jumped/handled) ---")
            for note in self.exc_log[-12:]:
                print(f"  #{note.n:2d} fc={note.first_chance} "
                      f"{df.EXCEPTION_NAMES.get(note.code, hex(note.code)):22s} "
                      f"{note.tag:16s} [{note.action}]")

        if verdict.returns:
            print("\n--- stack return chain (main image) ---")
            for off, ra in verdict.returns[:10]:
                cs = df.find_callsite_before(self.pi.hProcess, ra)
                cs_s = (f"{cs.mnemonic} {cs.op_str}" if cs else "?")
                print(f"  [rsp+0x{off:03X}] -> {self._label(ra)}  after: {cs_s}")
            roots = df.build_return_chain(
                self.pi.hProcess, ctx, self.main_base, self.imp, limit=10)
            df.print_call_roots("call racines (resolved targets + arg values)", roots,
                                self.main_base)

        if self.call_log:
            df.print_call_roots("traced call log (recent)", self.call_log[-12:],
                                self.main_base)

        if verdict.trace_tail:
            print(f"\n--- trace tail ({len(verdict.trace_tail)} steps, "
                  f"total traced {self.trace_steps}) ---")
            for fr in verdict.trace_tail:
                mark = "*" if fr.in_main else " "
                extra = ""
                if fr.call_root:
                    extra = f"  >> {fr.call_root.mnemonic} -> {fr.call_root.target_label}"
                print(f"  {mark} {self._label(fr.rip):22s}  rsp=0x{fr.rsp:X}{extra}")

        print("\n--- registers ---")
        print(f"  RAX=0x{ctx.Rax:016X} RBX=0x{ctx.Rbx:016X} "
              f"RCX=0x{ctx.Rcx:016X} RDX=0x{ctx.Rdx:016X}")
        print(f"  RSI=0x{ctx.Rsi:016X} RDI=0x{ctx.Rdi:016X} "
              f"R8 =0x{ctx.R8:016X} R9 =0x{ctx.R9:016X}")

        print("\n--- disasm @ fault RIP ---")
        for ins in df.disasm_range(self.pi.hProcess, ctx.Rip, 0, 32):
            print(f"  0x{ins.address:016X}: {ins.mnemonic:8s} {ins.op_str}")

        if verdict.site_rip and verdict.site_rip != ctx.Rip:
            print(f"\n--- disasm @ root site {self._label(verdict.site_rip)} ---")
            for ins in df.disasm_range(self.pi.hProcess, verdict.site_rip, 16, 16):
                mark = ">>" if ins.address == verdict.site_rip else "  "
                print(f"  {mark} 0x{ins.address:016X}: {ins.mnemonic:8s} {ins.op_str}")

        print("=" * 72)

    def run(self) -> int:
        import ctypes as C

        suppress_fault_ui()
        cmdline = '"' + self.exe + '" ' + ' '.join(self.args)
        si = df.STARTUPINFO()
        si.cb = C.sizeof(df.STARTUPINFO)
        pi = df.PROCESS_INFORMATION()
        flags = df.DEBUG_ONLY_THIS_PROCESS
        if self.new_console:
            flags |= df.CREATE_NEW_CONSOLE
        ok = k32.CreateProcessW(
            self.exe, C.create_unicode_buffer(cmdline), None, None, False,
            flags, None, os.path.dirname(self.exe) or None,
            C.byref(si), C.byref(pi))
        if not ok:
            print("CreateProcess failed", C.get_last_error())
            return 1
        self.pi = pi

        de = df.DEBUG_EVENT()
        initial_bp = False
        exc_count = 0
        tracing = self.trace

        print(f"[daemon] attached — jump-through={'off' if self.no_jump else 'on'} "
              f"trace={'on' if tracing else 'light'}")

        while True:
            if not k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
                break
            code = de.dwDebugEventCode
            status = df.DBG_CONTINUE

            if code == df.CREATE_PROCESS_DEBUG_EVENT:
                self.main_base = de.u.CreateProcessInfo.lpBaseOfImage
                print(f"[daemon] main base=0x{self.main_base:X}")
                h = de.u.CreateProcessInfo.hFile
                if h:
                    k32.CloseHandle(h)
                self._install_watchpoints()
                if tracing:
                    df.set_trace_flag(pi.hThread, True)
            elif code == df.LOAD_DLL_DEBUG_EVENT:
                b = de.u.LoadDll.lpBaseOfDll
                self.dll_bases[b] = f"dll@0x{b:X}"
                h = de.u.LoadDll.hFile
                if h:
                    k32.CloseHandle(h)
            elif code == df.EXIT_PROCESS_DEBUG_EVENT:
                ec = de.u.ExitProcess.dwExitCode & 0xFFFFFFFF
                print(f"[daemon] exit 0x{ec:08X}")
                if self.exit_report or self.watch:
                    try:
                        ctx = self._ctx()
                    except Exception:
                        ctx = None
                    if ctx:
                        self._print_exit_report(ctx, ec)
                break
            elif code == df.EXCEPTION_DEBUG_EVENT:
                er = de.u.Exception.ExceptionRecord
                ecode = er.ExceptionCode & 0xFFFFFFFF
                ctx = self._ctx()
                first = bool(de.u.Exception.dwFirstChance)

                if ecode == 0x80000003 and not initial_bp:
                    initial_bp = True
                    if tracing:
                        df.set_trace_flag(pi.hThread, True)
                    status = df.DBG_CONTINUE
                elif ecode == 0x80000003 and self.main_base and self.watch:
                    ea = er.ExceptionAddress or ctx.Rip
                    rva = ea - self.main_base
                    if (self._loader_bp_done or ea != self.main_base + 0x877A
                            ) and rva in self._watch_orig:
                        self._handle_probe_break(ctx, ea)
                        status = df.DBG_CONTINUE
                    elif not self._loader_bp_done and self.main_base:
                        self._loader_bp_done = True
                        status = df.DBG_CONTINUE
                elif ecode == 0x80000004 and tracing:
                    self._record_step(ctx)
                    ctx.EFlags |= 0x100
                    k32.SetThreadContext(pi.hThread, C.byref(ctx))
                    status = df.DBG_CONTINUE
                elif ecode in TERMINAL:
                    exc_count += 1
                    tag = self._label(ctx.Rip)
                    self._record_step(ctx)  # snapshot at each fault
                    stuck_key = (ctx.Rip, ctx.Rsp, ecode)
                    self._stuck[stuck_key] = self._stuck.get(stuck_key, 0) + 1
                    stuck = self._stuck[stuck_key] >= 3
                    jump = (not self.no_jump and first and ecode in JUMP_THROUGH
                            and exc_count < self.max_exc and not stuck)
                    if stuck and not tracing:
                        df.set_trace_flag(pi.hThread, True)
                        tracing = True

                    if jump:
                        self.exc_log.append(ExcNote(
                            n=exc_count, code=ecode, first_chance=first,
                            rip=ctx.Rip, fault_addr=0, rsp=ctx.Rsp,
                            tag=tag, action="jump",
                        ))
                        status = df.DBG_CONTINUE
                    else:
                        self.exc_log.append(ExcNote(
                            n=exc_count, code=ecode, first_chance=first,
                            rip=ctx.Rip, fault_addr=0, rsp=ctx.Rsp,
                            tag=tag, action="STOP",
                        ))
                        df.set_trace_flag(pi.hThread, False)
                        verdict = self._analyze(ctx, er)
                        self._print_verdict(ctx, er, verdict)
                        k32.TerminateProcess(pi.hProcess, 1)
                        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId,
                                               df.DBG_EXCEPTION_NOT_HANDLED)
                        break
                elif ecode not in (0x80000003, 0x80000004):
                    df.set_trace_flag(pi.hThread, False)
                    verdict = self._analyze(ctx, er)
                    self._print_verdict(ctx, er, verdict)
                    k32.TerminateProcess(pi.hProcess, 1)
                    break

            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)

        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
        return 0


def _parse_watch(spec: str) -> tuple[int, str]:
    if ":" in spec:
        rva_s, label = spec.split(":", 1)
    else:
        rva_s, label = spec, spec
    rva_s = rva_s.strip().lower().replace("main+", "")
    rva = int(rva_s, 16)
    return rva, label.strip() or f"0x{rva:X}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Root-cause exception daemon for cmd_shim debugging")
    ap.add_argument("exe")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--trace", action="store_true",
                    help="single-step and keep 512 instruction ring + call log")
    ap.add_argument("--crt", action="store_true",
                    help="probe preset CRT→main RVAs; print call roots on exit")
    ap.add_argument("--interactive", action="store_true",
                    help="probe Explorer double-click path (no args); interactive pipeline")
    ap.add_argument("--watch", action="append", default=[], metavar="RVA[:label]",
                    help="INT3 probe site (repeatable), e.g. 0x8EB9:main entry")
    ap.add_argument("--exit-report", action="store_true",
                    help="on clean exit print probe hits + return-chain call roots")
    ap.add_argument("--max-exc", type=int, default=64,
                    help="max first-chance exceptions to jump through")
    ap.add_argument("--pure", action="store_true",
                    help="remap --crt/--interactive probes via rva_map beside exe")
    ap.add_argument("--rva-map", metavar="PATH",
                    help="rva_map file (old new per line); default: auto or DUMP_RVA_MAP")
    ap.add_argument("--no-jump", action="store_true",
                    help="stop on first fault (no SEH jump-through)")
    opts = ap.parse_args()

    watch: dict[int, str] = {}
    pipeline = CRT_PIPELINE
    rmap: dict[int, int] = {}
    if opts.pure or opts.rva_map:
        rmap_path = opts.rva_map or find_rva_map_for_exe(opts.exe)
        if rmap_path and os.path.isfile(rmap_path):
            rmap = load_rva_map(rmap_path)
            print(f"[pure] loaded {len(rmap)} rva_map entries from {rmap_path}")
        elif opts.pure:
            print("[pure] warning: no rva_map found — probes use shim RVAs as-is")
    if opts.interactive:
        if rmap:
            watch = remap_x86_probes(list(INTERACTIVE_PIPELINE), rmap)
            pipeline = sorted(watch.keys())
        else:
            watch, pipeline = discover_interactive_watch(opts.exe)
    elif opts.crt:
        if rmap:
            watch.update(remap_x86_probes(PURE_CRT_X86, rmap))
            pipeline = sorted(watch.keys())
        else:
            watch.update(CRT_PROBE)
    for spec in opts.watch or []:
        rva, label = _parse_watch(spec)
        if rmap and rva < 0x20000 and rva in rmap:
            rva = rmap[rva]
            label = f"{label} (pure)"
        watch[rva] = label

    daemon = RootCauseDaemon(
        opts.exe, opts.args, trace=opts.trace,
        max_exc=opts.max_exc, no_jump=opts.no_jump,
        watch=watch,
        exit_report=opts.exit_report or bool(watch) or opts.crt or opts.interactive,
        pipeline=pipeline,
        new_console=opts.interactive and not opts.args,
    )
    return daemon.run()


if __name__ == "__main__":
    raise SystemExit(main())
