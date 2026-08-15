"""Static analysis of x86 .text: instruction boundaries, branch edges, and the
data islands that compilers leave inline.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # annotation-only, and importing it eagerly would cycle
    from x86x64.analysis.dynamic import DynamicScanResult


@dataclass
class X86TextAnalysis:
    """Static (+ dynamic merge) control-flow picture of an x86 executable section."""
    epilogue_labels: Dict[int, bytes] = field(default_factory=dict)   # rva → inline x64 epilog
    branch_targets: Set[int] = field(default_factory=set)
    call_targets: Set[int] = field(default_factory=set)  # E8 rel32 destinations only
    branch_sources: Dict[int, List[int]] = field(default_factory=dict)  # tgt → [src rva…]
    interior_labels: Set[int] = field(default_factory=set)
    data_spans: List[Tuple[int, int]] = field(default_factory=list)   # [lo,hi) x86 rva
    orphan_gaps: List[Tuple[int, int]] = field(default_factory=list)  # padding / tables
def _x64_bytes_for_x86_epilogue(sec_data: bytes, off: int) -> Optional[Tuple[int, bytes]]:
    """If *off* begins ``pop …; leave; ret[/n]`` or bare ``ret[/n]``, return (x86_len, x64_bytes).

    Also handles ``add esp, imm`` / ``add rsp, imm`` stack-cleanup patterns that
    appear after the pop sequence in larger-frame epilogues (universal for any
    Win2000 binary compiled with MSVC /O1 or /O2 optimisation).

    Leading ``mov eax, e[bsi]`` (MSVC return-value shuffle before the pop
    chain, e.g. cmd 0x24DF ``8B C3`` / ``89 D8``) is accepted so jcc targets
    to those labels materialize a complete epilogue instead of a remnant.

    Trailing ``pop ecx`` / ``pop edx`` immediately before ``ret`` are MSVC
    stdcall *argument* discards (4 bytes each).  On Win64 those must not become
    ``pop rcx`` — they would eat the return address.  They are dropped; ``ret N``
    is already lowered to plain ``ret``.
    """
    if off >= len(sec_data):
        return None
    b0 = sec_data[off]
    prefix = bytearray()
    pos = off

    def _push_imm_at(p: int) -> Optional[Tuple[int, int]]:
        """Return (imm32, size) for ``push imm8/imm32`` at *p*, else None."""
        if p >= len(sec_data):
            return None
        if sec_data[p] == 0x6A and p + 1 < len(sec_data):  # push ib
            return (struct.unpack('<b', sec_data[p + 1:p + 2])[0] & 0xFFFFFFFF, 2)
        if sec_data[p] == 0x68 and p + 5 <= len(sec_data):  # push id
            return (struct.unpack('<I', sec_data[p + 1:p + 5])[0], 5)
        return None

    # ``push imm; pop r32`` return-value idiom (cmd 0xA11C: push 1; pop eax)
    # before the real pop/ret chain — emit ``mov r32, imm``, never a bare pop.
    pi = _push_imm_at(pos)
    if pi is not None:
        imm, psz = pi
        p2 = pos + psz
        if p2 < len(sec_data) and sec_data[p2] in (
                0x58, 0x59, 0x5A, 0x5B, 0x5D, 0x5E, 0x5F):
            # pop eax/ecx/edx/ebx/ebp/esi/edi
            popb = sec_data[p2]
            # Prefer eax as 89 C0-style via mov eax, imm encoding we already use
            # through the 8B/89 prefix path: emit ``mov eax, imm`` when pop eax,
            # else mov of the popped reg.
            reg_mov = {
                0x58: b'\xb8',  # mov eax, imm32
                0x59: b'\xb9',
                0x5A: b'\xba',
                0x5B: b'\xbb',
                0x5D: b'\xbd',
                0x5E: b'\xbe',
                0x5F: b'\xbf',
            }[popb]
            prefix += reg_mov + struct.pack('<I', imm & 0xFFFFFFFF)
            pos = p2 + 1
            b0 = sec_data[pos] if pos < len(sec_data) else 0
    # ``mov eax, ebx/esi/edi/ecx/edx`` — both ``89 /r`` and ``8B /r`` forms.
    elif pos + 2 <= len(sec_data):
        b1 = sec_data[pos + 1]
        if b0 == 0x89 and b1 in (0xD8, 0xF0, 0xF8, 0xC8, 0xD0):
            prefix += bytes((0x89, b1))
            pos += 2
            b0 = sec_data[pos] if pos < len(sec_data) else 0
        elif b0 == 0x8B and b1 in (0xC3, 0xC6, 0xC7, 0xC1, 0xC2):
            prefix += bytes((0x89, {0xC3: 0xD8, 0xC6: 0xF0, 0xC7: 0xF8,
                                    0xC1: 0xC8, 0xC2: 0xD0}[b1]))
            pos += 2
            b0 = sec_data[pos] if pos < len(sec_data) else 0

    # If we landed on ``pop eax`` but the previous bytes were ``push imm``,
    # the branch targeted the pop half of the idiom — recover the mov.
    if (not prefix and b0 == 0x58 and off >= 2
            and _push_imm_at(off - 2) is not None):
        imm, psz = _push_imm_at(off - 2)  # type: ignore
        if off - 2 + psz == off:
            prefix += b'\xb8' + struct.pack('<I', imm & 0xFFFFFFFF)
            pos = off + 1
            b0 = sec_data[pos] if pos < len(sec_data) else 0
    elif (not prefix and b0 == 0x58 and off >= 5
            and _push_imm_at(off - 5) is not None):
        imm, psz = _push_imm_at(off - 5)  # type: ignore
        if off - 5 + psz == off:
            prefix += b'\xb8' + struct.pack('<I', imm & 0xFFFFFFFF)
            pos = off + 1
            b0 = sec_data[pos] if pos < len(sec_data) else 0
    if b0 == 0xC3:
        return (pos + 1 - off, bytes(prefix + b'\xc3'))
    # x86 ``ret N`` (stdcall callee stack cleanup) → x64 ``ret`` (C3). In the
    # translated calling convention args are register-passed and the caller's
    # align prologue/epilogue (R13 save/restore) cleans the stack, so the callee
    # must NOT pop N bytes — doing so misaligns RSP and returns to garbage. The
    # main RET path already emits C3; mirror that here for materialized epilogues.
    if b0 == 0xC2 and pos + 3 <= len(sec_data):
        return (pos + 3 - off, bytes(prefix + b'\xc3\x90\x90'))
    # Callee-save / frame pops — NOT ecx/edx (those are stdcall arg discards).
    CALLEE_POP = frozenset((0x5E, 0x5F, 0x5B, 0x5D, 0x56, 0x57, 0x53))  # esi/edi/ebx/ebp (+pushes)
    ARG_DISCARD = frozenset((0x59, 0x5A))  # pop ecx / pop edx
    if b0 in ARG_DISCARD:
        # Epilogue is only stdcall arg discards + ret → plain ret on x64.
        while pos < len(sec_data) and sec_data[pos] in ARG_DISCARD:
            pos += 1
        if pos < len(sec_data) and sec_data[pos] == 0xC3:
            return (pos + 1 - off, bytes(prefix + b'\xc3'))
        if pos + 3 <= len(sec_data) and sec_data[pos] == 0xC2:
            return (pos + 3 - off, bytes(prefix + b'\xc3\x90\x90'))
        return None
    if b0 not in CALLEE_POP:
        # Do not start/continue at ``pop eax`` (0x58) — that is the second
        # half of ``push imm; pop eax`` and must already be folded into prefix.
        return None
    x64 = bytearray(prefix)
    while pos < len(sec_data):
        b = sec_data[pos]
        if b in CALLEE_POP:
            x64.append(b)
            pos += 1
            continue
        if b in ARG_DISCARD:
            # Consume stdcall arg-discard pops; do not emit them on x64.
            while pos < len(sec_data) and sec_data[pos] in ARG_DISCARD:
                pos += 1
            continue
        if b == 0xC9:
            x64.append(0xC9)
            pos += 1
            continue
        # ── ADD ESP, imm32  (81 C4 xx xx xx xx) ──────────────────────────
        if b == 0x81 and pos + 6 <= len(sec_data) and sec_data[pos + 1] == 0xC4:
            imm32 = sec_data[pos + 2:pos + 6]
            x64 += b'\x48\x81\xc4' + imm32
            pos += 6
            continue
        # ── ADD ESP, imm8   (83 C4 xx) ───────────────────────────────────
        if b == 0x83 and pos + 3 <= len(sec_data) and sec_data[pos + 1] == 0xC4:
            imm8 = sec_data[pos + 2:pos + 3]
            x64 += b'\x48\x83\xc4' + imm8
            pos += 3
            continue
        if b == 0xC3:
            x64.append(0xC3)
            pos += 1
            return (pos - off, bytes(x64))
        if b == 0xC2 and pos + 3 <= len(sec_data):
            x64 += b'\xc3\x90\x90'   # ret N → ret (+NOP pad: keep length stable)
            pos += 3
            return (pos - off, bytes(x64))
        break
    return None
def _is_plausible_x86_insn_start(sec_data: bytes, off: int,
                                 image_base: int, sec_rva: int) -> bool:
    """True when *off* decodes as at least one valid x86 instruction."""
    if off < 0 or off >= len(sec_data):
        return False
    b0 = sec_data[off]
    if b0 == 0x00 and off + 1 < len(sec_data) and sec_data[off + 1] == 0x00:
        return False
    if not HAS_CAPSTONE:
        return b0 not in (0x00, 0xCC)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    try:
        insns = list(md.disasm(sec_data[off:off + 16], image_base + sec_rva + off, count=1))
    except CsError:
        return False
    return bool(insns) and insns[0].mnemonic not in ('invalid', '.byte')
def _valid_x86_insn_rvas(sec_data: bytes, sec_rva: int,
                         image_base: int,
                         entry_rvas: Optional[Set[int]] = None) -> Set[int]:
    """RVAs that are real x86 instruction boundaries."""
    valid: Set[int] = set()
    if not HAS_CAPSTONE or not sec_data:
        return valid
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    sec_end = sec_rva + len(sec_data)
    starts: Set[int] = set(entry_rvas or ())
    starts.add(sec_rva)
    for func_rva in sorted(starts):
        if not (sec_rva <= func_rva < sec_end):
            continue
        off = func_rva - sec_rva
        try:
            for insn in md.disasm(sec_data[off:off + 65536], image_base + func_rva):
                valid.add(insn.address - image_base)
                if insn.mnemonic in ('ret', 'retn'):
                    break
                if insn.mnemonic == 'jmp' and insn.operands:
                    op = insn.operands[0]
                    if op.type == X86_OP_IMM:
                        break
        except CsError:
            continue
    return valid
def _collect_x86_branch_edges(sec_data: bytes, sec_rva: int,
                             sec_end: int,
                             valid_targets: Optional[Set[int]] = None) -> Dict[int, List[int]]:
    """Map every in-section branch destination → list of source RVAs."""
    edges: Dict[int, List[int]] = {}
    n = len(sec_data)

    def _add(src: int, tgt: int) -> None:
        if not (sec_rva <= tgt < sec_end):
            return
        if valid_targets is not None and tgt not in valid_targets:
            return
        edges.setdefault(tgt, []).append(src)

    for i in range(n):
        src = sec_rva + i
        b = sec_data[i]
        if b == 0xE8 and i + 5 <= n:
            rel = int.from_bytes(sec_data[i + 1:i + 5], 'little', signed=True)
            _add(src, src + 5 + rel)
        elif b == 0xE9 and i + 5 <= n:
            rel = int.from_bytes(sec_data[i + 1:i + 5], 'little', signed=True)
            _add(src, src + 5 + rel)
        elif 0x70 <= b <= 0x7F and i + 2 <= n:
            rel = struct.unpack_from('b', sec_data, i + 1)[0]
            _add(src, src + 2 + rel)
        elif (b == 0x0F and i + 6 <= n and 0x80 <= sec_data[i + 1] <= 0x8F):
            rel = int.from_bytes(sec_data[i + 2:i + 6], 'little', signed=True)
            _add(src, src + 6 + rel)
    return edges
def _merge_spans(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping or adjacent spans and return them sorted."""
    if not spans:
        return []
    sorted_spans = sorted(spans)
    merged = [sorted_spans[0]]
    for lo, hi in sorted_spans[1:]:
        prev_lo, prev_hi = merged[-1]
        if lo <= prev_hi + 1:
            merged[-1] = (prev_lo, max(prev_hi, hi))
        else:
            merged.append((lo, hi))
    return merged
def _scan_x86_data_spans(sec_data: bytes, sec_rva: int,
                         branch_targets: Set[int],
                         min_run: int = 8) -> List[Tuple[int, int]]:
    """Find likely non-code filler (00/CC/90/FF runs) AND embedded string data
    (printable-ASCII-rich regions with null bytes) not referenced as branch
    targets.  Strings are typically narrow (C locale) or wide (UTF-16LE)
    and appear between functions or after ``jmp`` / ``ret`` padding."""
    spans: List[Tuple[int, int]] = []
    i = 0
    n = len(sec_data)

    # ── pass 1: filler bytes (00 / CC / 90 / FF) ──────────────────────
    while i < n:
        b = sec_data[i]
        if b not in (0x00, 0xCC, 0x90, 0xFF):
            i += 1
            continue
        j = i + 1
        while j < n and sec_data[j] in (0x00, 0xCC, 0x90, 0xFF):
            j += 1
        if j - i >= min_run:
            lo = sec_rva + i
            hi = sec_rva + j
            if not any(lo <= t < hi for t in branch_targets):
                spans.append((lo, hi))
        i = j

    # ── pass 2: string-like data (printable ASCII + nulls) ────────────
    # Universal characteristic: embedded strings in MSVC .text contain
    # printable ASCII (0x20-0x7E) and null bytes (0x00) as terminators /
    # wide-char padding.  These are NOT valid x86 code and must be
    # preserved verbatim in the output.
    i = 0
    candidate: List[int] = []
    while i < n:
        b = sec_data[i]
        if b in (0x00, 0x09, 0x0A, 0x0D, 0x20,0x21,0x22,0x23,0x24,0x25,0x26,
                 0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,
                 0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,
                 0x3F,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,
                 0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,
                 0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,0x60,0x61,0x62,
                 0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,
                 0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,
                 0x7B,0x7C,0x7D,0x7E,0x7F):
            candidate.append(i)
        i += 1

    if candidate:
        str_spans: List[Tuple[int, int]] = []
        start_pos = candidate[0]
        for k in range(1, len(candidate)):
            if candidate[k] - candidate[k - 1] > 3:
                end_pos = candidate[k - 1] + 1
                str_spans.append((start_pos, end_pos))
                start_pos = candidate[k]
        str_spans.append((start_pos, candidate[-1] + 1))

        for lo_off, hi_off in str_spans:
            if hi_off - lo_off < min_run:
                continue
            lo = sec_rva + lo_off
            hi = sec_rva + hi_off
            if any(lo <= t < hi for t in branch_targets):
                continue
            spans.append((lo, hi))
    return _merge_spans(spans)
def analyze_x86_text_section(pe: 'PE32Image', sec_data: bytes, sec_rva: int,
                             dyn: Optional[DynamicScanResult] = None,
                             entry_rvas: Optional[Set[int]] = None) -> X86TextAnalysis:
    """
    Pre-translation static CF analysis: epilogue labels, branch graph, data gaps.

    Merged with Unicorn ``visited_blocks`` / ``branch_targets`` when available so
    interior epilogue labels and orphan padding are known before Keystone emit.
    """
    sec_end = sec_rva + len(sec_data)
    cf = X86TextAnalysis()
    entries = entry_rvas or set()
    insn_rvas = _valid_x86_insn_rvas(sec_data, sec_rva, pe.image_base, entries)
    use_insn_filter = len(insn_rvas) >= max(64, len(entries))

    edges = _collect_x86_branch_edges(
        sec_data, sec_rva, sec_end,
        insn_rvas if use_insn_filter else None)
    cf.branch_sources = edges
    cf.branch_targets = set(edges.keys())
    for i in range(len(sec_data) - 5):
        if sec_data[i] == 0xE8:
            rel = int.from_bytes(sec_data[i + 1:i + 5], 'little', signed=True)
            cf.call_targets.add(sec_rva + i + 5 + rel)
    if not use_insn_filter:
        # Drop mid-instruction targets when we cannot trust full insn map.
        cf.branch_targets = {
            t for t in cf.branch_targets
            if _is_plausible_x86_insn_start(sec_data, t - sec_rva, pe.image_base, sec_rva)
        }
        cf.branch_sources = {
            t: srcs for t, srcs in cf.branch_sources.items()
            if t in cf.branch_targets
        }

    if dyn:
        for r in dyn.call_targets:
            if sec_rva <= r < sec_end and (not insn_rvas or r in insn_rvas):
                cf.branch_targets.add(r)
                cf.call_targets.add(r)
        for r in dyn.branch_targets:
            if sec_rva <= r < sec_end and (not insn_rvas or r in insn_rvas):
                cf.branch_targets.add(r)
        for r in dyn.visited_blocks:
            if sec_rva <= r < sec_end and (not insn_rvas or r in insn_rvas):
                cf.branch_targets.add(r)

    for tgt in sorted(cf.branch_targets):
        off = tgt - sec_rva
        if off < 0 or off >= len(sec_data):
            continue
        ep = _x64_bytes_for_x86_epilogue(sec_data, off)
        if ep is not None:
            _x86_len, x64_ep = ep
            cf.epilogue_labels[tgt] = x64_ep
            cf.interior_labels.add(tgt)
            continue
        if tgt not in entries:
            b0 = sec_data[off]
            if b0 in (0x5E, 0x5F, 0x5B, 0x5D, 0xC3, 0xC9, 0x90, 0xCC, 0x00):
                cf.interior_labels.add(tgt)

    # Also walk all pop/leave/ret tails reachable even if not branch-targeted yet.
    for i in range(len(sec_data) - 3):
        ep = _x64_bytes_for_x86_epilogue(sec_data, i)
        if ep is None:
            continue
        rva = sec_rva + i
        _x86_len, x64_ep = ep
        cf.epilogue_labels.setdefault(rva, x64_ep)

    cf.data_spans = _scan_x86_data_spans(sec_data, sec_rva, cf.branch_targets)
    # MSVC EH3/EH4 scope tables live in .text next to strings; force them into
    # data_spans so they are not instruction-translated (corrupt SEH → random
    # execute during unwind/exit).
    try:
        from x86x64.analysis.discover import _scope_table_spans
        for start, size in _scope_table_spans(sec_data, sec_rva, pe):
            cf.data_spans.append((start, start + size))
        cf.data_spans = _merge_spans(cf.data_spans)
    except Exception:
        pass
    cf.orphan_gaps = list(cf.data_spans)
    return cf
