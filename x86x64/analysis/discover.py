"""Function and pointer discovery.

Finds entry points, SEH anchors, jump thunks, and pointer slots that the
translator has to know about before it can move any code.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # annotation-only, and importing it eagerly would cycle
    from x86x64.analysis.dynamic import DynamicScanResult


def _looks_like_utf16le_dword(val: int) -> bool:
    """True when a DWORD is two ASCII UTF-16LE code units (or NUL).

    Heuristic pointer scans must not treat ``'.\\0C\\0'`` inside a wide string
    as an image RVA — relocating it with a QWORD write destroys the string.
    """
    b0 = val & 0xFF
    b1 = (val >> 8) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 24) & 0xFF
    if b1 != 0 or b3 != 0:
        return False

    def _ok(ch: int) -> bool:
        return ch == 0 or 0x20 <= ch <= 0x7E

    return _ok(b0) and _ok(b2)


# PE sections almost always start at RVA >= 0x1000.  Counters, sizes, and
# single-byte fields in .data are often small integers that would otherwise
# match ``0 < val < image_size`` and get QWORD-widened over neighbouring
# real pointers (cmd.exe: 0xa at .data+0x8d4 clobbers cmdline ptr at +0x8d8).
_MIN_PLAUSIBLE_PTR_RVA = 0x1000


def _plausible_image_pointer(val: int, old_base: int, image_size: int) -> bool:
    """True when *val* is an absolute image VA or a section-range RVA."""
    if image_size <= 0:
        return False
    img_end = old_base + image_size
    if old_base <= val < img_end:
        return (val - old_base) >= _MIN_PLAUSIBLE_PTR_RVA
    if _MIN_PLAUSIBLE_PTR_RVA <= val < image_size:
        return True
    return False


def discover_static_pointers(data: bytes, section_rva: int,
                             old_base: int, image_size: int) -> Set[int]:
    """Find offsets in a data section whose DWORD looks like an in-image VA or RVA."""
    sites: Set[int] = set()
    for off in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, off)[0]
        # Wide-string ASCII pairs (``.\\0C\\0``) must not be promoted to
        # pointer sites — a QWORD reloc write would destroy the string.
        if _looks_like_utf16le_dword(val):
            continue
        if _plausible_image_pointer(val, old_base, image_size):
            sites.add(section_rva + off)
    return sites
def discover_image_pointer_sites(pe: 'PE32Image',
                                 dyn: Optional[DynamicScanResult] = None) -> Set[int]:
    """Scan every section for pointer-like DWORDs, relocs, and dynamic write sites."""
    sites: Set[int] = set()
    old_base = pe.image_base
    for rva, _rtype in pe.parse_relocations():
        sites.add(rva)
    for sec in pe.sections:
        if not sec['raw_sz']:
            continue
        data = pe.get_section_data(sec)
        sites |= discover_static_pointers(
            data, sec['vaddr'], old_base, pe.image_size)
    if dyn:
        for site_va in dyn.pointer_writes:
            sites.add(site_va - old_base)
        for va in dyn.pointer_values:
            if old_base <= va < old_base + pe.image_size:
                sites.add(va - old_base)
    return sites
def _is_nested_ebp_callee_save(sec_data: bytes, off: int,
                               max_back: int = 160) -> bool:
    """True when push ebx/esi/edi sits inside an active push-ebp frame prologue."""
    if off < 0 or off + 3 > len(sec_data):
        return False
    if sec_data[off:off + 3] not in (b'\x53\x56\x57', b'\x53\x55\x56'):
        return False
    for back in range(1, min(max_back, off) + 1):
        p = off - back
        if sec_data[p] == 0xC3:
            return False
        if sec_data[p] == 0xC2 and p + 3 <= len(sec_data):
            return False
        if sec_data[p:p + 3] in (b'\x55\x8b\xec', b'\x55\x8B\xEC'):
            return True
    return False
def _is_post_chkstk_callee_save(sec_data: bytes, off: int) -> bool:
    """True when a callee-save push block is the BODY of a large-frame function.

    MSVC emits large stack frames as ``mov eax, imm32`` (``B8 imm32``) +
    ``call __chkstk`` (``E8 rel32``) followed immediately by the callee-save
    spill (``push ebx; push ebp; push esi; push edi`` etc.). The push block at
    ``off`` then looks exactly like a frameless function prologue, so the entry
    scanner registers a *phantom* second entry one instruction past the probe
    call (cmd 0xA4F1 inside 0xA4E7). That duplicate is translated without the
    chkstk frame context (no R15 arg anchor), so its deep ``[esp+disp]``
    incoming-parameter reads return raw stack garbage and any caller routed to
    it faults (wcschr(0x73006C)). The real entry is the ``mov eax,imm`` 10 bytes
    back, so this candidate must be rejected. Keyed purely on the canonical
    probe fingerprint — universal, not binary-specific.
    """
    if off < 10:
        return False
    # ``mov eax, imm32`` ; ``call rel32`` immediately preceding the push block.
    return sec_data[off - 10] == 0xB8 and sec_data[off - 5] == 0xE8
def _is_batch_helper_entry(sec_data: bytes, off: int) -> bool:
    """MSVC helper: and byte ptr [global], 0; push esi; … (cmd 0x5581/0x6581)."""
    if off + 8 > len(sec_data):
        return False
    if sec_data[off] not in (0x80, 0x83):
        return False
    if sec_data[off + 1] not in (0x25, 0x26):
        return False
    if sec_data[off + 6] != 0:
        return False
    tail = sec_data[off + 7:off + 12]
    return bool(tail) and tail[0] in (0x56, 0x53, 0x55)  # push esi/ebx/ebp
def discover_data_code_entry_rvas(pe: 'PE32Image', sec_rva: int,
                                  sec_end: int) -> Set[int]:
    """RVAs in *sec* that appear as absolute code pointers in non-exec sections.

    Win2000 MSVC binaries keep command/dispatch/atexit tables in ``.data`` as
    ``DWORD`` image VAs.  Those targets are often frameless ``stdcall`` bodies
    (``mov eax,[esp+4]; …; ret 4``) that prologue scans miss — without an
    entry they stay identity-mapped and calls through the table jump into
    the wrong bytes of the expanded PE64 ``.text``.
    """
    found: Set[int] = set()
    base = pe.image_base
    img_end = base + pe.image_size
    text = None
    for s in pe.sections:
        if s['vaddr'] == sec_rva:
            text = pe.get_section_data(s)
            break

    def _accept(va: int) -> None:
        if not (base <= va < img_end):
            return
        if not _plausible_image_pointer(va, base, pe.image_size):
            return
        if _looks_like_utf16le_dword(va):
            return
        rva = va - base
        if not (sec_rva <= rva < sec_end):
            return
        # Prefer targets that look like real instruction starts.
        if text is not None:
            off = rva - sec_rva
            if off < 0 or off >= len(text):
                return
            b0 = text[off]
            if b0 in (0x00, 0xCC, 0x90) and (
                    off + 1 >= len(text) or text[off + 1] in (0x00, 0xCC, 0x90)):
                return
        found.add(rva)

    for sec in pe.sections:
        if sec['flags'] & 0x20000000:  # executable — skip code
            continue
        if not sec.get('raw_sz'):
            continue
        data = pe.get_section_data(sec)
        for i in range(0, len(data) - 3, 4):
            va = struct.unpack_from('<I', data, i)[0]
            _accept(va)
    for site_rva, _rtype in pe.parse_relocations():
        sec = pe.section_for_rva(site_rva)
        if not sec or (sec['flags'] & 0x20000000):
            continue
        data = pe.get_section_data(sec)
        off = site_rva - sec['vaddr']
        if off < 0 or off + 4 > len(data):
            continue
        _accept(struct.unpack_from('<I', data, off)[0])
    return found


def discover_text_imm_code_entry_rvas(pe: 'PE32Image', sec_data: bytes,
                                      sec_rva: int) -> Set[int]:
    """Code RVAs materialized as ``push imm32`` / ``mov r32, imm32`` in *sec*.

    MSVC registers CRT callbacks with ``push <code_va>``; those targets are
    often tiny ``cmp [esp+4], …; ret N`` stubs that prologue scans miss.
    Floor-mapping the missing RVA then points the registered VA into the
    previous function's epilogue.
    """
    found: Set[int] = set()
    base = pe.image_base
    img_end = base + pe.image_size
    sec_end = sec_rva + len(sec_data)
    n = len(sec_data)

    def _accept(va: int) -> None:
        if not (base <= va < img_end):
            return
        if not _plausible_image_pointer(va, base, pe.image_size):
            return
        rva = va - base
        if not (sec_rva <= rva < sec_end):
            return
        off = rva - sec_rva
        b0 = sec_data[off]
        if b0 in (0x00, 0xCC) and (
                off + 1 >= n or sec_data[off + 1] in (0x00, 0xCC)):
            return
        # Reject UTF-16LE string starts (``L"..."``) mistaken for code.
        if (off + 3 < n and sec_data[off + 1] == 0 and sec_data[off + 3] == 0
                and 0x20 <= b0 <= 0x7E and 0x20 <= sec_data[off + 2] <= 0x7E):
            return
        # Prefer real instruction openers (callbacks, stdcall, frames).
        if b0 not in (0x55, 0x53, 0x56, 0x57, 0x8B, 0x83, 0x81, 0x51,
                      0x6A, 0x68, 0xB8, 0xE9, 0x33, 0x31, 0xFF, 0x48, 0x80,
                      0x85, 0x3B, 0x3D, 0xA1, 0x8A, 0x0F):
            return
        found.add(rva)

    for i in range(max(0, n - 5)):
        b0 = sec_data[i]
        if b0 == 0x68:
            _accept(struct.unpack_from('<I', sec_data, i + 1)[0])
        elif 0xB8 <= b0 <= 0xBF:
            _accept(struct.unpack_from('<I', sec_data, i + 1)[0])
    return found


def discover_function_rvas(pe: 'PE32Image', sec_data: bytes, sec_rva: int,
                           dyn: Optional[DynamicScanResult] = None) -> List[int]:
    """
    Find likely function entry RVAs inside an executable section.

    Uses PE entry/export RVAs, common x86 prologues, import thunks,
    and addresses observed during Unicorn emulation.
    """
    found: Set[int] = set()
    sec_end = sec_rva + len(sec_data)
    _static_calls = bool(_pure_translator_mode()
                         or os.environ.get('CMD_STATIC_CALLS'))

    def _in_sec(rva: int) -> bool:
        return sec_rva <= rva < sec_end

    if pe.entry_rva and _in_sec(pe.entry_rva):
        found.add(pe.entry_rva)
    for exp in pe.parse_exports():
        if _in_sec(exp['rva']):
            found.add(exp['rva'])

    for i in range(max(0, len(sec_data) - 3)):
        win = sec_data[i:i + 4]
        if win[:3] in (b'\x55\x8b\xec', b'\x55\x8B\xEC'):
            found.add(sec_rva + i)
        if i >= 1 and sec_data[i - 1:i + 3] == b'\x53\x55\x8b\xec'[:3]:
            found.add(sec_rva + i - 1)
        # Frameless MSVC callee-save entry (push ebx/esi/edi, no EBP frame)
        if sec_data[i:i + 3] == b'\x53\x56\x57':
            if (not (_static_calls and _is_nested_ebp_callee_save(sec_data, i))
                    and not _is_post_chkstk_callee_save(sec_data, i)):
                found.add(sec_rva + i)
        # Frameless callee-save entry: push ebx; push ebp; push esi; push edi
        if (_static_calls and sec_data[i:i + 4] == b'\x53\x55\x56\x57'):
            if (not _is_nested_ebp_callee_save(sec_data, i)
                    and not _is_post_chkstk_callee_save(sec_data, i)):
                found.add(sec_rva + i)
        # Batch/copy helper (and byte ptr [global],0; push esi; …)
        if _static_calls and _is_batch_helper_entry(sec_data, i):
            found.add(sec_rva + i)
        # stdcall wchar helper: mov ecx,[esp+4]; test ecx,ecx; mov eax,ecx
        if (sec_data[i:i + 4] == b'\x8b\x4c\x24\x04' and i + 6 < len(sec_data)
                and sec_data[i + 4:i + 6] == b'\x85\xc9'):
            found.add(sec_rva + i)
        # stdcall helper: mov eax,[esp+4]; …; ret 4  (cmd command-table bodies)
        if sec_data[i:i + 4] == b'\x8b\x44\x24\x04':
            found.add(sec_rva + i)
        # CRT/DLL callback: cmp dword ptr [esp+4], imm  (atexit / DllMain-style)
        if sec_data[i:i + 4] == b'\x83\x7c\x24\x04':
            found.add(sec_rva + i)

    for imp in pe.parse_imports():
        for fn in imp['functions']:
            iat_rva = fn.get('iat_rva')
            if iat_rva and _in_sec(iat_rva):
                found.add(iat_rva)

    if dyn:
        found.update(r for r in dyn.visited_blocks if _in_sec(r))
        found.update(r for r in dyn.call_targets if _in_sec(r))

    # .data / reloc sites that hold code VAs (dispatch tables, atexit, …).
    # These are often frameless stdcall thunks missed by prologue scans.
    found.update(r for r in discover_data_code_entry_rvas(pe, sec_rva, sec_end)
                 if _in_sec(r))

    # Absolute code addresses pushed/moved in .text (atexit, SetUnhandled…).
    # Without an entry, remap_image_va floor-maps them into the previous
    # function's epilogue (cmd 0x9E65 → 0x11FC3 mid-ret).
    found.update(r for r in discover_text_imm_code_entry_rvas(
        pe, sec_data, sec_rva) if _in_sec(r))

    # Static direct-CALL (E8 rel32) target discovery. Dynamic emulation misses
    # functions whose callers never execute under Unicorn (e.g. cmd's command
    # dispatch helpers), so their entries are never queued and they end up
    # mistranslated. Every E8 whose target lands on a plausible instruction
    # start inside this section is a function entry. Gated to avoid disturbing
    # the legacy hacked default layout.
    if _static_calls:
        n = len(sec_data)
        for i in range(max(0, n - 5)):
            if sec_data[i] != 0xE8:
                continue
            rel = int.from_bytes(sec_data[i + 1:i + 5], 'little', signed=True)
            tgt = sec_rva + i + 5 + rel
            if not _in_sec(tgt):
                continue
            off = tgt - sec_rva
            b0 = sec_data[off]
            # Plausible function opener; skip obvious data (00/filler).
            if b0 in (0x55, 0x53, 0x56, 0x57, 0x8B, 0x83, 0x81, 0x51,
                      0x6A, 0x68, 0xB8, 0xE9, 0x33, 0x31, 0xFF, 0x48, 0x80):
                if b0 == 0x53 and _is_nested_ebp_callee_save(sec_data, off):
                    continue
                # Callee-save block right after a ``mov eax,imm; call __chkstk``
                # probe is a large-frame function BODY, not an entry (the real
                # entry is the ``mov eax,imm`` 10 bytes back). Snap back to it.
                if b0 in (0x53, 0x55, 0x56, 0x57) and _is_post_chkstk_callee_save(
                        sec_data, off):
                    if sec_data[off - 10] == 0xB8:
                        found.add(tgt - 10)
                    continue
                if b0 == 0x8B and off + 1 < len(sec_data):
                    modrm = sec_data[off + 1]
                    # ``mov r32, [abs32]`` — interior data load, not an entry.
                    if modrm in (0x0D, 0x05, 0x15, 0x1D, 0x35, 0x3D):
                        continue
                if _is_batch_helper_entry(sec_data, off):
                    found.add(tgt)
                    continue
                found.add(tgt)

    return sorted(found)
def discover_seh_except_handler3_push_vas(pe: 'PE32Image', text_data: bytes,
                                          text_rva: int) -> Set[int]:
    """x86 VAs pushed as SEH handler when the target is an _except_handler3 IAT jmp."""
    iat_fn: Dict[int, str] = {}
    for imp in pe.parse_imports():
        for fn in imp['functions']:
            iat_rva = fn.get('iat_rva')
            if iat_rva:
                iat_fn[iat_rva] = fn.get('name') or ''
    base = pe.image_base
    img_end = base + pe.image_size
    handlers: Set[int] = set()
    i = 0
    while i < len(text_data) - 11:
        is_push_m1 = (text_data[i] == 0x6A and text_data[i + 1] == 0xFF)
        is_push_m1 |= text_data[i:i + 5] == b'\x68\xff\xff\xff\xff'
        if is_push_m1:
            p = i + (2 if text_data[i] == 0x6A else 5)
            if p + 10 <= len(text_data) and text_data[p] == 0x68 and text_data[p + 5] == 0x68:
                handler_va = struct.unpack_from('<I', text_data, p + 6)[0]
                if base <= handler_va < img_end:
                    hrva = handler_va - base
                    off = hrva - text_rva
                    if (0 <= off <= len(text_data) - 6
                            and text_data[off:off + 2] == b'\xff\x25'):
                        slot = struct.unpack_from('<I', text_data, off + 2)[0]
                        if slot >= base:
                            slot_rva = slot - base
                            if iat_fn.get(slot_rva) == '_except_handler3':
                                handlers.add(handler_va)
                i = p + 10
                continue
        i += 1
    return handlers
def discover_seh_text_targets(text_data: bytes, text_rva: int,
                              image_base: int, image_size: int) -> Set[int]:
    """
    RVAs referenced by MSVC x86 SEH registration (push -1; push scope; push filter).
    Uses byte-pattern scan — linear Capstone disasm fails on cmd's .text jump tables.
    """
    targets: Set[int] = set()
    img_end = image_base + image_size
    i = 0
    while i < len(text_data) - 11:
        # push imm8 -1  (6A FF)  or  push 0xFFFFFFFF  (68 FF FF FF FF)
        is_push_m1 = (text_data[i] == 0x6A and text_data[i + 1] == 0xFF)
        is_push_m1 |= text_data[i:i + 5] == b'\x68\xff\xff\xff\xff'
        if is_push_m1:
            p = i + (2 if text_data[i] == 0x6A else 5)
            if p + 10 <= len(text_data) and text_data[p] == 0x68 and text_data[p + 5] == 0x68:
                for off in (p + 1, p + 6):
                    va = struct.unpack_from('<I', text_data, off)[0]
                    if image_base <= va < img_end:
                        targets.add(va - image_base)
                i = p + 10
                continue
        i += 1
    return targets
def _is_wchar16le_text_at(text_data: bytes, off: int) -> bool:
    """Heuristic: offset looks like a UTF-16LE literal (``Sun``, ``Mon``, …)."""
    if off + 3 >= len(text_data):
        return False
    lo, hi = text_data[off], text_data[off + 1]
    if hi != 0 or lo == 0:
        return False
    if lo in (0x55, 0x53, 0x56, 0x57, 0x6A, 0x68, 0xE8, 0xFF, 0xC3, 0x8B, 0x89):
        return False
    return lo < 0x7F
def _is_embedded_text_data_at(text_data: bytes, off: int) -> bool:
    """Heuristic: offset looks like embedded data (UTF-16LE or narrow ASCII)."""
    if _is_wchar16le_text_at(text_data, off):
        return True
    n = len(text_data)
    if off >= n or text_data[off] == 0:
        return False
    b0 = text_data[off]
    if not (0x20 <= b0 < 0x7f or b0 in (0x2e, 0x2f, 0x3a, 0x3b)):
        return False
    j = off
    while j < n and j < off + 64:
        b = text_data[j]
        if b == 0:
            return j > off
        if b >= 0x7f or b in (0xe8, 0xff, 0xc3, 0x8b, 0x89, 0x68, 0x6a):
            return False
        j += 1
    return False
def _embedded_text_blob_size(text_data: bytes, off: int,
                             max_size: int = 128) -> int:
    """Byte size of an embedded wchar/ascii literal in x86 .text."""
    n = len(text_data)
    if off < 0 or off >= n:
        return 0
    if text_data[off:off + 4] == b'\xff\xff\xff\xff':
        return 16
    if off + 1 < n and text_data[off + 1] == 0:
        i = off
        while i + 1 < n and i < off + max_size:
            if text_data[i] == 0 and text_data[i + 1] == 0:
                return i - off + 2
            i += 2
    i = off
    while i < n and i < off + max_size and text_data[i] != 0:
        i += 1
    return max(4, min(max_size, i - off + 1))
def discover_push_imm_text_data_refs(text_data: bytes, text_rva: int,
                                     image_base: int,
                                     image_size: int) -> Set[int]:
    """RVAs in .text used as data via ``push imm32`` (locale tables, literals)."""
    refs: Set[int] = set()
    img_end = image_base + image_size
    text_end = text_rva + len(text_data)
    i = 0
    n = len(text_data)
    while i < n - 5:
        if text_data[i] == 0x68:
            imm = struct.unpack_from('<I', text_data, i + 1)[0]
            if image_base <= imm < img_end:
                old_rva = imm - image_base
                if text_rva <= old_rva < text_end:
                    off = old_rva - text_rva
                    if _is_embedded_text_data_at(text_data, off):
                        refs.add(old_rva)
        i += 1
    return refs
def discover_seh_scope_anchors(text_data: bytes, text_rva: int,
                               image_base: int, image_size: int) -> Dict[int, int]:
    """Map x86 scope-table RVA → the function RVA that registers it."""
    anchors: Dict[int, int] = {}
    img_end = image_base + image_size
    i = 0
    while i < len(text_data) - 11:
        is_push_m1 = (text_data[i] == 0x6A and text_data[i + 1] == 0xFF)
        is_push_m1 |= text_data[i:i + 5] == b'\x68\xff\xff\xff\xff'
        if is_push_m1:
            p = i + (2 if text_data[i] == 0x6A else 5)
            if p + 10 <= len(text_data) and text_data[p] == 0x68 and text_data[p + 5] == 0x68:
                scope_va = struct.unpack_from('<I', text_data, p + 1)[0]
                if image_base <= scope_va < img_end:
                    anchors[scope_va - image_base] = text_rva + i
                i = p + 10
                continue
        i += 1
    return anchors
def discover_ff25_jmp_thunks(text_data: bytes, text_rva: int,
                             image_base: int,
                             iat_slot_rvas: Optional[Set[int]] = None,
                             exclude_rva_spans: Optional[List[Tuple[int, int]]] = None) -> Set[int]:
    """RVAs of x86 `jmp dword ptr [abs32]` import / runtime tail thunks in .text."""
    thunks: Set[int] = set()
    if not HAS_CAPSTONE:
        return thunks
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    i = 0
    while i < len(text_data) - 6:
        if text_data[i:i + 2] != b'\xff\x25':
            i += 1
            continue
        rva = text_rva + i
        if exclude_rva_spans and _rva_inside_spans(rva, exclude_rva_spans):
            i += 1
            continue
        insns = list(md.disasm(text_data[i:i + 6], image_base + rva, count=1))
        if insns and insns[0].mnemonic == 'jmp':
            absva = struct.unpack_from('<I', text_data, i + 2)[0]
            if absva < image_base:
                i += 1
                continue
            slot_rva = absva - image_base
            if iat_slot_rvas is not None and slot_rva not in iat_slot_rvas:
                i += 1
                continue
            thunks.add(rva)
        i += 1
    return thunks
def _msvc_scope_table_size(pe: 'PE32Image', text_data: bytes, text_rva: int,
                           off: int) -> int:
    """
    Byte size of an x86 MSVC scope table (sentinel + 16-byte entries).

    cmd.exe stores scope tables adjacent to string blobs; stop when the next
    entry no longer looks like code-range begin/end/filter/handler DWORDs.
    Filter/handler may be a code pointer *or* a small EH constant
    (e.g. ``0x01`` = EXECUTE_HANDLER, cmd also uses ``0x2F``/``0x3F``).
    """
    if off < 0 or off + 4 > len(text_data):
        return 16
    if text_data[off:off + 4] != b'\xff\xff\xff\xff':
        return min(16, len(text_data) - off)
    base = pe.image_base
    text = pe.sections[0]
    code_lo = base + text['vaddr']
    code_hi = code_lo + text.get('vsize', len(text_data))

    def _code_or_eh_const(val: int) -> bool:
        if val == 0 or val >= 0xFFFFFFFE:
            return True
        if val <= 0xFFFF:  # disposition / small sentinel, not a VA
            return True
        return code_lo <= val < code_hi

    size = 4
    for _ in range(32):
        eoff = off + size
        if eoff + 16 > len(text_data):
            break
        begin, end, filt, handler = struct.unpack_from('<4I', text_data, eoff)
        if not (code_lo <= begin < code_hi and code_lo < end <= code_hi and begin < end):
            break
        # EH3 filter/handler misread as begin/end: span is only a few bytes
        # (cmd 0x1a88).  Stop — do not treat as an EH4 try-range entry.
        if (end - begin) <= 8:
            break
        # cmd.exe packs UTF-16 literals immediately after begin/end for some
        # tables, so filter/handler may look like wchar data (``0x2A002E``).
        # Still count the 16-byte slot; rematerialize zeroes bogus filt/handler.
        size += 16
        # Stop if the *next* dword looks like a new sentinel or non-code
        # (avoid swallowing the following string blob as a 2nd entry).
        if off + size + 4 <= len(text_data):
            nxt = struct.unpack_from('<I', text_data, off + size)[0]
            if nxt == 0xFFFFFFFF:
                break
            if not (code_lo <= nxt < code_hi):
                break
    # Sentinel alone is not a scope table (avoids every ``FF FF FF FF`` in
    # .text becoming a false-positive 16-byte span that steals code RVAs).
    return size if size >= 20 else 0
def _scope_table_spans(text_data: bytes, text_rva: int,
                       pe: 'PE32Image') -> List[Tuple[int, int]]:
    """(start_rva, byte_size) for each MSVC scope table in .text."""
    spans: List[Tuple[int, int]] = []
    i = 0
    while i < len(text_data) - 4:
        if text_data[i:i + 4] == b'\xff\xff\xff\xff':
            size = _msvc_scope_table_size(pe, text_data, text_rva, i)
            if size >= 20:
                spans.append((text_rva + i, size))
                i += size
            else:
                i += 4
        else:
            i += 1
    return spans
def _rva_inside_spans(rva: int, spans: List[Tuple[int, int]]) -> bool:
    return any(lo <= rva < lo + sz for lo, sz in spans)
def discover_crt_data_pointer_slots(pe: 'PE32Image', text_data: bytes,
                                    text_rva: int) -> Set[int]:
    """RVAs in .data holding CRT tail pointer cells (targets of FF 25 thunks)."""
    slots: Set[int] = set()
    if not HAS_CAPSTONE:
        return slots
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    base = pe.image_base
    i = 0
    while i < len(text_data) - 6:
        if text_data[i:i + 2] != b'\xff\x25':
            i += 1
            continue
        rva = text_rva + i
        insns = list(md.disasm(text_data[i:i + 6], base + rva, count=1))
        if not insns or insns[0].mnemonic != 'jmp':
            i += 1
            continue
        absva = struct.unpack_from('<I', text_data, i + 2)[0]
        if absva >= base:
            slot_rva = absva - base
            sec = pe.section_for_rva(slot_rva)
            if sec and not (sec['flags'] & 0x20000000):
                slots.add(slot_rva)
        i += 1
    return slots
