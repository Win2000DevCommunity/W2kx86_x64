"""Section-level fixups applied while moving a PE32 image to PE64 addresses.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403
from x86x64.analysis.discover import (
    discover_static_pointers,
    _plausible_image_pointer,
)


def fixup_rsrc_section(data: bytes, old_sec_rva: int, new_sec_rva: int) -> bytes:
    """Rebase leaf ``IMAGE_RESOURCE_DATA_ENTRY`` RVAs when .rsrc moves."""
    if old_sec_rva == new_sec_rva or not data:
        return data
    delta = new_sec_rva - old_sec_rva
    buf = bytearray(data)
    old_end = old_sec_rva + len(data)

    def walk(dir_off: int) -> None:
        if dir_off + 16 > len(buf):
            return
        num_named, num_id = struct.unpack_from('<HH', buf, dir_off + 12)
        ent_off = dir_off + 16
        for i in range(num_named + num_id):
            off = ent_off + i * 8
            if off + 8 > len(buf):
                return
            _name_or_id, entry_off = struct.unpack_from('<II', buf, off)
            if entry_off & 0x80000000:
                walk(entry_off & 0x7FFFFFFF)
            else:
                if entry_off + 4 > len(buf):
                    return
                leaf_rva = struct.unpack_from('<I', buf, entry_off)[0]
                if old_sec_rva <= leaf_rva < old_end:
                    struct.pack_into('<I', buf, entry_off, leaf_rva + delta)

    walk(0)
    return bytes(buf)
def fixup_data_section(data: bytes, section_rva: int,
                       relocs: List[Tuple[int, int]],
                       old_base: int, new_base: int, image_size: int,
                       pointer_sites: Set[int],
                       dyn_writes: Dict[int, int],
                       pe: Optional['PE32Image'] = None,
                       old_to_new_section: Optional[Dict[int, int]] = None,
                       iat_rva_map: Optional[Dict[int, int]] = None,
                       final_rva_map: Optional[Dict[int, int]] = None) -> bytes:
    """
    Apply base relocations and patch known pointer slots for PE64 rebasing.

    For each HIGHLOW reloc (or discovered pointer site), update the DWORD to
    point at the same relative offset under new_base.  Dynamic write sites
    discovered by Unicorn take precedence.
    """
    buf = bytearray(data)
    img_end = old_base + image_size
    delta = new_base - old_base

    def _relocate_va(va: int) -> int:
        if pe and (old_to_new_section or iat_rva_map):
            return remap_image_va(va, pe, old_base, new_base,
                                  old_to_new_section or {}, iat_rva_map,
                                  final_rva_map)
        if old_base <= va < img_end:
            return new_base + (va - old_base)
        return va

    # Standard PE base relocations (HIGHLOW)
    for rva, rtype in relocs:
        if rtype != IMAGE_REL_BASED_HIGHLOW:
            continue
        if not (section_rva <= rva < section_rva + len(buf)):
            continue
        off = rva - section_rva
        if off + 4 > len(buf):
            continue
        val = struct.unpack_from('<I', buf, off)[0]
        struct.pack_into('<I', buf, off, (_relocate_va(val) & 0xFFFFFFFF))

    # Heuristic static pointer scan
    for rva in discover_static_pointers(bytes(buf), section_rva, old_base, image_size):
        pointer_sites.add(rva)

    # Dynamic Unicorn write sites override (keys are absolute VAs)
    for site_va, value in dyn_writes.items():
        site_rva = site_va - old_base if site_va >= old_base else site_va
        if not (section_rva <= site_rva < section_rva + len(buf)):
            continue
        off = site_rva - section_rva
        if off + 4 > len(buf):
            continue
        struct.pack_into('<I', buf, off, (_relocate_va(value) & 0xFFFFFFFF))

    # Explicit pointer sites (relocs + static + dynamic keys).
    # Sort for determinism; skip slots already covered by a prior QWORD widen
    # so packed adjacent DWORD pointers are not clobbered.
    covered: Set[int] = set()
    for rva in sorted(pointer_sites):
        if rva in covered:
            continue
        if not (section_rva <= rva < section_rva + len(buf)):
            continue
        off = rva - section_rva
        if off + 4 > len(buf):
            continue
        val = struct.unpack_from('<I', buf, off)[0]
        if not _plausible_image_pointer(val, old_base, image_size):
            continue
        new_val = _relocate_va(val if val >= old_base else old_base + val)
        # Widen DWORD→QWORD only when the high half is clear padding and is
        # not itself another pointer site.  Blind QWORD writes destroy packed
        # adjacent pointers (and small-integer false positives used to wipe
        # neighbours entirely — cmd .data+0x8d8 cmdline slot).
        hi = struct.unpack_from('<I', buf, off + 4)[0] if off + 8 <= len(buf) else None
        can_widen = (
            hi == 0
            and (rva + 4) not in pointer_sites
            and off + 8 <= len(buf)
        )
        if can_widen:
            struct.pack_into('<Q', buf, off, new_val & 0xFFFFFFFFFFFFFFFF)
            covered.add(rva + 4)
        else:
            struct.pack_into('<I', buf, off, new_val & 0xFFFFFFFF)

    return bytes(buf)
def remap_section_rva(old_rva: int, pe: 'PE32Image',
                      old_to_new_section: Dict[int, int]) -> int:
    """Map an x86 image RVA to its PE64 section-placed RVA."""
    for sec in pe.sections:
        old_va = sec['vaddr']
        size = max(sec['vsize'], sec['raw_sz'], 1)
        if old_va <= old_rva < old_va + size:
            new_va = old_to_new_section.get(old_va, old_va)
            return new_va + (old_rva - old_va)
    return old_rva
def remap_image_va(va: int, pe: 'PE32Image', old_base: int, new_base: int,
                   old_to_new_section: Dict[int, int],
                   iat_rva_map: Optional[Dict[int, int]] = None,
                   final_rva_map: Optional[Dict[int, int]] = None) -> int:
    """Remap a 32-bit image VA to the final PE64 VA (IAT + moved sections + code)."""
    img_end = old_base + pe.image_size
    if old_base <= va < img_end:
        old_rva = va - old_base
    elif new_base <= va < new_base + pe.image_size:
        old_rva = va - new_base
    else:
        return va
    if iat_rva_map and old_rva in iat_rva_map:
        return new_base + iat_rva_map[old_rva]
    # IAT thunk slots live in .text; function-driven layout remaps them as code.
    if iat_rva_map and final_rva_map:
        for old_iat, code_rva in final_rva_map.items():
            if old_rva == code_rva and old_iat in iat_rva_map:
                return new_base + iat_rva_map[old_iat]
    # .data/.rsrc must win over code rva_map when the PE64 .text section has
    # grown to cover the old x86 RVA (cmd.exe: unpatch 0x80044c58 lands in blob).
    sec = pe.section_for_rva(old_rva)
    if (sec and not (sec['flags'] & 0x20000000) and old_to_new_section):
        return new_base + remap_section_rva(old_rva, pe, old_to_new_section)
    if final_rva_map and old_rva in final_rva_map:
        return new_base + final_rva_map[old_rva]
    # Code VAs often appear in .data as mid-function / label pointers that
    # were never exact rva_map keys.  Floor-map through the nearest prior
    # translated RVA (same as ``_code_rva_to_pe64_va``) so dispatch tables
    # do not keep ``new_base+old_rva`` identity into the expanded blob.
    if final_rva_map and sec and (sec['flags'] & 0x20000000):
        sec_lo = sec['vaddr']
        sec_hi = sec_lo + max(sec.get('vsize', 0), sec.get('raw_sz', 0), 1)
        candidates = [r for r in final_rva_map
                      if sec_lo <= r <= old_rva < sec_hi]
        if candidates:
            best = max(candidates)
            # Reject absurd gaps (different mega-chunk / rematerialized island).
            if old_rva - best <= 0x200:
                return new_base + final_rva_map[best] + (old_rva - best)
    if old_to_new_section:
        return new_base + remap_section_rva(old_rva, pe, old_to_new_section)
    return new_base + old_rva
