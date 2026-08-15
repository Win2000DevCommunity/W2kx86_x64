"""
Relocations: recorded references to symbols, applied once addresses are known.

The translator used to bake final addresses straight into emitted bytes and
then, whenever a section moved, re-scan the blob for ``movabs`` byte patterns
and add the delta.  That scan cannot tell an address from a constant, cannot
tell code from embedded data, and is not idempotent -- it is the source of the
"shifted pointer" corruption class.

Here a reference is *recorded* instead: site offset, field kind, target symbol,
addend.  Applying is a pure function of (pristine bytes, symbol addresses), so
moving a section is just "lay out again and re-apply" with no scanning and no
double-patching.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from ..errors import RelocationRangeError

INT32_MIN, INT32_MAX = -0x8000_0000, 0x7FFF_FFFF
UINT32_MAX = 0xFFFF_FFFF
UINT64_MAX = 0xFFFF_FFFF_FFFF_FFFF


class RelocKind(enum.Enum):
    """
    How a resolved symbol value is written into the instruction stream.

    ``width`` is the field size in bytes, ``pc_relative`` says the value is
    computed against the end of the field, and ``needs_base_reloc`` marks the
    kinds that must also appear in the PE base-relocation directory so the
    loader can rebase the image.
    """

    #: 64-bit absolute VA -- ``movabs reg, imm64`` and qword pointer slots.
    ABS64 = 'abs64'
    #: 32-bit absolute VA -- legacy pointer slots kept 4 bytes wide.
    ABS32 = 'abs32'
    #: 32-bit RVA (VA minus image base) -- PE directories, scope tables.
    RVA32 = 'rva32'
    #: 32-bit PC-relative displacement -- ``call``/``jmp rel32``, RIP-relative
    #: memory operands.
    REL32 = 'rel32'
    #: 8-bit PC-relative displacement -- short ``jcc``/``jmp``.
    REL8 = 'rel8'
    #: Offset of the target from the start of its own section.
    SECREL32 = 'secrel32'
    #: 1-based index of the target's section (PE ``SECTION`` fixup).
    SECTION16 = 'section16'

    @property
    def width(self) -> int:
        return _KIND_WIDTH[self]

    @property
    def pc_relative(self) -> bool:
        return self in (RelocKind.REL32, RelocKind.REL8)

    @property
    def needs_base_reloc(self) -> bool:
        """True when the PE loader must fix this field up on rebase."""
        return self in (RelocKind.ABS64, RelocKind.ABS32)


_KIND_WIDTH: Dict[RelocKind, int] = {
    RelocKind.ABS64: 8,
    RelocKind.ABS32: 4,
    RelocKind.RVA32: 4,
    RelocKind.REL32: 4,
    RelocKind.REL8: 1,
    RelocKind.SECREL32: 4,
    RelocKind.SECTION16: 2,
}


@dataclass(frozen=True)
class Relocation:
    """
    A single reference from a section's bytes to a symbol.

    ``offset`` is relative to the start of the owning section's data.  The
    value written is ``resolve(symbol) + addend``, transformed per ``kind``.
    ``pcrel_adjust`` handles instructions where the field does not end the
    instruction: for ``mov dword [rip+disp32], imm32`` the displacement is
    followed by 4 more bytes, so ``pcrel_adjust=4``.
    """

    offset: int
    kind: RelocKind
    symbol: str
    addend: int = 0
    pcrel_adjust: int = 0
    #: Diagnostic only -- the x86 RVA this reference was translated from.
    origin: Optional[int] = None

    @property
    def end(self) -> int:
        """Offset one past the last byte this relocation writes."""
        return self.offset + self.kind.width

    def __str__(self) -> str:
        sign = '+' if self.addend >= 0 else '-'
        return (f'{self.kind.value}@0x{self.offset:x} -> {self.symbol}'
                f'{sign}0x{abs(self.addend):x}')


def compute_value(reloc: Relocation, target_va: int, *, site_va: int,
                  image_base: int, section_base: int = 0,
                  section_index: int = 0) -> int:
    """
    Turn a resolved target address into the raw field value for *reloc*.

    ``site_va`` is the virtual address of the relocation field itself, which
    is what PC-relative kinds are measured from.
    """
    kind = reloc.kind
    value = target_va + reloc.addend

    if kind is RelocKind.RVA32:
        return value - image_base
    if kind is RelocKind.SECREL32:
        return value - section_base
    if kind is RelocKind.SECTION16:
        return section_index
    if kind.pc_relative:
        return value - (site_va + kind.width + reloc.pcrel_adjust)
    return value


def encode_value(kind: RelocKind, value: int, *, site: str = '') -> bytes:
    """Pack *value* into *kind*'s field, rejecting anything that will not fit."""
    if kind is RelocKind.ABS64:
        if not 0 <= value <= UINT64_MAX:
            raise RelocationRangeError(kind.value, value, site)
        return struct.pack('<Q', value)
    if kind in (RelocKind.ABS32, RelocKind.RVA32, RelocKind.SECREL32):
        if not 0 <= value <= UINT32_MAX:
            raise RelocationRangeError(kind.value, value, site)
        return struct.pack('<I', value)
    if kind is RelocKind.REL32:
        if not INT32_MIN <= value <= INT32_MAX:
            raise RelocationRangeError(kind.value, value, site)
        return struct.pack('<i', value)
    if kind is RelocKind.REL8:
        if not -128 <= value <= 127:
            raise RelocationRangeError(kind.value, value, site)
        return struct.pack('<b', value)
    if kind is RelocKind.SECTION16:
        if not 0 <= value <= 0xFFFF:
            raise RelocationRangeError(kind.value, value, site)
        return struct.pack('<H', value)
    raise AssertionError(f'unhandled relocation kind {kind!r}')


def apply_relocation(data: bytearray, reloc: Relocation, target_va: int, *,
                     site_va: int, image_base: int, section_base: int = 0,
                     section_index: int = 0, site: str = '') -> int:
    """
    Write *reloc* into *data* in place and return the encoded value.

    *data* must be the section's byte buffer; ``reloc.offset`` indexes into it.
    """
    if reloc.offset < 0 or reloc.end > len(data):
        raise RelocationRangeError(
            reloc.kind.value, reloc.offset,
            site or f'offset 0x{reloc.offset:x} outside {len(data)}-byte section')
    value = compute_value(reloc, target_va, site_va=site_va,
                          image_base=image_base, section_base=section_base,
                          section_index=section_index)
    data[reloc.offset:reloc.end] = encode_value(reloc.kind, value, site=site)
    return value


#: PE base-relocation type codes, indexed by the kinds that need them.
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

_BASE_RELOC_TYPE: Dict[RelocKind, int] = {
    RelocKind.ABS64: IMAGE_REL_BASED_DIR64,
    RelocKind.ABS32: IMAGE_REL_BASED_HIGHLOW,
}


def base_reloc_type(kind: RelocKind) -> Optional[int]:
    """PE ``IMAGE_REL_BASED_*`` code for *kind*, or ``None`` if not needed."""
    return _BASE_RELOC_TYPE.get(kind)
