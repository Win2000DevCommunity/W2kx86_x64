"""
Decoding Win2000 ntdll syscall stubs and re-emitting them for x64.

A Win2000 SP4 stub is a fixed 16-byte shape::

    B8 nr nr nr nr    mov  eax, <ssdt index>
    8D 54 24 04       lea  edx, [esp+4]        ; or 8B D4  mov edx, esp
    CD 2E             int  0x2e                ; or 0F 34  sysenter
    C2 nn nn          ret  <n>                 ; or C3     ret

The x64 replacement is the shape real Windows uses::

    4C 8B D1          mov  r10, rcx
    B8 nr nr nr nr    mov  eax, <index>
    0F 05             syscall
    C3                ret

``mov r10, rcx`` is not optional.  ``syscall`` writes the return address into
RCX, so the first argument has to be parked in R10 first; the kernel dispatcher
reads argument one from R10.  Emitting the stub without it -- as the legacy
translator did -- corrupts the first argument of every system call.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from ..errors import SyscallError
from .table import SyscallTable, SyscallTarget, default_table

# -- x86 stub shapes ------------------------------------------------------
MOV_EAX_IMM32 = 0xB8
LEA_EDX_ESP4 = b'\x8d\x54\x24\x04'
MOV_EDX_ESP = b'\x8b\xd4'
INT_2E = b'\xcd\x2e'
SYSENTER = b'\x0f\x34'
RET_IMM16 = 0xC2
RET_NEAR = 0xC3
STUB_SIZE = 16

# -- x64 replacement bytes ------------------------------------------------
X64_MOV_R10_RCX = b'\x4c\x8b\xd1'
X64_SYSCALL = b'\x0f\x05'
X64_RET = b'\xc3'
X64_INT3 = b'\xcc'


class StubMechanism:
    """How the 32-bit stub entered the kernel."""

    INT2E = 'INT2E'
    SYSENTER = 'SYSENTER'


@dataclass(frozen=True)
class StubInfo:
    """A decoded Win2000 ntdll syscall stub."""

    rva: int
    name: str
    win2000_nr: int
    n_args: int
    ret_pop: int
    mechanism: str = StubMechanism.INT2E
    raw: bytes = b''
    #: Filled in by the translator for the active target.
    x64_nr: int = 0

    @property
    def is_alias(self) -> bool:
        return self.name.startswith('Zw')

    def with_number(self, x64_nr: int) -> 'StubInfo':
        return StubInfo(self.rva, self.name, self.win2000_nr, self.n_args,
                        self.ret_pop, self.mechanism, self.raw, x64_nr)

    def __str__(self) -> str:
        return (f'{self.name}@0x{self.rva:X} w2k=0x{self.win2000_nr:04X} '
                f'args={self.n_args} {self.mechanism}')


def decode_stub(data: bytes, *, name: str = '', rva: int = 0) -> Optional[StubInfo]:
    """
    Decode one stub from *data*, or return ``None`` if it is not a stub.

    Exports such as ``NtCurrentTeb`` share the ``Nt`` prefix but are ordinary
    functions, so a caller filtering purely on name relies on this returning
    ``None`` for them.
    """
    if len(data) < 12 or data[0] != MOV_EAX_IMM32:
        return None
    win2000_nr = struct.unpack_from('<I', data, 1)[0]

    if data[5:9] == LEA_EDX_ESP4:
        body_off = 9
    elif data[5:7] == MOV_EDX_ESP:
        body_off = 7
    else:
        return None

    body = data[body_off:body_off + 2]
    if body == INT_2E:
        mechanism = StubMechanism.INT2E
    elif body == SYSENTER:
        mechanism = StubMechanism.SYSENTER
    else:
        return None

    tail = data[body_off + 2:]
    if tail[:1] == bytes([RET_IMM16]) and len(tail) >= 3:
        ret_pop = struct.unpack_from('<H', tail, 1)[0]
    else:
        ret_pop = 0

    return StubInfo(rva=rva, name=name, win2000_nr=win2000_nr,
                    n_args=ret_pop // 4, ret_pop=ret_pop,
                    mechanism=mechanism, raw=bytes(data[:STUB_SIZE]))


def extract_stubs(pe, *, table: Optional[SyscallTable] = None) -> List[StubInfo]:
    """
    Decode every syscall stub exported by an ntdll :class:`PE32Image`.

    Results are sorted by SSDT index, which is the order the kernel's service
    table uses.
    """
    tbl = table or default_table()
    stubs: List[StubInfo] = []

    for exp in pe.parse_exports():
        name = exp.get('name') or ''
        if not (name.startswith('Nt') or name.startswith('Zw')):
            continue
        offset = pe.rva_to_offset(exp['rva'])
        if offset is None:
            continue
        stub = decode_stub(pe.raw[offset:offset + STUB_SIZE],
                           name=name, rva=exp['rva'])
        if stub is None:
            continue
        stubs.append(stub.with_number(tbl.resolve(name, stub.win2000_nr)))

    stubs.sort(key=lambda s: (s.win2000_nr, s.name))
    return stubs


def emit_x64_stub(number: int, *, tail_ret: bool = True) -> bytes:
    """Assemble the four-instruction x64 syscall stub for *number*."""
    if not 0 <= number <= 0xFFFF_FFFF:
        raise SyscallError(f'syscall number 0x{number:x} does not fit in eax')
    blob = X64_MOV_R10_RCX + bytes([MOV_EAX_IMM32]) + struct.pack('<I', number)
    blob += X64_SYSCALL
    return blob + X64_RET if tail_ret else blob


def emit_unmapped_stub() -> bytes:
    """Body for a service with no equivalent on the target: trap, then return."""
    return X64_INT3 + X64_RET


@dataclass
class StubTranslation:
    """Result of translating one stub, including why it may have been stubbed out."""

    stub: StubInfo
    code: bytes
    number: int
    mapped: bool
    note: str = ''

    @property
    def name(self) -> str:
        return self.stub.name


def translate_stub(stub: StubInfo, *,
                   table: Optional[SyscallTable] = None) -> StubTranslation:
    """
    Turn a decoded 32-bit stub into its x64 body.

    Under the ``win10`` target a service with no published number becomes
    ``int3; ret`` so that hitting it is an obvious, debuggable trap rather
    than a wild jump into the kernel with a bogus index.
    """
    tbl = table or default_table()
    number = tbl.resolve(stub.name, stub.win2000_nr)

    if tbl.target is SyscallTarget.WIN10 and not number:
        return StubTranslation(
            stub, emit_unmapped_stub(), 0, False,
            f'{stub.name} (Win2000=0x{stub.win2000_nr:04X}) has no Win10 x64 '
            f'equivalent')

    return StubTranslation(stub, emit_x64_stub(number), number, True)


def translate_stubs(stubs: Sequence[StubInfo], *,
                    table: Optional[SyscallTable] = None) -> List[StubTranslation]:
    return [translate_stub(s, table=table) for s in stubs]
