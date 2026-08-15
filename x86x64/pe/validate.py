"""
Structural validation for emitted PE images.

The translator has shipped images the Windows loader silently rejects -- the
``ntdll64.dll`` in this tree declares ``SizeOfOptionalHeader = 368`` while
writing only 240 bytes, so the loader looks for the section table 128 bytes
past where it actually is and reads garbage.  ``ERROR_BAD_EXE_FORMAT`` is all
you get back.

Checking the invariants directly turns that class of failure into a named
problem at build time.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from . import constants as C


@dataclass
class Finding:
    """One problem found in an image."""

    severity: str        # 'error' or 'warning'
    code: str
    message: str

    @property
    def is_error(self) -> bool:
        return self.severity == 'error'

    def __str__(self) -> str:
        return f'[{self.severity}] {self.code}: {self.message}'


@dataclass
class ValidationReport:
    """Everything :func:`validate_pe` found."""

    findings: List[Finding] = field(default_factory=list)

    def add(self, severity: str, code: str, message: str) -> None:
        self.findings.append(Finding(severity, code, message))

    def error(self, code: str, message: str) -> None:
        self.add('error', code, message)

    def warn(self, code: str, message: str) -> None:
        self.add('warning', code, message)

    @property
    def errors(self) -> List[Finding]:
        return [f for f in self.findings if f.is_error]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if not f.is_error]

    @property
    def ok(self) -> bool:
        return not self.errors

    def __bool__(self) -> bool:
        return self.ok

    def __str__(self) -> str:
        if not self.findings:
            return 'PE looks structurally sound'
        return '\n'.join(str(f) for f in self.findings)


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def validate_pe(data: bytes) -> ValidationReport:
    """Check the structural invariants a PE loader relies on."""
    report = ValidationReport()

    if len(data) < 0x40 or data[:2] != C.DOS_SIGNATURE:
        report.error('dos-signature', 'missing MZ signature')
        return report

    pe_off = struct.unpack_from('<I', data, C.PE_OFFSET_FIELD)[0]
    if pe_off == 0 or pe_off + 24 > len(data):
        report.error('e-lfanew',
                     f'e_lfanew 0x{pe_off:x} does not point at a PE header')
        return report
    if data[pe_off:pe_off + 4] != C.PE_SIGNATURE:
        report.error('pe-signature', f'no PE signature at 0x{pe_off:x}')
        return report

    machine, n_sections = struct.unpack_from('<HH', data, pe_off + 4)
    opt_sz = struct.unpack_from('<H', data, pe_off + 20)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from('<H', data, opt_off)[0]

    if magic == C.PE32PLUS_MAGIC:
        expected_opt = C.PE64_OPT_TOTAL
        if machine != C.IMAGE_FILE_MACHINE_AMD64:
            report.warn('machine',
                        f'PE32+ image with machine 0x{machine:04x}')
    elif magic == C.PE32_MAGIC:
        expected_opt = 224
    else:
        report.error('opt-magic', f'unknown optional header magic 0x{magic:04x}')
        return report

    n_dirs = struct.unpack_from('<I', data, opt_off + (108 if magic ==
                                                       C.PE32PLUS_MAGIC else 92))[0]
    computed = expected_opt + (n_dirs - C.NUM_DATA_DIRECTORIES) * 8
    if opt_sz != computed:
        report.error(
            'opt-header-size',
            f'SizeOfOptionalHeader is {opt_sz} but the header holds '
            f'{computed} bytes ({n_dirs} data directories); the loader will '
            f'look for the section table at the wrong offset')

    sec_off = opt_off + opt_sz
    if sec_off + n_sections * C.SECTION_HEADER_SIZE > len(data):
        report.error('section-table',
                     'section table runs past the end of the file')
        return report

    section_align = struct.unpack_from('<I', data, opt_off + 32)[0]
    file_align = struct.unpack_from('<I', data, opt_off + 36)[0]
    size_field = 56 if magic == C.PE32PLUS_MAGIC else 56
    image_size = struct.unpack_from('<I', data, opt_off + size_field)[0]
    headers_size = struct.unpack_from('<I', data, opt_off + 60)[0]

    if section_align and section_align & (section_align - 1):
        report.error('section-align',
                     f'SectionAlignment 0x{section_align:x} is not a power of two')
    if file_align and file_align & (file_align - 1):
        report.error('file-align',
                     f'FileAlignment 0x{file_align:x} is not a power of two')
    if section_align and file_align and file_align > section_align:
        report.error('align-order',
                     'FileAlignment must not exceed SectionAlignment')

    min_headers = sec_off + n_sections * C.SECTION_HEADER_SIZE
    if headers_size < min_headers:
        report.error('headers-size',
                     f'SizeOfHeaders 0x{headers_size:x} does not cover the '
                     f'section table ending at 0x{min_headers:x}')

    seen_names = set()
    spans = []
    for i in range(n_sections):
        sh = sec_off + i * C.SECTION_HEADER_SIZE
        raw_name = data[sh:sh + 8].rstrip(b'\x00')
        vsize, vaddr, rsize, rptr = struct.unpack_from('<IIII', data, sh + 8)
        name = raw_name.decode('latin1', errors='replace')

        if raw_name and not all(32 <= c < 127 for c in raw_name):
            report.error('section-name',
                         f'section {i} name is not printable: {raw_name!r}')
        if name in seen_names:
            report.warn('duplicate-section', f'section name {name!r} appears twice')
        seen_names.add(name)

        if section_align and vaddr % section_align:
            report.error('section-rva',
                         f'{name} RVA 0x{vaddr:x} is not section-aligned')
        if rptr and file_align and rptr % file_align:
            report.error('section-offset',
                         f'{name} file offset 0x{rptr:x} is not file-aligned')
        if rptr and rptr + rsize > len(data):
            report.error('section-data',
                         f'{name} raw data runs past the end of the file')
        if image_size and vaddr + vsize > image_size:
            report.error('section-extent',
                         f'{name} ends at 0x{vaddr + vsize:x}, past '
                         f'SizeOfImage 0x{image_size:x}')
        if vsize:
            spans.append((vaddr, vaddr + vsize, name))

    spans.sort()
    for (a_lo, a_hi, a_name), (b_lo, b_hi, b_name) in zip(spans, spans[1:]):
        if a_hi > b_lo:
            report.error('section-overlap',
                         f'{a_name} [0x{a_lo:x},0x{a_hi:x}) overlaps '
                         f'{b_name} [0x{b_lo:x},0x{b_hi:x})')
        elif section_align:
            # Sections must tile the address space with no hole. The loader
            # maps them one after another and rejects the image outright if
            # the next RVA is past where the previous section ends, rounded
            # up -- ERROR_BAD_EXE_FORMAT, with nothing said about why.
            expected = _align_up(a_hi, section_align)
            if b_lo > expected:
                report.error(
                    'section-gap',
                    f'{a_name} ends at 0x{a_hi:x} (0x{expected:x} aligned) but '
                    f'{b_name} starts at 0x{b_lo:x}, leaving 0x{b_lo - expected:x} '
                    f'bytes unmapped; grow {a_name} VirtualSize to close it')

    entry = struct.unpack_from('<I', data, opt_off + 16)[0]
    if entry and not any(lo <= entry < hi for lo, hi, _ in spans):
        report.error('entry-point',
                     f'entry RVA 0x{entry:x} is not inside any section')

    return report


def validate_file(path: str) -> ValidationReport:
    with open(path, 'rb') as fh:
        return validate_pe(fh.read())
