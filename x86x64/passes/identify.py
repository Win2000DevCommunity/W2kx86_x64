"""
Working out what an image is, from the image.

A universal translator cannot key off filenames: ``ntdll.dll`` under another
name is still a native DLL, and a renamed driver is still ring 0. Everything
here is derived from headers and exports, so the same file always classifies
the same way and :class:`ImageIdentity` is a stable key for quirks.
"""

from __future__ import annotations

import pathlib
import struct
from typing import Optional, Sequence, Tuple, Union

from x86x64.pe import pe32 as pe32mod
from x86x64.pipeline import ImageIdentity, ImageKind, SourceImage, TargetSpec

#: The native API layer exports each system service twice, as ``Nt*`` and
#: ``Zw*``. Nothing else does, which makes it a far better marker than the
#: subsystem field: Win2000's own ntdll.dll reports subsystem 3 (console),
#: not 1 (native), so classifying on the header alone gets it wrong.
NATIVE_STUB_PREFIXES = ('Nt', 'Zw')
NATIVE_STUB_THRESHOLD = 8

#: Exports that only the kernel and HAL provide.
KERNEL_EXPORT_MARKERS = frozenset({
    'KeBugCheck', 'KeBugCheckEx', 'IoCreateDevice', 'MmGetSystemRoutineAddress',
    'ExAllocatePool', 'ExAllocatePoolWithTag', 'KeInitializeDpc',
    'HalGetInterruptVector', 'KeStallExecutionProcessor',
})

#: Imports that mark a ring 0 module compiled against the kernel.
KERNEL_IMPORT_MARKERS = frozenset({'ntoskrnl.exe', 'hal.dll', 'ndis.sys'})

IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_FILE_DLL = 0x2000


def classify(image: 'pe32mod.PE32Image', exports: Sequence[str],
             imports: Sequence[str]) -> ImageKind:
    """Decide what kind of image this is.

    Ordered most specific first: the kernel exports routines nothing else
    does, a driver imports the kernel, and the native layer exports paired
    ``Nt``/``Zw`` syscall stubs.
    """
    exported = set(exports)
    imported = {d.lower() for d in imports}
    is_dll = image.is_dll

    if exported & KERNEL_EXPORT_MARKERS:
        return ImageKind.KERNEL
    if imported & KERNEL_IMPORT_MARKERS:
        return ImageKind.DRIVER

    nt_stubs = sum(1 for n in exported if n.startswith('Nt'))
    zw_stubs = sum(1 for n in exported if n.startswith('Zw'))
    if min(nt_stubs, zw_stubs) >= NATIVE_STUB_THRESHOLD:
        return ImageKind.NATIVE_DLL

    if image.subsystem == IMAGE_SUBSYSTEM_NATIVE:
        return ImageKind.NATIVE_DLL if is_dll else ImageKind.DRIVER
    return ImageKind.DLL if is_dll else ImageKind.EXECUTABLE


def _linker_version(data: bytes, pe_off: int) -> Tuple[int, int]:
    """MajorLinkerVersion/MinorLinkerVersion, two bytes into the optional header."""
    opt = pe_off + 24
    if opt + 2 > len(data):
        return (0, 0)
    return (data[opt + 2], data[opt + 3])


def _timestamp(data: bytes, pe_off: int) -> int:
    off = pe_off + 8
    if off + 4 > len(data):
        return 0
    return struct.unpack_from('<I', data, off)[0]


def _machine(data: bytes, pe_off: int) -> int:
    off = pe_off + 4
    if off + 2 > len(data):
        return 0
    return struct.unpack_from('<H', data, off)[0]


def identify(data: bytes, name: str = '') -> ImageIdentity:
    """Build the identity a quirk matcher keys off."""
    image = pe32mod.PE32Image(data)
    try:
        exports = [e['name'] for e in image.parse_exports() if e.get('name')]
    except Exception:
        exports = []
    try:
        imports = [d['dll'] for d in image.parse_imports() if d.get('dll')]
    except Exception:
        imports = []

    return ImageIdentity.from_bytes(
        data,
        kind=classify(image, exports, imports),
        name=name,
        machine=_machine(data, image.pe_off),
        timestamp=_timestamp(data, image.pe_off),
        linker_version=_linker_version(data, image.pe_off),
        exports=exports,
        imports=imports,
    )


def load_source(source: Union[str, pathlib.Path, bytes],
                name: str = '') -> SourceImage:
    """Read an image and classify it, ready to build a context around."""
    if isinstance(source, (str, pathlib.Path)):
        path = pathlib.Path(source)
        data = path.read_bytes()
        name = name or path.name
        return SourceImage(data=data, identity=identify(data, name),
                           path=str(path))
    return SourceImage(data=bytes(source),
                       identity=identify(bytes(source), name))


def target_for(source: SourceImage,
               base: Optional[TargetSpec] = None) -> TargetSpec:
    """Pick sensible output settings for what the input turned out to be."""
    spec = base or TargetSpec()
    if source.kind.is_ring0:
        return spec.for_kernel()
    if source.kind is ImageKind.NATIVE_DLL:
        return TargetSpec(**{**spec.__dict__, 'subsystem': IMAGE_SUBSYSTEM_NATIVE})
    return spec
