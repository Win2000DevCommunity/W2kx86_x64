"""
x86x64 -- Windows 2000 x86 (PE32) to x64 (PE64) binary translation framework.

The pipeline is split so each stage can be tested on its own:

``x86x64.core``
    Relocatable objects, symbols, relocations, and the linker.  Emitters never
    write a final address; they record a relocation and let the linker place
    it.  This is what makes growing or rebasing the image safe.
``x86x64.pe``
    PE32 reading and PE64 writing.
``x86x64.syscall``
    The Win2000 SSDT, Win10 x64 number mapping, and ntdll stub translation.
``x86x64.abi``
    TEB ``fs:`` to ``gs:`` remapping and stdcall/cdecl to Microsoft x64.
``x86x64.encoding``
    Raw x64 instruction encoders used by every emitter.
``x86x64.dispatch``
    Import (IAT) dispatch and thunk construction.
``x86x64.kernel``
    Ring-0 surface: SSDT layout and kernel-side service descriptors.
"""

from __future__ import annotations

__version__ = '0.1.0'

from . import errors
from .errors import (
    DuplicateSymbolError,
    EncodingError,
    LayoutError,
    PEFormatError,
    RelocationError,
    RelocationRangeError,
    SymbolError,
    SyscallError,
    UndefinedSymbolError,
    X86X64Error,
)

__all__ = [
    '__version__', 'errors',
    'X86X64Error', 'PEFormatError', 'SymbolError', 'UndefinedSymbolError',
    'DuplicateSymbolError', 'RelocationError', 'RelocationRangeError',
    'LayoutError', 'SyscallError', 'EncodingError',
]
