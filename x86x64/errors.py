"""Exception hierarchy for the x86->x64 translation framework."""

from __future__ import annotations


class X86X64Error(Exception):
    """Base class for every error raised by the framework."""


class PEFormatError(X86X64Error):
    """A PE image is malformed or unsupported."""


class SymbolError(X86X64Error):
    """A symbol is undefined, duplicated, or of the wrong kind."""


class UndefinedSymbolError(SymbolError):
    """A relocation references a symbol that no object defines."""

    def __init__(self, name: str, referenced_from: str = '') -> None:
        self.name = name
        self.referenced_from = referenced_from
        where = f' (referenced from {referenced_from})' if referenced_from else ''
        super().__init__(f'undefined symbol {name!r}{where}')


class DuplicateSymbolError(SymbolError):
    """Two objects define the same global symbol."""

    def __init__(self, name: str, first: str = '', second: str = '') -> None:
        self.name = name
        super().__init__(
            f'duplicate definition of {name!r}'
            + (f' in {first!r} and {second!r}' if first or second else ''))


class RelocationError(X86X64Error):
    """A relocation cannot be encoded at its target address."""


class RelocationRangeError(RelocationError):
    """A relocation value does not fit in the field it must be written to."""

    def __init__(self, kind: str, value: int, site: str = '') -> None:
        self.kind = kind
        self.value = value
        where = f' at {site}' if site else ''
        super().__init__(
            f'{kind} relocation value 0x{value:x} out of range{where}')


class LayoutError(X86X64Error):
    """Sections cannot be laid out (overlap, alignment, or size problem)."""


class SyscallError(X86X64Error):
    """A syscall number or name cannot be resolved."""


class EncodingError(X86X64Error):
    """An instruction could not be encoded."""
