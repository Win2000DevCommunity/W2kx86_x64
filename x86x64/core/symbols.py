"""
Symbols: named locations that relocations resolve against.

A symbol is either *defined* (it names an offset inside a section of some
object) or *absolute* (it names a fixed value that no layout can move).
Import symbols are a special case of defined symbols: the linker materialises
an IAT slot for them and the definition points at that slot.

Nothing in this module knows about final addresses.  Binding a symbol to a
virtual address happens in :mod:`x86x64.core.linker` once section placement is
decided, which is what makes re-layout free.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional

from ..errors import DuplicateSymbolError, UndefinedSymbolError


class SymbolKind(enum.Enum):
    """What a symbol names and how the linker must treat it."""

    #: Offset inside a section; visible only within its own object.
    LOCAL = 'local'
    #: Offset inside a section; visible to every object in the link.
    GLOBAL = 'global'
    #: A fixed value, unaffected by section placement.
    ABSOLUTE = 'absolute'
    #: Resolved to an IAT slot the linker creates for ``dll!name``.
    IMPORT = 'import'
    #: Referenced but not defined here; some other object must define it.
    UNDEFINED = 'undefined'


@dataclass(frozen=True)
class Symbol:
    """
    A named location.

    For ``LOCAL``/``GLOBAL`` symbols, ``section`` names the owning section and
    ``value`` is a byte offset within it.  For ``ABSOLUTE`` symbols ``section``
    is ``None`` and ``value`` is the literal value.  For ``IMPORT`` symbols the
    ``dll`` and ``import_name`` fields identify the thunk to build.
    """

    name: str
    kind: SymbolKind = SymbolKind.GLOBAL
    section: Optional[str] = None
    value: int = 0
    size: int = 0
    #: Only meaningful for ``IMPORT`` symbols.
    dll: str = ''
    import_name: str = ''
    #: Free-form provenance, e.g. the x86 RVA this came from. Never used for
    #: resolution -- purely to make link failures diagnosable.
    origin: Optional[int] = None

    def __post_init__(self) -> None:
        if self.kind in (SymbolKind.LOCAL, SymbolKind.GLOBAL) and not self.section:
            raise ValueError(
                f'{self.kind.value} symbol {self.name!r} must name a section')
        if self.kind is SymbolKind.IMPORT and not (self.dll and self.import_name):
            raise ValueError(
                f'import symbol {self.name!r} needs both dll and import_name')

    @property
    def is_defined(self) -> bool:
        return self.kind is not SymbolKind.UNDEFINED

    @property
    def is_exported(self) -> bool:
        return self.kind in (SymbolKind.GLOBAL, SymbolKind.IMPORT)

    def __str__(self) -> str:
        if self.kind is SymbolKind.ABSOLUTE:
            return f'{self.name}=0x{self.value:x}'
        if self.kind is SymbolKind.IMPORT:
            return f'{self.name}->{self.dll}!{self.import_name}'
        if self.kind is SymbolKind.UNDEFINED:
            return f'{self.name}(undef)'
        return f'{self.name}@{self.section}+0x{self.value:x}'


def import_symbol_name(dll: str, name: str) -> str:
    """Canonical symbol name for an imported function.

    The DLL is lower-cased (Windows import names are case-insensitive at the
    module level) while the function name keeps its case, which matters for
    the export tables we read.
    """
    stem = dll.lower()
    if stem.endswith('.dll'):
        stem = stem[:-4]
    return f'__imp_{stem}!{name}'


class SymbolTable:
    """
    A mutable set of symbols keyed by name.

    Defining the same *global* name twice is an error; re-defining a name with
    an identical symbol is tolerated so that idempotent build passes stay
    cheap.  Undefined entries are placeholders that a later ``define`` can
    fill in.
    """

    __slots__ = ('_syms', '_owner')

    def __init__(self, owner: str = '') -> None:
        self._syms: Dict[str, Symbol] = {}
        self._owner = owner

    # -- construction ----------------------------------------------------
    def define(self, sym: Symbol, *, replace: bool = False) -> Symbol:
        """Add *sym*, raising on a conflicting redefinition."""
        prev = self._syms.get(sym.name)
        if prev is not None and not replace and prev != sym:
            if prev.kind is not SymbolKind.UNDEFINED:
                raise DuplicateSymbolError(sym.name, self._owner, self._owner)
        self._syms[sym.name] = sym
        return sym

    def declare(self, name: str) -> Symbol:
        """Record *name* as referenced-but-not-defined, if it is not known."""
        existing = self._syms.get(name)
        if existing is not None:
            return existing
        return self.define(Symbol(name, SymbolKind.UNDEFINED))

    def absolute(self, name: str, value: int) -> Symbol:
        """Define *name* as a fixed value."""
        return self.define(Symbol(name, SymbolKind.ABSOLUTE, value=value))

    def at(self, name: str, section: str, offset: int,
           kind: SymbolKind = SymbolKind.GLOBAL, **kw) -> Symbol:
        """Define *name* at *offset* inside *section*."""
        return self.define(Symbol(name, kind, section=section, value=offset, **kw))

    # -- lookup ----------------------------------------------------------
    def get(self, name: str) -> Optional[Symbol]:
        return self._syms.get(name)

    def require(self, name: str, referenced_from: str = '') -> Symbol:
        sym = self._syms.get(name)
        if sym is None or not sym.is_defined:
            raise UndefinedSymbolError(name, referenced_from or self._owner)
        return sym

    def __contains__(self, name: object) -> bool:
        return name in self._syms

    def __len__(self) -> int:
        return len(self._syms)

    def __iter__(self) -> Iterator[Symbol]:
        return iter(self._syms.values())

    def names(self) -> Iterable[str]:
        return self._syms.keys()

    def undefined(self) -> List[Symbol]:
        return [s for s in self._syms.values() if not s.is_defined]

    def defined(self) -> List[Symbol]:
        return [s for s in self._syms.values() if s.is_defined]

    def imports(self) -> List[Symbol]:
        return [s for s in self._syms.values() if s.kind is SymbolKind.IMPORT]

    def merge(self, other: 'SymbolTable') -> None:
        """Fold *other* into this table, honouring the duplicate rules."""
        for sym in other:
            if sym.kind is SymbolKind.UNDEFINED:
                self.declare(sym.name)
                continue
            prev = self._syms.get(sym.name)
            if prev is not None and prev.is_defined and prev != sym:
                if prev.kind is SymbolKind.LOCAL or sym.kind is SymbolKind.LOCAL:
                    # Locals never collide across objects; the qualified name
                    # produced by ObjectFile.localize keeps them apart.
                    continue
                raise DuplicateSymbolError(sym.name, self._owner, other._owner)
            self._syms[sym.name] = sym

    def __repr__(self) -> str:
        return f'<SymbolTable {self._owner!r} n={len(self._syms)}>'
