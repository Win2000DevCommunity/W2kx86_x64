"""
The syscall table: Win2000 SSDT indices and their Win10 x64 counterparts.

The legacy translator kept this state in four module-level dictionaries plus a
global target string, so two translations could not run with different targets
and tests had to mutate globals to set up.  Here a :class:`SyscallTable`
instance owns everything; :func:`default_table` provides the shared one for
callers that do not care.
"""

from __future__ import annotations

import enum
import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from ..errors import SyscallError
from .table_data import WIN2000_SYSCALL_TABLE


class SyscallTarget(enum.Enum):
    """Which numbering scheme translated stubs should load into ``eax``."""

    #: Keep the NT 5.0 index -- for running against our own x64 NT 5.0 kernel.
    WIN2000 = 'win2000'
    #: Map by ``Nt*`` name to the published Win10 x64 index -- for shimming on
    #: a stock modern Windows.
    WIN10 = 'win10'

    @classmethod
    def parse(cls, value: 'str | SyscallTarget') -> 'SyscallTarget':
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError:
            raise SyscallError(
                f"syscall target must be 'win2000' or 'win10', got {value!r}"
            ) from None


@dataclass(frozen=True)
class SyscallEntry:
    """One system service, as seen from both numbering schemes."""

    win2000_nr: int
    win10_nr: int
    n_args: int
    name: str

    @property
    def is_alias(self) -> bool:
        """``Zw*`` names are aliases of the matching ``Nt*`` service."""
        return self.name.startswith('Zw')

    @property
    def nt_name(self) -> str:
        """The ``Nt*`` spelling of this service."""
        return 'Nt' + self.name[2:] if self.is_alias else self.name

    @property
    def has_win10_mapping(self) -> bool:
        return self.win10_nr != 0

    @property
    def stack_bytes(self) -> int:
        """Bytes the 32-bit stub pops on return (``ret n``)."""
        return self.n_args * 4

    def number_for(self, target: SyscallTarget) -> int:
        return (self.win2000_nr if target is SyscallTarget.WIN2000
                else self.win10_nr)

    def __str__(self) -> str:
        return (f'{self.name}(w2k=0x{self.win2000_nr:04X}, '
                f'w10=0x{self.win10_nr:04X}, args={self.n_args})')


class SyscallTable:
    """
    Name and number lookups over the Win2000 SSDT.

    The instance is mutable: :meth:`apply_win10_map` and
    :meth:`load_from_ntdll` refine it from external data, which is how the
    Win10 numbers get refreshed for a specific build.
    """

    def __init__(self, entries: Iterable[Tuple[int, int, int, str]] = (),
                 *, target: 'str | SyscallTarget' = SyscallTarget.WIN2000) -> None:
        self._by_nr: Dict[int, SyscallEntry] = {}
        self._by_name: Dict[str, SyscallEntry] = {}
        #: Names present in the loaded Win10 reference data, used to tell
        #: "no mapping known" apart from "genuinely removed in Win10".
        self._win10_known: set[str] = set()
        self.target = SyscallTarget.parse(target)
        for row in entries or WIN2000_SYSCALL_TABLE:
            self.add(SyscallEntry(*row))

    # -- population ------------------------------------------------------
    def add(self, entry: SyscallEntry) -> SyscallEntry:
        self._by_nr.setdefault(entry.win2000_nr, entry)
        self._by_name[entry.name] = entry
        return entry

    def replace(self, entry: SyscallEntry) -> SyscallEntry:
        self._by_nr[entry.win2000_nr] = entry
        self._by_name[entry.name] = entry
        return entry

    # -- lookup ----------------------------------------------------------
    def by_name(self, name: str) -> Optional[SyscallEntry]:
        entry = self._by_name.get(name)
        if entry is None and name.startswith('Zw'):
            entry = self._by_name.get('Nt' + name[2:])
        return entry

    def by_number(self, win2000_nr: int) -> Optional[SyscallEntry]:
        return self._by_nr.get(win2000_nr)

    def require(self, name: str) -> SyscallEntry:
        entry = self.by_name(name)
        if entry is None:
            raise SyscallError(f'unknown system service {name!r}')
        return entry

    def __contains__(self, name: object) -> bool:
        return self.by_name(str(name)) is not None

    def __len__(self) -> int:
        return len(self._by_name)

    def __iter__(self) -> Iterator[SyscallEntry]:
        return iter(sorted(self._by_name.values(), key=lambda e: e.win2000_nr))

    def services(self, *, include_aliases: bool = False) -> List[SyscallEntry]:
        """Unique services, ``Nt*`` only unless *include_aliases*."""
        return [e for e in self if include_aliases or not e.is_alias]

    # -- resolution ------------------------------------------------------
    def resolve(self, name: str, win2000_nr: Optional[int] = None,
                *, target: Optional[SyscallTarget] = None) -> int:
        """
        The number a translated stub must load into ``eax``.

        Falls back to *win2000_nr* when the name is unknown, which keeps stubs
        harvested from an ntdll we have no table row for translatable.
        """
        tgt = target or self.target
        if tgt is SyscallTarget.WIN2000:
            if win2000_nr is not None:
                return win2000_nr
            entry = self.by_name(name)
            return entry.win2000_nr if entry else 0

        entry = self.by_name(name)
        if entry is not None and entry.win10_nr:
            return entry.win10_nr
        return 0

    def is_mappable(self, name: str) -> bool:
        """True when *name* has a usable number for the active target."""
        if self.target is SyscallTarget.WIN2000:
            return True
        entry = self.by_name(name)
        return bool(entry and entry.win10_nr)

    # -- external data ---------------------------------------------------
    def apply_win10_map(self, by_name: Mapping[str, int]) -> int:
        """
        Overlay published Win10 x64 numbers, returning how many rows changed.

        ``Zw*`` rows follow their ``Nt*`` sibling, matching how ntdll aliases
        the two spellings onto one service.
        """
        self._win10_known.update(by_name.keys())
        changed = 0
        for entry in list(self._by_name.values()):
            new_nr = by_name.get(entry.name)
            if new_nr is None and entry.is_alias:
                new_nr = by_name.get(entry.nt_name)
            if new_nr is None or new_nr == entry.win10_nr:
                continue
            self.replace(SyscallEntry(entry.win2000_nr, int(new_nr),
                                      entry.n_args, entry.name))
            changed += 1
        return changed

    def load_win10_json(self, path: str) -> int:
        """Apply a ``{"NtName": number}`` JSON map from *path*."""
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        return self.apply_win10_map({k: int(v) for k, v in data.items()})

    def autoload_win10(self, search: Sequence[str] = ()) -> int:
        """Apply the first ``win10_x64_syscalls.json`` found on *search*."""
        candidates = list(search) or [
            os.path.join(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))),
                'win10_x64_syscalls.json'),
            os.path.join(os.getcwd(), 'win10_x64_syscalls.json'),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return self.load_win10_json(path)
        return 0

    def load_from_stubs(self, stubs: Iterable['StubInfo']) -> int:  # noqa: F821
        """Refresh Win2000 numbers from stubs decoded out of a real ntdll."""
        updated = 0
        for stub in stubs:
            if stub.name.startswith('Zw'):
                continue
            prev = self.by_name(stub.name)
            win10 = prev.win10_nr if prev else 0
            self.replace(SyscallEntry(stub.win2000_nr, win10,
                                      stub.n_args, stub.name))
            updated += 1
        return updated

    # -- reporting -------------------------------------------------------
    def coverage(self) -> Tuple[int, int, List[str]]:
        """``(mapped, total, unmapped_names)`` for the active target."""
        services = self.services()
        if self.target is SyscallTarget.WIN2000:
            return len(services), len(services), []
        unmapped = [e.name for e in services if not e.win10_nr]
        return len(services) - len(unmapped), len(services), sorted(unmapped)

    def to_rows(self) -> List[Dict[str, object]]:
        """JSON-ready rows describing the table under the active target."""
        return [{
            'name': e.name,
            'win2000_nr': e.win2000_nr,
            'x64_nr': self.resolve(e.name, e.win2000_nr),
            'n_args': e.n_args,
            'target': self.target.value,
        } for e in self.services()]

    def export_json(self, path: str) -> int:
        rows = self.to_rows()
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(rows, fh, indent=2)
        return len(rows)

    def __repr__(self) -> str:
        return (f'<SyscallTable target={self.target.value} '
                f'services={len(self.services())}>')


_DEFAULT: Optional[SyscallTable] = None


def default_table() -> SyscallTable:
    """The process-wide table, built on first use."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = SyscallTable()
    return _DEFAULT


def reset_default_table() -> SyscallTable:
    """Drop the shared table so a test starts from pristine data."""
    global _DEFAULT
    _DEFAULT = SyscallTable()
    return _DEFAULT
