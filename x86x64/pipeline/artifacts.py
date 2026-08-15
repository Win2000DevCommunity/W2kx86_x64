"""
The store that passes exchange data through.

The legacy translator kept everything on one object, so any pass could read or
write any field and nothing recorded that it had. Measuring it showed 52 of 69
fields touched by more than one module, which is why no pass could be tested or
replaced alone.

Here a pass sees only the keys it declared. Reading something it did not ask
for is an error, not a silent dependency, so the dependency graph in the source
is the real one.
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Iterator, Mapping, Optional, Set

from x86x64.errors import X86X64Error


class ArtifactError(X86X64Error):
    """Base for artifact access violations."""


class UndeclaredRead(ArtifactError):
    def __init__(self, pass_name: str, key: str, declared: FrozenSet[str]):
        self.pass_name, self.key = pass_name, key
        super().__init__(
            f'pass {pass_name!r} read undeclared artifact {key!r}; '
            f'add it to reads (declared: {_show(declared)})')


class UndeclaredWrite(ArtifactError):
    def __init__(self, pass_name: str, key: str, declared: FrozenSet[str]):
        self.pass_name, self.key = pass_name, key
        super().__init__(
            f'pass {pass_name!r} wrote undeclared artifact {key!r}; '
            f'add it to writes (declared: {_show(declared)})')


class MissingArtifact(ArtifactError):
    def __init__(self, pass_name: str, key: str, available: Set[str]):
        self.pass_name, self.key = pass_name, key
        super().__init__(
            f'pass {pass_name!r} needs artifact {key!r}, which no earlier pass '
            f'produced (available: {_show(available)})')


def _show(names) -> str:
    return ', '.join(sorted(names)) if names else 'none'


class ArtifactView(Mapping[str, Any]):
    """One pass's window onto the store.

    Reads are limited to declared inputs, writes to declared outputs. Both
    raise rather than failing quietly, so a pass that grows a dependency has
    to say so.
    """

    __slots__ = ('_store', '_pass', '_reads', '_writes', '_optional', '_written')

    def __init__(self, store: 'Artifacts', pass_name: str,
                 reads: FrozenSet[str], writes: FrozenSet[str],
                 optional: FrozenSet[str] = frozenset()):
        self._store = store
        self._pass = pass_name
        self._reads = reads | optional
        self._writes = writes
        self._optional = optional
        self._written: Set[str] = set()

    def __getitem__(self, key: str) -> Any:
        if key not in self._reads:
            raise UndeclaredRead(self._pass, key, self._reads)
        if key not in self._store:
            if key in self._optional:
                raise KeyError(key)
            raise MissingArtifact(self._pass, key, self._store.keys())
        return self._store.get(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key not in self._writes:
            raise UndeclaredWrite(self._pass, key, self._writes)
        self._store.put(key, value, producer=self._pass)
        self._written.add(key)

    def __iter__(self) -> Iterator[str]:
        return iter(k for k in self._reads if k in self._store)

    def __len__(self) -> int:
        return sum(1 for _ in iter(self))

    def get(self, key: str, default: Any = None) -> Any:
        """Read a declared key, falling back to *default* when unset."""
        try:
            return self[key]
        except (KeyError, MissingArtifact):
            return default

    @property
    def written(self) -> FrozenSet[str]:
        """Keys this pass actually produced, for the pipeline to report on."""
        return frozenset(self._written)


class Artifacts:
    """Everything the passes have produced so far.

    Passes never touch this directly; the pipeline hands each one an
    :class:`ArtifactView` scoped to its declarations.
    """

    def __init__(self, initial: Optional[Mapping[str, Any]] = None):
        self._data: Dict[str, Any] = dict(initial or {})
        self._producers: Dict[str, str] = {}

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def put(self, key: str, value: Any, producer: str = '') -> None:
        self._data[key] = value
        if producer:
            self._producers[key] = producer

    def keys(self) -> Set[str]:
        return set(self._data)

    def producer_of(self, key: str) -> Optional[str]:
        """Which pass produced *key*, when a later pass disagrees with it."""
        return self._producers.get(key)

    def view(self, pass_name: str, reads: FrozenSet[str],
             writes: FrozenSet[str],
             optional: FrozenSet[str] = frozenset()) -> ArtifactView:
        return ArtifactView(self, pass_name, reads, writes, optional)

    def snapshot(self) -> Dict[str, Any]:
        """Shallow copy, for comparing state across passes while debugging."""
        return dict(self._data)
