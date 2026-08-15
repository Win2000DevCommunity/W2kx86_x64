"""
Structured findings from a translation run.

The legacy passes printed counters as they went, which is fine to watch but
impossible to assert on -- a test could not ask "did the branch repair fire?"
without scraping stdout. Passes record entries here instead, and printing is
one way of rendering them.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional


class Severity(enum.Enum):
    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'


@dataclass(frozen=True)
class Diagnostic:
    """One thing a pass observed, tied to where it happened."""

    severity: Severity
    pass_name: str
    message: str
    rva: Optional[int] = None
    count: int = 1
    detail: Dict[str, object] = field(default_factory=dict)

    def render(self) -> str:
        where = f' at {self.rva:#x}' if self.rva is not None else ''
        times = f' (x{self.count})' if self.count != 1 else ''
        return f'[{self.severity.value}] {self.pass_name}: {self.message}{where}{times}'


class Diagnostics:
    """Collected diagnostics, queryable by pass and severity."""

    def __init__(self) -> None:
        self._entries: List[Diagnostic] = []
        self._counters: Dict[str, int] = {}

    def __iter__(self) -> Iterator[Diagnostic]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def add(self, severity: Severity, pass_name: str, message: str,
            rva: Optional[int] = None, count: int = 1, **detail) -> Diagnostic:
        entry = Diagnostic(severity, pass_name, message, rva, count, detail)
        self._entries.append(entry)
        return entry

    def info(self, pass_name: str, message: str, **kw) -> Diagnostic:
        return self.add(Severity.INFO, pass_name, message, **kw)

    def warning(self, pass_name: str, message: str, **kw) -> Diagnostic:
        return self.add(Severity.WARNING, pass_name, message, **kw)

    def error(self, pass_name: str, message: str, **kw) -> Diagnostic:
        return self.add(Severity.ERROR, pass_name, message, **kw)

    def count(self, name: str, amount: int = 1) -> None:
        """Bump a named counter, the structured form of the progress prints."""
        self._counters[name] = self._counters.get(name, 0) + amount

    @property
    def counters(self) -> Dict[str, int]:
        return dict(self._counters)

    def by_pass(self, pass_name: str) -> List[Diagnostic]:
        return [e for e in self._entries if e.pass_name == pass_name]

    def by_severity(self, severity: Severity) -> List[Diagnostic]:
        return [e for e in self._entries if e.severity is severity]

    @property
    def errors(self) -> List[Diagnostic]:
        return self.by_severity(Severity.ERROR)

    @property
    def ok(self) -> bool:
        return not self.errors

    def render(self, min_severity: Severity = Severity.INFO) -> str:
        order = list(Severity)
        floor = order.index(min_severity)
        return '\n'.join(e.render() for e in self._entries
                         if order.index(e.severity) >= floor)
