"""
Running the passes.

Order comes from what passes declare, not from a hand-maintained list: if A
writes what B reads, A runs first. That is the difference between adding a
pass and inserting one -- the legacy translator's ordering lived in the body
of one 400-line method, and several comments there exist only to warn that a
call must not be moved.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from x86x64.errors import X86X64Error

from .artifacts import Artifacts
from .context import TranslationContext
from .diagnostics import Severity
from .passes import Pass, PassError, PassResult, Phase
from .registry import REGISTRY, PassRegistry


class PipelineError(X86X64Error):
    """The pipeline could not be built or run."""


class CyclicDependency(PipelineError):
    def __init__(self, cycle: Sequence[str]):
        self.cycle = list(cycle)
        super().__init__('passes depend on each other in a cycle: '
                         + ' -> '.join([*cycle, cycle[0]]))


class UnsatisfiedDependency(PipelineError):
    def __init__(self, pass_name: str, key: str, available: Iterable[str]):
        self.pass_name, self.key = pass_name, key
        known = ', '.join(sorted(available)) or 'none'
        super().__init__(
            f'pass {pass_name!r} reads {key!r} but no pass writes it and it is '
            f'not seeded (produced elsewhere: {known})')


@dataclass(frozen=True)
class PassRecord:
    """What happened when one pass ran."""

    name: str
    result: PassResult
    seconds: float
    wrote: frozenset = frozenset()

    @property
    def changed(self) -> bool:
        return self.result.changed


@dataclass
class PipelineResult:
    """The outcome of a whole run."""

    context: TranslationContext
    records: List[PassRecord] = field(default_factory=list)
    stopped_at: str = ''

    @property
    def artifacts(self) -> Artifacts:
        return self.context.artifacts

    @property
    def ok(self) -> bool:
        return self.context.diagnostics.ok

    def record_for(self, name: str) -> Optional[PassRecord]:
        return next((r for r in self.records if r.name == name), None)

    def changed_passes(self) -> List[str]:
        return [r.name for r in self.records if r.changed]

    def summary(self) -> str:
        lines = [f'{len(self.records)} passes, '
                 f'{len(self.changed_passes())} changed something']
        for r in self.records:
            if r.result.skipped:
                lines.append(f'  {r.name:<40} skipped: {r.result.reason}')
            else:
                mark = '*' if r.changed else ' '
                count = f' ({r.result.count})' if r.result.count else ''
                lines.append(f'{mark} {r.name:<40} {r.seconds * 1000:7.1f}ms{count}')
        if self.stopped_at:
            lines.append(f'stopped after {self.stopped_at}')
        return '\n'.join(lines)


class Pipeline:
    """An ordered set of passes, ready to run against a context."""

    def __init__(self, passes: Sequence[Pass]):
        self._passes = list(passes)
        self._order: Optional[List[Pass]] = None

    def __len__(self) -> int:
        return len(self._passes)

    def __iter__(self):
        return iter(self._passes)

    @classmethod
    def for_context(cls, ctx: TranslationContext,
                    registry: PassRegistry = REGISTRY) -> 'Pipeline':
        """Build the pipeline this particular image needs."""
        return cls(registry.selected_for(ctx))

    def order(self, seeded: Iterable[str] = ()) -> List[Pass]:
        """Sort passes so every read happens after the write that supplies it.

        *seeded* names artifacts already in the store before any pass runs.
        Ties are broken by phase, then by name, so the order is deterministic
        and a rebuild cannot silently reshuffle.
        """
        if self._order is not None:
            return self._order

        producers: Dict[str, List[str]] = {}
        for p in self._passes:
            for key in p.writes:
                producers.setdefault(key, []).append(p.name)

        by_name = {p.name: p for p in self._passes}
        seeded = set(seeded)

        edges: Dict[str, Set[str]] = {p.name: set() for p in self._passes}
        for p in self._passes:
            for key in p.reads:
                if key in seeded:
                    continue
                if key not in producers:
                    raise UnsatisfiedDependency(p.name, key, producers)
                for producer in producers[key]:
                    if producer != p.name:
                        edges[p.name].add(producer)
            for key in p.optional_reads:
                for producer in producers.get(key, []):
                    if producer != p.name:
                        edges[p.name].add(producer)
            for earlier in p.after:
                if earlier in by_name:
                    edges[p.name].add(earlier)

        self._order = self._toposort(by_name, edges)
        return self._order

    @staticmethod
    def _toposort(by_name: Dict[str, Pass],
                  edges: Dict[str, Set[str]]) -> List[Pass]:
        """Kahn's algorithm, with phase then name as the tie-break."""
        remaining = dict(edges)
        out: List[Pass] = []

        while remaining:
            ready = [n for n, deps in remaining.items()
                     if not (deps & remaining.keys())]
            if not ready:
                out_names = {p.name for p in out}
                cycle = _find_cycle(remaining, out_names)
                raise CyclicDependency(cycle)
            ready.sort(key=lambda n: (by_name[n].phase, n))
            chosen = ready[0]
            out.append(by_name[chosen])
            del remaining[chosen]

        return out

    def run(self, ctx: TranslationContext) -> PipelineResult:
        """Run every pass in order, threading artifacts between them."""
        result = PipelineResult(context=ctx)
        order = self.order(seeded=ctx.artifacts.keys())

        for p in order:
            view = ctx.artifacts.view(p.name, p.reads, p.writes,
                                      p.optional_reads)
            started = time.perf_counter()
            try:
                outcome = p.run(ctx, view)
            except PassError:
                raise
            except Exception as exc:
                raise PassError(p.name, f'{type(exc).__name__}: {exc}') from exc
            elapsed = time.perf_counter() - started

            if outcome is None:
                outcome = PassResult.did_nothing()
            result.records.append(
                PassRecord(p.name, outcome, elapsed, view.written))

            if ctx.options.trace_passes:
                ctx.diagnostics.add(
                    Severity.DEBUG, p.name,
                    outcome.message or ('changed' if outcome.changed else 'no change'),
                    count=outcome.count or 1)
            if outcome.count:
                ctx.diagnostics.count(p.name, outcome.count)

            if ctx.options.stop_after and p.name == ctx.options.stop_after:
                result.stopped_at = p.name
                break

        return result


def _find_cycle(remaining: Dict[str, Set[str]], done: Set[str]) -> List[str]:
    """Pull one concrete cycle out, so the error names the passes involved."""
    start = next(iter(remaining))
    seen: List[str] = []
    node = start
    while node not in seen:
        seen.append(node)
        nxt = sorted(remaining[node] - done)
        if not nxt:
            break
        node = nxt[0]
    if node in seen:
        return seen[seen.index(node):]
    return seen
