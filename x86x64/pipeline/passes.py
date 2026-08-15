"""
The unit of work.

A pass declares what it reads and what it writes, then does one job. Those
declarations are not documentation: the pipeline orders passes by them and the
artifact store enforces them, so a pass cannot quietly depend on something it
did not name.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Sequence, TYPE_CHECKING

from x86x64.errors import X86X64Error

if TYPE_CHECKING:
    from .artifacts import ArtifactView
    from .context import TranslationContext


class PassError(X86X64Error):
    """A pass could not do its job."""

    def __init__(self, pass_name: str, message: str):
        self.pass_name = pass_name
        super().__init__(f'pass {pass_name!r}: {message}')


class Phase(enum.IntEnum):
    """Coarse ordering, for passes whose data dependencies do not pin them.

    Two passes that read the same thing and write nothing in common are
    unordered by dependency alone; the phase breaks that tie in a way that
    matches how translation actually proceeds.
    """

    LOAD = 10          # parse the input image
    ANALYZE = 20       # discover functions, branches, data
    PLAN = 30          # decide layout and symbols
    TRANSLATE = 40     # x86 to x64
    REPAIR = 50        # general fixups over translated output
    QUIRK = 60         # image-specific repairs, after everything general
    LAYOUT = 70        # assign final addresses
    EMIT = 80          # build the output image
    VERIFY = 90        # check what was produced


@dataclass(frozen=True)
class PassResult:
    """What a pass reports back.

    ``changed`` distinguishes a pass that did nothing from one that did not
    apply, which matters when deciding whether a repair is still needed.
    """

    changed: bool = False
    count: int = 0
    message: str = ''
    skipped: bool = False
    reason: str = ''

    @classmethod
    def did_nothing(cls, reason: str = '') -> 'PassResult':
        return cls(changed=False, reason=reason)

    @classmethod
    def skip(cls, reason: str) -> 'PassResult':
        return cls(skipped=True, reason=reason)

    @classmethod
    def applied(cls, count: int = 1, message: str = '') -> 'PassResult':
        return cls(changed=True, count=count, message=message)


class Pass(abc.ABC):
    """Base for every unit of translation work.

    Subclasses set ``name``, ``reads``, and ``writes``, then implement
    :meth:`run`. Anything else -- ordering, artifact plumbing, diagnostics --
    is the pipeline's job.
    """

    #: Unique, stable; used in diagnostics and to order the pipeline.
    name: str = ''

    #: Artifact keys this pass needs. Missing ones are an error.
    reads: FrozenSet[str] = frozenset()

    #: Keys it may read if present, without failing when they are not.
    optional_reads: FrozenSet[str] = frozenset()

    #: Keys it produces. Writing anything else is an error.
    writes: FrozenSet[str] = frozenset()

    #: Tie-breaker when data dependencies leave the order open.
    phase: Phase = Phase.TRANSLATE

    #: Names of passes that must run first even without a shared artifact.
    after: FrozenSet[str] = frozenset()

    def applies_to(self, ctx: 'TranslationContext') -> bool:
        """Whether this pass should run at all for this image.

        The hook that keeps image-specific work out of the engine: a quirk
        returns ``True`` only for the images it was written for.
        """
        return True

    @abc.abstractmethod
    def run(self, ctx: 'TranslationContext', art: 'ArtifactView') -> PassResult:
        """Do the work. *art* exposes only the declared keys."""

    def __repr__(self) -> str:
        return f'<{type(self).__name__} {self.name!r} phase={self.phase.name}>'


class FunctionPass(Pass):
    """Adapter so a plain function can be a pass.

    Useful for small repairs that do not need state, and for tests.
    """

    def __init__(self, name: str, fn, *, reads=frozenset(),
                 writes=frozenset(), optional_reads=frozenset(),
                 phase: Phase = Phase.TRANSLATE, after=frozenset(),
                 applies=None):
        self.name = name
        self._fn = fn
        self.reads = frozenset(reads)
        self.writes = frozenset(writes)
        self.optional_reads = frozenset(optional_reads)
        self.phase = phase
        self.after = frozenset(after)
        self._applies = applies

    def applies_to(self, ctx: 'TranslationContext') -> bool:
        return True if self._applies is None else bool(self._applies(ctx))

    def run(self, ctx: 'TranslationContext', art: 'ArtifactView') -> PassResult:
        result = self._fn(ctx, art)
        if result is None:
            return PassResult.did_nothing()
        if isinstance(result, PassResult):
            return result
        if isinstance(result, bool):
            return PassResult(changed=result)
        if isinstance(result, int):
            return PassResult(changed=bool(result), count=result)
        raise PassError(self.name,
                        f'returned {type(result).__name__}, expected PassResult')
