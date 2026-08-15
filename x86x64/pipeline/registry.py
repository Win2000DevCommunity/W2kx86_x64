"""
Where passes are found.

Adding translation behaviour means registering a pass, not editing the engine.
That is the whole point for image-specific repairs: the 192 cmd.exe fixups in
the legacy translator are engine code, so every new binary means touching the
core. A registered quirk matches on :class:`ImageIdentity` and the engine never
learns its name.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional, Sequence

from x86x64.errors import X86X64Error

from .context import ImageIdentity, ImageKind, TranslationContext
from .passes import Pass, Phase


class RegistryError(X86X64Error):
    """A pass could not be registered or looked up."""


#: A predicate over the image being translated.
Matcher = Callable[[ImageIdentity], bool]


def by_sha256(*digests: str) -> Matcher:
    """Match exactly one build of one binary.

    The honest matcher for an address-pinned repair: those offsets are only
    valid for the bytes they were derived from.
    """
    wanted = {d.lower() for d in digests}
    return lambda ident: ident.sha256.lower() in wanted


def by_export(*names: str) -> Matcher:
    """Match any image exporting all of *names*."""
    wanted = set(names)
    return lambda ident: wanted <= ident.exports


def by_kind(*kinds: ImageKind) -> Matcher:
    wanted = set(kinds)
    return lambda ident: ident.kind in wanted


def by_linker(major: int, minor: Optional[int] = None) -> Matcher:
    """Match a toolchain, for quirks that are really compiler idioms."""
    def match(ident: ImageIdentity) -> bool:
        if ident.linker_version[0] != major:
            return False
        return minor is None or ident.linker_version[1] == minor
    return match


def any_of(*matchers: Matcher) -> Matcher:
    return lambda ident: any(m(ident) for m in matchers)


def all_of(*matchers: Matcher) -> Matcher:
    return lambda ident: all(m(ident) for m in matchers)


class PassRegistry:
    """The set of passes available to build a pipeline from."""

    def __init__(self) -> None:
        self._passes: Dict[str, Pass] = {}
        self._matchers: Dict[str, Matcher] = {}

    def __len__(self) -> int:
        return len(self._passes)

    def __contains__(self, name: object) -> bool:
        return name in self._passes

    def __iter__(self):
        return iter(self._passes.values())

    def add(self, p: Pass, matcher: Optional[Matcher] = None) -> Pass:
        """Register *p*, optionally limited to images *matcher* accepts."""
        if not p.name:
            raise RegistryError(f'{type(p).__name__} has no name')
        if p.name in self._passes:
            raise RegistryError(
                f'pass {p.name!r} is already registered by '
                f'{type(self._passes[p.name]).__name__}')
        overlap = p.reads & p.writes
        if overlap:
            # Allowed, but it means the pass edits in place; say so explicitly
            # rather than letting the dependency graph imply a cycle.
            pass
        self._passes[p.name] = p
        if matcher is not None:
            self._matchers[p.name] = matcher
        return p

    def register(self, matcher: Optional[Matcher] = None):
        """Decorator form, for a :class:`Pass` subclass."""
        def decorate(cls):
            self.add(cls(), matcher)
            return cls
        return decorate

    def get(self, name: str) -> Pass:
        try:
            return self._passes[name]
        except KeyError:
            raise RegistryError(
                f'no pass named {name!r}; known: '
                f'{", ".join(sorted(self._passes)) or "none"}') from None

    def names(self) -> List[str]:
        return sorted(self._passes)

    def matcher_for(self, name: str) -> Optional[Matcher]:
        return self._matchers.get(name)

    def selected_for(self, ctx: TranslationContext) -> List[Pass]:
        """The passes that should run for this image.

        A pass runs when its registered matcher accepts the image and its own
        :meth:`~Pass.applies_to` agrees. Quirk-phase passes are dropped
        entirely when quirks are off, which is what ``--pure`` means.
        """
        chosen: List[Pass] = []
        for p in self._passes.values():
            if p.phase is Phase.QUIRK and not ctx.options.enable_quirks:
                continue
            matcher = self._matchers.get(p.name)
            if matcher is not None and not matcher(ctx.identity):
                continue
            if not p.applies_to(ctx):
                continue
            chosen.append(p)
        return chosen

    def quirks(self) -> List[Pass]:
        return [p for p in self._passes.values() if p.phase is Phase.QUIRK]


#: The registry the shipped passes attach to. Applications may build their own.
REGISTRY = PassRegistry()


def register(matcher: Optional[Matcher] = None):
    """Register into the default registry."""
    return REGISTRY.register(matcher)
