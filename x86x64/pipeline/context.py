"""
What a translation run knows about itself.

The context separates three things the legacy translator kept mixed together
on one object: the input image (never changes), the target description (chosen
once, up front), and the artifacts passes build up as they run.

Nothing here mentions a particular binary. A pass that needs to behave
differently for one image matches on :class:`ImageIdentity` instead, so the
engine stays the same for every Win2000 file.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .artifacts import Artifacts
from .diagnostics import Diagnostics


class ImageKind(enum.Enum):
    """What the image is, which decides which passes make sense.

    Determined from the image itself, never from its filename.
    """

    EXECUTABLE = 'executable'
    DLL = 'dll'
    NATIVE_DLL = 'native-dll'      # ntdll and friends: syscall stubs inside
    KERNEL = 'kernel'              # ntoskrnl, hal: ring 0, has an SSDT
    DRIVER = 'driver'

    @property
    def is_ring0(self) -> bool:
        return self in (ImageKind.KERNEL, ImageKind.DRIVER)


@dataclass(frozen=True)
class ImageIdentity:
    """Enough to recognise an image without trusting its name.

    Quirks key off this. A repair pinned to one build of one binary matches on
    ``sha256``; one that applies to a whole product family matches on the
    linker version or an exported symbol.
    """

    sha256: str
    size: int
    machine: int
    timestamp: int
    kind: ImageKind
    name: str = ''
    linker_version: Tuple[int, int] = (0, 0)
    exports: frozenset = frozenset()
    imports: frozenset = frozenset()

    @classmethod
    def from_bytes(cls, data: bytes, *, kind: ImageKind, name: str = '',
                   machine: int = 0, timestamp: int = 0,
                   linker_version: Tuple[int, int] = (0, 0),
                   exports=(), imports=()) -> 'ImageIdentity':
        return cls(
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            machine=machine,
            timestamp=timestamp,
            kind=kind,
            name=name,
            linker_version=linker_version,
            exports=frozenset(exports),
            imports=frozenset(imports),
        )

    def short(self) -> str:
        return f'{self.name or "image"}@{self.sha256[:12]}'


@dataclass(frozen=True)
class SourceImage:
    """The input, held read-only for the whole run."""

    data: bytes
    identity: ImageIdentity
    path: str = ''

    @property
    def kind(self) -> ImageKind:
        return self.identity.kind


class Abi(enum.Enum):
    WIN64 = 'win64'          # Microsoft x64: rcx, rdx, r8, r9 then stack
    SYSV = 'sysv'            # here so the ABI is a choice, not an assumption


@dataclass(frozen=True)
class TargetSpec:
    """Where the output has to run.

    Defaults describe a user-mode Win64 image; kernel targets override the
    base and subsystem.
    """

    image_base: int = 0x140000000
    section_alignment: int = 0x1000
    file_alignment: int = 0x200
    subsystem: int = 3                    # console
    abi: Abi = Abi.WIN64
    machine: int = 0x8664
    os_major: int = 10
    os_minor: int = 0
    dynamic_base: bool = True
    nx_compat: bool = True

    def for_kernel(self) -> 'TargetSpec':
        return dataclasses.replace(
            self, image_base=0xFFFFF80000000000, subsystem=1,
            dynamic_base=False)


@dataclass(frozen=True)
class Options:
    """Run-level switches, kept separate from anything image-specific."""

    pure: bool = False
    """Skip every address-pinned quirk and use only general translation."""

    enable_quirks: bool = True
    strict_artifacts: bool = True
    """Fail on an undeclared artifact access instead of warning."""

    stop_after: str = ''
    """Pass name to stop at, for bisecting a bad output."""

    trace_passes: bool = False
    extra: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> 'Options':
        """Read the switches the legacy CLI took from the environment."""
        env = os.environ if env is None else env
        pure = bool(env.get('PURE') or env.get('CMD_NO_HACKS')
                    or env.get('PURE_TRANSLATOR'))
        return cls(pure=pure, enable_quirks=not pure,
                   trace_passes=bool(env.get('TRACE_PASSES')))


@dataclass
class TranslationContext:
    """Handed to every pass; the only thing they share.

    ``source``, ``target``, and ``options`` are frozen. Everything a pass
    produces goes into ``artifacts``, and it can only reach the keys it
    declared.
    """

    source: SourceImage
    target: TargetSpec = field(default_factory=TargetSpec)
    options: Options = field(default_factory=Options)
    artifacts: Artifacts = field(default_factory=Artifacts)
    diagnostics: Diagnostics = field(default_factory=Diagnostics)

    @property
    def identity(self) -> ImageIdentity:
        return self.source.identity

    def describe(self) -> str:
        return (f'{self.identity.short()} ({self.source.kind.value}, '
                f'{self.source.identity.size:,} bytes) -> '
                f'base {self.target.image_base:#x}')
