"""
The translation pipeline: explicit inputs, explicit outputs, pluggable passes.

A pass declares the artifacts it reads and writes. The pipeline derives its
order from those declarations, and the artifact store refuses any access that
was not declared. Together that means a pass can be read, tested, and replaced
on its own, and a new one can be added without editing the engine.

Image-specific behaviour goes in a pass that matches on
:class:`~x86x64.pipeline.context.ImageIdentity`, so the engine stays universal
across Win2000 binaries.

    from x86x64.pipeline import Pass, Phase, PassResult, register

    @register()
    class CountRelocations(Pass):
        name = 'analyze.reloc-count'
        phase = Phase.ANALYZE
        reads = frozenset({'pe32'})
        writes = frozenset({'reloc.count'})

        def run(self, ctx, art):
            art['reloc.count'] = len(art['pe32'].relocations)
            return PassResult.applied(art['reloc.count'])
"""

from .artifacts import (
    ArtifactError,
    Artifacts,
    ArtifactView,
    MissingArtifact,
    UndeclaredRead,
    UndeclaredWrite,
)
from .context import (
    Abi,
    ImageIdentity,
    ImageKind,
    Options,
    SourceImage,
    TargetSpec,
    TranslationContext,
)
from .diagnostics import Diagnostic, Diagnostics, Severity
from .passes import FunctionPass, Pass, PassError, PassResult, Phase
from .pipeline import (
    CyclicDependency,
    Pipeline,
    PipelineError,
    PipelineResult,
    PassRecord,
    UnsatisfiedDependency,
)
from .registry import (
    REGISTRY,
    Matcher,
    PassRegistry,
    RegistryError,
    all_of,
    any_of,
    by_export,
    by_kind,
    by_linker,
    by_sha256,
    register,
)

__all__ = [
    # context
    'TranslationContext', 'SourceImage', 'TargetSpec', 'Options',
    'ImageIdentity', 'ImageKind', 'Abi',
    # artifacts
    'Artifacts', 'ArtifactView', 'ArtifactError',
    'UndeclaredRead', 'UndeclaredWrite', 'MissingArtifact',
    # passes
    'Pass', 'FunctionPass', 'PassResult', 'PassError', 'Phase',
    # pipeline
    'Pipeline', 'PipelineResult', 'PassRecord', 'PipelineError',
    'CyclicDependency', 'UnsatisfiedDependency',
    # registry
    'PassRegistry', 'REGISTRY', 'register', 'RegistryError', 'Matcher',
    'by_sha256', 'by_export', 'by_kind', 'by_linker', 'any_of', 'all_of',
    # diagnostics
    'Diagnostics', 'Diagnostic', 'Severity',
]
