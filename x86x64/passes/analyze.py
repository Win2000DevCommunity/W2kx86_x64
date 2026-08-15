"""
Analysis passes: what the input code actually is.

Each wraps one function from :mod:`x86x64.analysis` and states what it needs.
Splitting them this way means a caller can run only the analysis it wants, and
a replacement for any one step slots in by declaring the same outputs.
"""

from __future__ import annotations

from x86x64.analysis.discover import (
    discover_function_rvas,
    discover_seh_scope_anchors,
    discover_static_pointers,
)
from x86x64.analysis.text import analyze_x86_text_section
from x86x64.pipeline import Pass, PassResult, Phase, register

from .load import ENTRY_RVA, PE32, TEXT, TEXT_RVA

CFG = 'analysis.cfg'
FUNCTIONS = 'analysis.functions'
POINTERS = 'analysis.pointers'
SEH_ANCHORS = 'analysis.seh_anchors'
DYNAMIC = 'analysis.dynamic'


@register()
class DiscoverFunctions(Pass):
    """Find function entry points in the text section."""

    name = 'analyze.functions'
    phase = Phase.ANALYZE
    reads = frozenset({PE32, TEXT, TEXT_RVA})
    optional_reads = frozenset({DYNAMIC})
    writes = frozenset({FUNCTIONS})

    def run(self, ctx, art) -> PassResult:
        rvas = discover_function_rvas(art[PE32], art[TEXT], art[TEXT_RVA],
                                      art.get(DYNAMIC))
        art[FUNCTIONS] = sorted(rvas)
        ctx.diagnostics.info(self.name, f'{len(rvas)} entry points')
        return PassResult.applied(len(rvas))


@register()
class AnalyzeControlFlow(Pass):
    """Recover branch targets, epilogues, and inline data spans."""

    name = 'analyze.cfg'
    phase = Phase.ANALYZE
    reads = frozenset({PE32, TEXT, TEXT_RVA, FUNCTIONS})
    optional_reads = frozenset({DYNAMIC})
    writes = frozenset({CFG})

    def run(self, ctx, art) -> PassResult:
        cfg = analyze_x86_text_section(art[PE32], art[TEXT], art[TEXT_RVA],
                                       art.get(DYNAMIC), art[FUNCTIONS])
        art[CFG] = cfg
        ctx.diagnostics.info(
            self.name,
            f'{len(getattr(cfg, "branch_targets", ()))} branch targets, '
            f'{len(getattr(cfg, "data_spans", ()))} data spans')
        return PassResult.applied(len(getattr(cfg, 'branch_targets', ())))


@register()
class DiscoverPointers(Pass):
    """Find absolute pointers into the image that will need relocating."""

    name = 'analyze.pointers'
    phase = Phase.ANALYZE
    reads = frozenset({PE32, TEXT, TEXT_RVA})
    writes = frozenset({POINTERS})

    def run(self, ctx, art) -> PassResult:
        image = art[PE32]
        found = discover_static_pointers(art[TEXT], art[TEXT_RVA],
                                         image.image_base, image.image_size)
        art[POINTERS] = found
        return PassResult.applied(len(found))


@register()
class DiscoverSehAnchors(Pass):
    """Locate VC6 SEH scope tables, which must not be treated as code."""

    name = 'analyze.seh'
    phase = Phase.ANALYZE
    reads = frozenset({PE32, TEXT, TEXT_RVA})
    writes = frozenset({SEH_ANCHORS})

    def run(self, ctx, art) -> PassResult:
        image = art[PE32]
        anchors = discover_seh_scope_anchors(art[TEXT], art[TEXT_RVA],
                                             image.image_base, image.image_size)
        art[SEH_ANCHORS] = anchors
        return PassResult.applied(len(anchors))
