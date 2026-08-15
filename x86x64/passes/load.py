"""
Getting the input image into the pipeline.

These are the first passes to run and the only ones that touch
:attr:`~x86x64.pipeline.context.SourceImage.data` directly; everything
downstream works from the artifacts produced here.
"""

from __future__ import annotations

from x86x64.pe import pe32 as pe32mod
from x86x64.pipeline import Pass, PassResult, Phase, register

#: Artifact keys, named once so a typo is an import error rather than a
#: dependency that silently never resolves.
PE32 = 'pe32'
SECTIONS = 'pe32.sections'
TEXT = 'pe32.text'
TEXT_RVA = 'pe32.text_rva'
IMPORTS = 'pe32.imports'
EXPORTS = 'pe32.exports'
ENTRY_RVA = 'pe32.entry_rva'


@register()
class LoadPE32(Pass):
    """Parse the PE32 headers and section table."""

    name = 'load.pe32'
    phase = Phase.LOAD
    writes = frozenset({PE32, SECTIONS, ENTRY_RVA})

    def run(self, ctx, art) -> PassResult:
        image = pe32mod.PE32Image(ctx.source.data)
        art[PE32] = image
        art[SECTIONS] = list(image.sections)
        art[ENTRY_RVA] = image.entry_rva
        ctx.diagnostics.info(
            self.name,
            f'{len(image.sections)} sections, entry at {image.entry_rva:#x}')
        return PassResult.applied(len(image.sections))


@register()
class LoadTextSection(Pass):
    """Pull out the primary executable section.

    Kept separate from :class:`LoadPE32` so an image with an unusual layout can
    replace just this step.
    """

    name = 'load.text'
    phase = Phase.LOAD
    reads = frozenset({PE32})
    writes = frozenset({TEXT, TEXT_RVA})

    def run(self, ctx, art) -> PassResult:
        found = art[PE32].get_text_section()
        if found is None:
            ctx.diagnostics.warning(self.name, 'no executable section found')
            return PassResult.did_nothing('no executable section')

        section, data = found
        art[TEXT] = data
        art[TEXT_RVA] = section.vaddr
        ctx.diagnostics.info(
            self.name,
            f'{section.name} at {section.vaddr:#x}, {len(data):,} bytes')
        return PassResult.applied(len(data))


@register()
class LoadImports(Pass):
    """Read the import directory."""

    name = 'load.imports'
    phase = Phase.LOAD
    reads = frozenset({PE32})
    writes = frozenset({IMPORTS})

    def run(self, ctx, art) -> PassResult:
        imports = art[PE32].parse_imports()
        art[IMPORTS] = imports
        total = sum(len(d['functions']) for d in imports)
        ctx.diagnostics.info(self.name,
                             f'{total} imports from {len(imports)} DLLs')
        return PassResult.applied(total)


@register()
class LoadExports(Pass):
    """Read the export directory, empty for most executables."""

    name = 'load.exports'
    phase = Phase.LOAD
    reads = frozenset({PE32})
    writes = frozenset({EXPORTS})

    def run(self, ctx, art) -> PassResult:
        exports = art[PE32].parse_exports()
        art[EXPORTS] = exports
        if not exports:
            return PassResult.did_nothing('image exports nothing')
        ctx.diagnostics.info(self.name, f'{len(exports)} exports')
        return PassResult.applied(len(exports))
