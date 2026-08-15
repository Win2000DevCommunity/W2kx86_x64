"""
Tests for the shipped passes, run against real Win2000 binaries where they
are available.

The pipeline tests use synthetic passes to check the framework's rules. These
check that the framework carries actual translation work: that the passes
compose, that the pipeline orders them correctly from their declarations, and
that image classification is driven by content rather than by filename.
"""

from __future__ import annotations

import pathlib

import pytest

from x86x64.passes import classify, identify, load_source, target_for
from x86x64.passes.analyze import CFG, FUNCTIONS, POINTERS, SEH_ANCHORS
from x86x64.passes.load import ENTRY_RVA, EXPORTS, IMPORTS, PE32, SECTIONS, TEXT, TEXT_RVA
from x86x64.pipeline import (
    REGISTRY,
    ImageKind,
    Options,
    Pipeline,
    TargetSpec,
    TranslationContext,
    UndeclaredRead,
)

WIN2000 = pathlib.Path(
    r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU')
CMD = WIN2000 / 'cmd.exe'
NTDLL = WIN2000 / 'ntdll.dll'

needs_cmd = pytest.mark.skipif(not CMD.exists(), reason='cmd.exe not available')
needs_ntdll = pytest.mark.skipif(not NTDLL.exists(),
                                 reason='ntdll.dll not available')


def context_for(path: pathlib.Path, **option_kw) -> TranslationContext:
    source = load_source(path)
    return TranslationContext(source=source, target=target_for(source),
                              options=Options(**option_kw))


# ── registration ──────────────────────────────────────────────────────────

class TestRegistration:

    def test_importing_the_package_registers_the_passes(self):
        assert 'load.pe32' in REGISTRY
        assert 'analyze.functions' in REGISTRY

    def test_every_registered_pass_declares_a_name_and_phase(self):
        for p in REGISTRY:
            assert p.name, f'{type(p).__name__} has no name'
            assert p.phase is not None, p.name

    def test_no_shipped_pass_is_image_specific(self):
        """The engine stays universal.

        A pass tied to one binary must carry a matcher, so it cannot become a
        hidden assumption inside a generally-named pass.
        """
        for p in REGISTRY:
            if REGISTRY.matcher_for(p.name) is None:
                assert 'cmd' not in p.name.lower(), p.name


# ── ordering derived from the real declarations ───────────────────────────

class TestRealOrdering:

    def test_pipeline_orders_the_shipped_passes(self):
        source_bytes = b'MZ' + b'\x00' * 200
        order = [p.name for p in Pipeline(list(REGISTRY)).order()]

        assert order.index('load.pe32') < order.index('load.text')
        assert order.index('load.text') < order.index('analyze.functions')
        assert order.index('analyze.functions') < order.index('analyze.cfg')

    def test_declarations_have_no_cycles(self):
        Pipeline(list(REGISTRY)).order()  # raises CyclicDependency if broken

    def test_every_read_is_produced_by_some_pass(self):
        """No shipped pass depends on something nothing supplies."""
        Pipeline(list(REGISTRY)).order()


# ── image classification, from content ────────────────────────────────────

class TestClassification:

    @needs_cmd
    def test_executable_is_recognised(self):
        assert identify(CMD.read_bytes(), 'cmd.exe').kind is ImageKind.EXECUTABLE

    @needs_ntdll
    def test_native_dll_is_recognised(self):
        assert identify(NTDLL.read_bytes(), 'ntdll.dll').kind is ImageKind.NATIVE_DLL

    @needs_ntdll
    def test_native_dll_is_not_detected_from_the_subsystem_field(self):
        """Win2000's ntdll.dll reports subsystem 3, not 1.

        Classifying on the header would call it an ordinary DLL and skip
        syscall stub extraction, so the paired Nt/Zw exports are the marker.
        """
        from x86x64.pe import pe32 as pe32mod

        data = NTDLL.read_bytes()
        assert pe32mod.PE32Image(data).subsystem != 1
        assert identify(data, 'ntdll.dll').kind is ImageKind.NATIVE_DLL

    @needs_ntdll
    def test_classification_ignores_the_filename(self):
        """The property a universal translator needs.

        The same bytes under a different name must classify the same way,
        otherwise renaming a file changes how it is translated.
        """
        data = NTDLL.read_bytes()

        assert identify(data, 'ntdll.dll').kind is identify(data, 'x.bin').kind

    @needs_cmd
    def test_identity_is_content_addressed(self):
        data = CMD.read_bytes()

        assert identify(data, 'a').sha256 == identify(data, 'b').sha256

    @needs_ntdll
    def test_native_exports_are_captured_for_matching(self):
        ident = identify(NTDLL.read_bytes(), 'ntdll.dll')

        assert 'NtCreateFile' in ident.exports

    @needs_cmd
    def test_linker_version_is_read(self):
        """VC6 built Win2000, so this is how toolchain quirks get matched."""
        ident = identify(CMD.read_bytes(), 'cmd.exe')

        assert ident.linker_version[0] > 0

    @needs_cmd
    def test_user_mode_target_stays_in_user_space(self):
        source = load_source(CMD)

        assert target_for(source).image_base < 0x800000000000

    def test_kernel_images_target_kernel_space(self):
        spec = TargetSpec().for_kernel()

        assert spec.image_base >= 0xFFFF000000000000


# ── the passes, on a real image ───────────────────────────────────────────

@needs_cmd
class TestOnRealBinary:

    @pytest.fixture(scope='class')
    def loaded(self):
        ctx = context_for(CMD)
        pipeline = Pipeline([REGISTRY.get(n) for n in
                             ('load.pe32', 'load.text', 'load.imports',
                              'load.exports')])
        result = pipeline.run(ctx)
        return ctx, result

    def test_headers_parse(self, loaded):
        ctx, _ = loaded

        assert ctx.artifacts.get(SECTIONS)
        assert ctx.artifacts.get(ENTRY_RVA) > 0

    def test_text_section_is_found(self, loaded):
        ctx, _ = loaded

        assert len(ctx.artifacts.get(TEXT)) > 0x1000
        assert ctx.artifacts.get(TEXT_RVA) > 0

    def test_imports_are_read(self, loaded):
        ctx, _ = loaded
        imports = ctx.artifacts.get(IMPORTS)

        assert imports
        assert any('kernel32' in entry['dll'].lower() for entry in imports)

    def test_each_artifact_records_its_producer(self, loaded):
        ctx, _ = loaded

        assert ctx.artifacts.producer_of(TEXT) == 'load.text'
        assert ctx.artifacts.producer_of(PE32) == 'load.pe32'

    def test_analysis_finds_functions(self):
        ctx = context_for(CMD)
        pipeline = Pipeline([REGISTRY.get(n) for n in
                             ('load.pe32', 'load.text', 'analyze.functions')])

        pipeline.run(ctx)

        assert len(ctx.artifacts.get(FUNCTIONS)) > 100

    def test_full_analysis_runs_end_to_end(self):
        names = ('load.pe32', 'load.text', 'analyze.functions', 'analyze.cfg',
                 'analyze.pointers', 'analyze.seh')
        ctx = context_for(CMD)

        result = Pipeline([REGISTRY.get(n) for n in names]).run(ctx)

        assert [r.name for r in result.records][0] == 'load.pe32'
        assert ctx.artifacts.get(CFG) is not None
        assert ctx.artifacts.get(POINTERS) is not None
        assert ctx.artifacts.get(SEH_ANCHORS) is not None
        assert result.ok

    def test_a_pass_cannot_reach_past_its_declarations(self):
        """The isolation guarantee, checked on a real pass.

        ``load.text`` declares only ``pe32``; the imports another pass
        produced are invisible to it.
        """
        ctx = context_for(CMD)
        Pipeline([REGISTRY.get('load.pe32'), REGISTRY.get('load.imports')]).run(ctx)

        text_pass = REGISTRY.get('load.text')
        view = ctx.artifacts.view(text_pass.name, text_pass.reads,
                                  text_pass.writes, text_pass.optional_reads)

        with pytest.raises(UndeclaredRead):
            view[IMPORTS]

    def test_diagnostics_are_queryable_rather_than_printed(self):
        ctx = context_for(CMD)
        Pipeline([REGISTRY.get('load.pe32'), REGISTRY.get('load.text')]).run(ctx)

        assert ctx.diagnostics.by_pass('load.text')
        assert ctx.diagnostics.ok
