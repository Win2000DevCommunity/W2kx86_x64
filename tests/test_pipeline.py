"""
Tests for the pass pipeline.

The point of the pipeline is that coupling becomes impossible rather than
merely discouraged, so most of these assert on what the framework *refuses*:
undeclared reads, undeclared writes, dependencies nothing supplies, and cycles.
"""

from __future__ import annotations

import pytest

from x86x64.pipeline import (
    Artifacts,
    CyclicDependency,
    Diagnostics,
    FunctionPass,
    ImageIdentity,
    ImageKind,
    MissingArtifact,
    Options,
    Pass,
    PassError,
    PassRegistry,
    PassResult,
    Phase,
    Pipeline,
    RegistryError,
    Severity,
    SourceImage,
    TargetSpec,
    TranslationContext,
    UndeclaredRead,
    UndeclaredWrite,
    UnsatisfiedDependency,
    all_of,
    any_of,
    by_export,
    by_kind,
    by_linker,
    by_sha256,
)


def make_context(data: bytes = b'MZ\x90\x00', *, kind=ImageKind.EXECUTABLE,
                 name='test.exe', pure=False, **identity_kw):
    identity = ImageIdentity.from_bytes(data, kind=kind, name=name,
                                        **identity_kw)
    return TranslationContext(
        source=SourceImage(data=data, identity=identity),
        target=TargetSpec(),
        options=Options(pure=pure, enable_quirks=not pure),
    )


def simple_pass(name, *, reads=(), writes=(), phase=Phase.TRANSLATE,
                fn=None, after=(), optional_reads=()):
    def default(ctx, art):
        for key in writes:
            art[key] = f'{name}:{key}'
        return PassResult.applied(len(writes))

    return FunctionPass(name, fn or default, reads=reads, writes=writes,
                        phase=phase, after=after, optional_reads=optional_reads)


# ── artifact access control ───────────────────────────────────────────────

class TestArtifactIsolation:
    """A pass sees exactly what it declared, and nothing else."""

    def test_declared_read_and_write_work(self):
        store = Artifacts({'input': 7})
        view = store.view('p', frozenset({'input'}), frozenset({'output'}))

        view['output'] = view['input'] * 2

        assert store.get('output') == 14

    def test_reading_an_undeclared_key_is_an_error(self):
        """The failure the shared-self design could not produce.

        In the legacy translator any pass could read ``self.rva_map``; nothing
        recorded the dependency, so reordering passes broke things silently.
        """
        store = Artifacts({'secret': 1})
        view = store.view('p', frozenset({'allowed'}), frozenset())

        with pytest.raises(UndeclaredRead) as exc:
            view['secret']

        assert 'secret' in str(exc.value)
        assert 'allowed' in str(exc.value)

    def test_writing_an_undeclared_key_is_an_error(self):
        store = Artifacts()
        view = store.view('p', frozenset(), frozenset({'mine'}))

        with pytest.raises(UndeclaredWrite):
            view['theirs'] = 1

        assert 'theirs' not in store

    def test_declared_but_absent_read_names_the_producer_gap(self):
        store = Artifacts()
        view = store.view('p', frozenset({'absent'}), frozenset())

        with pytest.raises(MissingArtifact) as exc:
            view['absent']

        assert 'no earlier pass produced' in str(exc.value)

    def test_optional_read_falls_back_instead_of_failing(self):
        store = Artifacts()
        view = store.view('p', frozenset(), frozenset(),
                          optional=frozenset({'maybe'}))

        assert view.get('maybe', 'default') == 'default'

    def test_store_records_which_pass_produced_each_key(self):
        store = Artifacts()
        store.view('producer', frozenset(), frozenset({'k'}))['k'] = 1

        assert store.producer_of('k') == 'producer'

    def test_view_reports_what_the_pass_actually_wrote(self):
        store = Artifacts()
        view = store.view('p', frozenset(), frozenset({'a', 'b'}))
        view['a'] = 1

        assert view.written == frozenset({'a'})


# ── ordering ──────────────────────────────────────────────────────────────

class TestOrdering:
    """Order is derived from declarations, never from a maintained list."""

    def test_producer_runs_before_consumer(self):
        consumer = simple_pass('consumer', reads=['x'], writes=['y'])
        producer = simple_pass('producer', writes=['x'])

        order = [p.name for p in Pipeline([consumer, producer]).order()]

        assert order == ['producer', 'consumer']

    def test_chain_of_three_resolves(self):
        c = simple_pass('c', reads=['b'], writes=['out'])
        a = simple_pass('a', writes=['a_out'])
        b = simple_pass('b', reads=['a_out'], writes=['b'])

        order = [p.name for p in Pipeline([c, a, b]).order()]

        assert order == ['a', 'b', 'c']

    def test_phase_breaks_ties_between_independent_passes(self):
        late = simple_pass('late', writes=['l'], phase=Phase.EMIT)
        early = simple_pass('early', writes=['e'], phase=Phase.ANALYZE)

        order = [p.name for p in Pipeline([late, early]).order()]

        assert order == ['early', 'late']

    def test_after_orders_passes_that_share_no_artifact(self):
        second = simple_pass('second', writes=['s'], after=['first'])
        first = simple_pass('first', writes=['f'])

        order = [p.name for p in Pipeline([second, first]).order()]

        assert order == ['first', 'second']

    def test_seeded_artifacts_satisfy_reads(self):
        p = simple_pass('p', reads=['preloaded'], writes=['out'])

        order = Pipeline([p]).order(seeded={'preloaded'})

        assert [q.name for q in order] == ['p']

    def test_unsatisfied_read_is_reported_with_the_key(self):
        p = simple_pass('p', reads=['nobody_writes_this'], writes=['out'])

        with pytest.raises(UnsatisfiedDependency) as exc:
            Pipeline([p]).order()

        assert 'nobody_writes_this' in str(exc.value)

    def test_cycle_is_reported_with_the_passes_involved(self):
        a = simple_pass('a', reads=['from_b'], writes=['from_a'])
        b = simple_pass('b', reads=['from_a'], writes=['from_b'])

        with pytest.raises(CyclicDependency) as exc:
            Pipeline([a, b]).order()

        assert 'a' in exc.value.cycle and 'b' in exc.value.cycle

    def test_order_is_deterministic(self):
        passes = [simple_pass(n, writes=[n]) for n in 'fedcba']

        first = [p.name for p in Pipeline(list(passes)).order()]
        second = [p.name for p in Pipeline(list(reversed(passes))).order()]

        assert first == second == sorted('abcdef')


# ── execution ─────────────────────────────────────────────────────────────

class TestExecution:

    def test_artifacts_flow_from_one_pass_to_the_next(self):
        def produce(ctx, art):
            art['value'] = 21
            return PassResult.applied()

        def consume(ctx, art):
            art['doubled'] = art['value'] * 2
            return PassResult.applied()

        pipeline = Pipeline([
            FunctionPass('consume', consume, reads=['value'], writes=['doubled']),
            FunctionPass('produce', produce, writes=['value']),
        ])
        ctx = make_context()

        result = pipeline.run(ctx)

        assert ctx.artifacts.get('doubled') == 42
        assert result.changed_passes() == ['produce', 'consume']

    def test_a_failing_pass_is_named_in_the_error(self):
        def boom(ctx, art):
            raise ValueError('inner detail')

        pipeline = Pipeline([FunctionPass('exploding', boom)])

        with pytest.raises(PassError) as exc:
            pipeline.run(make_context())

        assert 'exploding' in str(exc.value)
        assert 'inner detail' in str(exc.value)

    def test_stop_after_halts_the_run(self):
        """Bisecting a bad output means stopping at a chosen pass."""
        pipeline = Pipeline([
            simple_pass('one', writes=['a']),
            simple_pass('two', reads=['a'], writes=['b']),
            simple_pass('three', reads=['b'], writes=['c']),
        ])
        ctx = make_context()
        ctx.options = Options(stop_after='two')

        result = pipeline.run(ctx)

        assert result.stopped_at == 'two'
        assert len(result.records) == 2
        assert 'c' not in ctx.artifacts

    def test_records_capture_timing_and_effect(self):
        pipeline = Pipeline([simple_pass('p', writes=['x'])])

        result = pipeline.run(make_context())
        record = result.record_for('p')

        assert record.changed
        assert record.wrote == frozenset({'x'})
        assert record.seconds >= 0

    def test_counts_reach_diagnostics(self):
        def counted(ctx, art):
            return PassResult.applied(count=17)

        ctx = make_context()
        Pipeline([FunctionPass('repair', counted)]).run(ctx)

        assert ctx.diagnostics.counters['repair'] == 17

    def test_function_pass_accepts_a_plain_int(self):
        pipeline = Pipeline([FunctionPass('n', lambda ctx, art: 5)])

        result = pipeline.run(make_context())

        assert result.record_for('n').result.count == 5


# ── registry and image matching ───────────────────────────────────────────

class TestRegistry:

    def test_duplicate_names_are_rejected(self):
        reg = PassRegistry()
        reg.add(simple_pass('dup'))

        with pytest.raises(RegistryError, match='already registered'):
            reg.add(simple_pass('dup'))

    def test_unknown_name_lists_what_is_available(self):
        reg = PassRegistry()
        reg.add(simple_pass('known'))

        with pytest.raises(RegistryError, match='known'):
            reg.get('missing')

    def test_sha256_matcher_selects_one_build_only(self):
        """An address-pinned repair is only valid for the bytes it came from."""
        reg = PassRegistry()
        ctx = make_context(b'the real binary')
        reg.add(simple_pass('quirk', writes=['q'], phase=Phase.QUIRK),
                by_sha256(ctx.identity.sha256))

        assert [p.name for p in reg.selected_for(ctx)] == ['quirk']
        assert reg.selected_for(make_context(b'a different binary')) == []

    def test_export_matcher_selects_a_family(self):
        reg = PassRegistry()
        reg.add(simple_pass('native', writes=['n']),
                by_export('NtCreateFile'))

        ntdll = make_context(b'x', exports=['NtCreateFile', 'NtClose'])
        plain = make_context(b'y', exports=['main'])

        assert len(reg.selected_for(ntdll)) == 1
        assert reg.selected_for(plain) == []

    def test_kind_matcher_selects_ring0_images(self):
        reg = PassRegistry()
        reg.add(simple_pass('ssdt', writes=['s']), by_kind(ImageKind.KERNEL))

        kernel = make_context(b'k', kind=ImageKind.KERNEL)
        user = make_context(b'u', kind=ImageKind.EXECUTABLE)

        assert len(reg.selected_for(kernel)) == 1
        assert reg.selected_for(user) == []

    def test_linker_matcher_selects_a_toolchain(self):
        reg = PassRegistry()
        reg.add(simple_pass('vc6', writes=['v']), by_linker(6))

        vc6 = make_context(b'a', linker_version=(6, 0))
        vc7 = make_context(b'b', linker_version=(7, 10))

        assert len(reg.selected_for(vc6)) == 1
        assert reg.selected_for(vc7) == []

    def test_matchers_combine(self):
        reg = PassRegistry()
        reg.add(simple_pass('combined', writes=['c']),
                all_of(by_kind(ImageKind.NATIVE_DLL), by_export('NtClose')))

        good = make_context(b'a', kind=ImageKind.NATIVE_DLL,
                            exports=['NtClose'])
        wrong_kind = make_context(b'b', kind=ImageKind.DLL,
                                  exports=['NtClose'])

        assert len(reg.selected_for(good)) == 1
        assert reg.selected_for(wrong_kind) == []

    def test_pure_mode_drops_every_quirk(self):
        """``--pure`` means the general engine only, with no pinned repairs."""
        reg = PassRegistry()
        reg.add(simple_pass('general', writes=['g'], phase=Phase.TRANSLATE))
        reg.add(simple_pass('pinned', writes=['p'], phase=Phase.QUIRK))

        normal = reg.selected_for(make_context(pure=False))
        pure = reg.selected_for(make_context(pure=True))

        assert {p.name for p in normal} == {'general', 'pinned'}
        assert {p.name for p in pure} == {'general'}

    def test_applies_to_can_veto_per_image(self):
        class Conditional(Pass):
            name = 'conditional'
            writes = frozenset({'c'})

            def applies_to(self, ctx):
                return ctx.source.identity.size > 100

            def run(self, ctx, art):
                art['c'] = True
                return PassResult.applied()

        reg = PassRegistry()
        reg.add(Conditional())

        assert reg.selected_for(make_context(b'x' * 200))
        assert not reg.selected_for(make_context(b'x' * 10))

    def test_a_new_pass_needs_no_engine_change(self):
        """The extensibility claim, stated as a test.

        Registering a pass is enough: the pipeline picks it up and places it
        by its declarations.
        """
        reg = PassRegistry()
        reg.add(simple_pass('existing', writes=['base']))
        ctx = make_context()

        before = Pipeline.for_context(ctx, reg).order()

        reg.add(simple_pass('added_later', reads=['base'], writes=['more']))
        after = Pipeline.for_context(ctx, reg).order()

        assert [p.name for p in before] == ['existing']
        assert [p.name for p in after] == ['existing', 'added_later']


# ── context ───────────────────────────────────────────────────────────────

class TestContext:

    def test_identity_is_content_addressed_not_name_based(self):
        same_bytes_a = make_context(b'payload', name='a.exe').identity
        same_bytes_b = make_context(b'payload', name='b.exe').identity

        assert same_bytes_a.sha256 == same_bytes_b.sha256

    def test_kernel_target_moves_the_base_into_kernel_space(self):
        kernel = TargetSpec().for_kernel()

        assert kernel.image_base == 0xFFFFF80000000000
        assert not kernel.dynamic_base

    def test_ring0_kinds_are_flagged(self):
        assert ImageKind.KERNEL.is_ring0
        assert ImageKind.DRIVER.is_ring0
        assert not ImageKind.EXECUTABLE.is_ring0
        assert not ImageKind.NATIVE_DLL.is_ring0

    def test_pure_env_var_disables_quirks(self):
        assert Options.from_env({'PURE': '1'}).enable_quirks is False
        assert Options.from_env({}).enable_quirks is True

    def test_legacy_env_var_names_still_work(self):
        for var in ('PURE', 'CMD_NO_HACKS', 'PURE_TRANSLATOR'):
            assert Options.from_env({var: '1'}).pure, var

    def test_source_and_target_are_frozen(self):
        ctx = make_context()

        with pytest.raises(Exception):
            ctx.source.data = b'replaced'
        with pytest.raises(Exception):
            ctx.target.image_base = 0


# ── diagnostics ───────────────────────────────────────────────────────────

class TestDiagnostics:
    """Findings are queryable, so tests can assert a repair actually fired."""

    def test_entries_are_filterable_by_pass_and_severity(self):
        d = Diagnostics()
        d.info('a', 'fine')
        d.warning('b', 'suspicious')
        d.error('b', 'broken')

        assert len(d.by_pass('b')) == 2
        assert len(d.by_severity(Severity.ERROR)) == 1
        assert not d.ok

    def test_rva_is_carried_through_to_the_rendered_line(self):
        d = Diagnostics()
        entry = d.warning('repair', 'unresolved branch', rva=0x401000)

        assert '0x401000' in entry.render()

    def test_counters_accumulate(self):
        d = Diagnostics()
        d.count('fixups', 3)
        d.count('fixups', 4)

        assert d.counters['fixups'] == 7

    def test_clean_run_reports_ok(self):
        d = Diagnostics()
        d.info('p', 'did a thing')

        assert d.ok
