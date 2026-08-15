"""Command-line entry points: single-file, batch, and whole-system builds.
"""

from __future__ import annotations

from x86x64.translator.runtime import *  # noqa: F401,F403
from x86x64.translator import Win2000Translator


class BatchTranslator:
    r"""
    Translate every PE32 binary under a Windows 2000 directory tree.

    Win2000 SP4 user-mode binaries live under:
      %SystemRoot%\system32\       — core DLLs, EXEs
      %SystemRoot%\system32\dllcache\ — cached DLLs
      %SystemRoot%\               — shell, explorer, etc.
      %SystemRoot%\system\        — 16-bit subsystem (skip)
      %ProgramFiles%\             — applications

    We skip:
      *.sys  — kernel drivers (require kernel-mode translation)
      *.drv  — driver modules (some are kernel mode)
      files in \system\ — 16-bit stubs

    Output tree mirrors the input tree under <out_dir>.
    A JSON report is written to <out_dir>/translation_report.json.
    """

    SKIP_EXTS   = {'.vxd', '.386'}   # .sys handled when include_drivers=True
    SKIP_EXTS_ALWAYS = {'.vxd', '.386'}
    SKIP_DIRS   = {'system', 'drivers', 'wins', 'mui', 'catroot', 'catroot2'}
    PE_EXTS     = {'.exe', '.dll', '.ocx', '.cpl', '.ax', '.acm', '.tlb', '.sys'}

    def __init__(self, src_dir: str, out_dir: str,
                 dynamic: bool = True, verbose: bool = False,
                 ntdll_ref: Optional[str] = None,
                 include_drivers: bool = False,
                 win10_test_shim: bool = False):
        self.src     = os.path.normpath(src_dir)
        self.out     = os.path.normpath(out_dir)
        self.dynamic = dynamic
        self.verbose = verbose
        self.ntdll_ref = ntdll_ref
        self.include_drivers = include_drivers
        self.win10_test_shim = win10_test_shim
        self.report  = {'translated': [], 'skipped': [], 'failed': [], 'drivers': []}

    def run(self) -> None:
        if _SYSCALL_TARGET == 'win10':
            auto_load_win10_syscall_table()
        if self.ntdll_ref and os.path.isfile(self.ntdll_ref):
            n = load_syscall_table_from_ntdll(self.ntdll_ref)
            print(f"[+] Loaded {n} syscall stubs from {self.ntdll_ref}")
        os.makedirs(self.out, exist_ok=True)
        if self.win10_test_shim:
            ensure_w2kshim_dll(self.out)
            print("[!] Win10 test shim ON — imports may use w2kshim64.dll "
                  "(not for production Win2000 x64)")
        if _pure_translator_mode():
            print("[+] Pure translator ON (universal, no cmd-specific hacks)")
        total = 0
        for root, dirs, files in os.walk(self.src):
            # Prune skip directories
            dirs[:] = [d for d in dirs
                       if d.lower() not in self.SKIP_DIRS]
            rel_root = os.path.relpath(root, self.src)
            out_root = os.path.join(self.out, rel_root)
            os.makedirs(out_root, exist_ok=True)

            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext == '.sys' and not self.include_drivers:
                    self.report['skipped'].append(os.path.join(rel_root, fname))
                    continue
                if ext in self.SKIP_EXTS_ALWAYS:
                    self.report['skipped'].append(os.path.join(rel_root, fname))
                    continue
                if ext not in self.PE_EXTS:
                    # Copy non-PE files verbatim (REG files, INI, etc.)
                    src_path = os.path.join(root, fname)
                    dst_path = os.path.join(out_root, fname)
                    try:
                        with open(src_path,'rb') as f:
                            d = f.read()
                        with open(dst_path,'wb') as f:
                            f.write(d)
                    except Exception:
                        pass
                    continue

                src_path = os.path.join(root, fname)
                dst_path = os.path.join(out_root, fname)
                total += 1
                print(f"\n[{total:4d}] {os.path.join(rel_root, fname)}")

                try:
                    self._translate_file(src_path, dst_path, fname)
                    entry = os.path.join(rel_root, fname)
                    self.report['translated'].append(entry)
                    if ext == '.sys':
                        self.report['drivers'].append(entry)
                except Exception as ex:
                    msg = f"  [FAILED] {ex}"
                    print(msg)
                    self.report['failed'].append({
                        'file': os.path.join(rel_root, fname),
                        'error': str(ex)
                    })
                    # Copy original as fallback
                    try:
                        with open(src_path,'rb') as f:
                            with open(dst_path,'wb') as g:
                                g.write(f.read())
                    except Exception:
                        pass

        # Write report
        report_path = os.path.join(self.out, 'translation_report.json')
        with open(report_path, 'w') as f:
            json.dump(self.report, f, indent=2)
        print(f"\n{'═'*60}")
        print(f"  Batch complete.")
        print(f"  Translated : {len(self.report['translated'])}")
        print(f"  Skipped    : {len(self.report['skipped'])}")
        print(f"  Failed     : {len(self.report['failed'])}")
        print(f"  Report     : {report_path}")
        print(f"{'═'*60}")

    def _translate_file(self, src: str, dst: str, fname: str) -> None:
        with open(src, 'rb') as f:
            data = f.read()

        # Quick PE check
        if data[:2] != b'MZ':
            # Not a PE — copy as-is
            with open(dst, 'wb') as f: f.write(data)
            print(f"  → Not PE, copied verbatim")
            return

        pe = PE32Image(data)
        if pe.machine != 0x014C:   # not i386
            with open(dst, 'wb') as f: f.write(data)
            print(f"  → Not i386 PE (machine=0x{pe.machine:04X}), copied verbatim")
            return

        is_ntdll = fname.lower() in ('ntdll.dll',)
        is_kernel = (fname.lower() in ('ntoskrnl.exe', 'hal.dll', 'halmacpi.dll')
                     or fname.lower().endswith('.sys'))
        dyn_result = DynamicScanResult()

        if self.dynamic:
            if not HAS_UNICORN:
                raise RuntimeError("Dynamic analysis is mandatory — install unicorn: pip install unicorn")
            print(f"  [dyn] Running Unicorn emulation (mandatory)…")
            stub_rvas = set()
            if is_ntdll:
                for s in extract_stubs_from_ntdll(pe):
                    stub_rvas.add(s.rva)
            scanner = DynamicScanner(pe, stub_rvas=stub_rvas)
            dyn_result = scanner.scan()
            print(f"  [dyn] {dyn_result.entries_emulated} entries, "
                  f"{dyn_result.blocks_executed} blocks, "
                  f"{len(dyn_result.visited_blocks)} visited RVAs, "
                  f"{len(dyn_result.call_targets)} call targets, "
                  f"{len(dyn_result.branch_targets)} branch targets, "
                  f"{len(dyn_result.pointer_values)} pointers, "
                  f"{len(dyn_result.pointer_writes)} write sites")

        translator = Win2000Translator(
            pe, is_ntdll=is_ntdll, is_kernel=is_kernel,
            dynamic_result=dyn_result,
            verbose=self.verbose,
            win10_test_shim=self.win10_test_shim,
            source_path=src,
        )
        pe64_data = translator.translate()

        with open(dst, 'wb') as f:
            f.write(pe64_data)
        if self.win10_test_shim and os.path.basename(src).lower() == 'cmd.exe':
            ubrt_n = translator._cmd_shim_ubrt_fixup(dst)
            if ubrt_n:
                print(f"  UBRT cmd shim fixups: {ubrt_n}")
        print(f"  → {len(data):,} B  →  {len(pe64_data):,} B  ({dst})")
class SystemBuilder:
    """
    Build a Win2000 SP4 → x86-64 system tree from a flat SP4 install folder.
    Translates all PE32 binaries, copies everything else, writes a manifest.
    """

    def __init__(self, sp4_root: str, out_root: str,
                 dynamic: bool = True, verbose: bool = False,
                 include_drivers: bool = False,
                 win10_test_shim: bool = False):
        self.sp4_root = os.path.normpath(sp4_root)
        self.out_root = os.path.normpath(out_root)
        self.dynamic = dynamic
        self.verbose = verbose
        self.include_drivers = include_drivers
        self.win10_test_shim = win10_test_shim
        self.ntdll_ref = os.path.join(self.sp4_root, 'ntdll.dll')
        if not os.path.isfile(self.ntdll_ref):
            alt = os.path.join(self.sp4_root, 'uniproc', 'ntdll.dll')
            if os.path.isfile(alt):
                self.ntdll_ref = alt

    def build(self) -> None:
        print(f"\n{'='*70}")
        print(f"  Win2000 SP4 → x86-64 System Base Builder")
        print(f"  Source : {self.sp4_root}")
        print(f"  Output : {self.out_root}")
        print(f"  Syscall target: {_SYSCALL_TARGET}")
        print(f"  Import shim   : {'win10-test (w2kshim64.dll)' if self.win10_test_shim else 'OFF (native Win2000 imports)'}")
        print(f"  Pure translator: {'ON' if _pure_translator_mode() else 'OFF'}")
        print(f"{'='*70}")
        if _SYSCALL_TARGET == 'win10':
            auto_load_win10_syscall_table()
        if os.path.isfile(self.ntdll_ref):
            load_syscall_table_from_ntdll(self.ntdll_ref)
        os.makedirs(self.out_root, exist_ok=True)
        bt = BatchTranslator(self.sp4_root, self.out_root,
                           dynamic=self.dynamic, verbose=self.verbose,
                           ntdll_ref=self.ntdll_ref,
                           include_drivers=self.include_drivers,
                           win10_test_shim=self.win10_test_shim)
        bt.run()
        manifest = os.path.join(self.out_root, 'win2000_x64_manifest.json')
        syscall_json = os.path.join(self.out_root, 'win2000_x64_syscalls.json')
        if os.path.isfile(self.ntdll_ref):
            with open(self.ntdll_ref, 'rb') as f:
                export_syscall_table_json(syscall_json, PE32Image(f.read()))
            print(f"  Syscall table: {syscall_json}")
        mapped, total, unmapped = count_syscall_coverage()
        with open(manifest, 'w', encoding='utf-8') as f:
            json.dump({
                'source': self.sp4_root,
                'output': self.out_root,
                'syscall_target': _SYSCALL_TARGET,
                'win10_test_shim': self.win10_test_shim,
                'pure_translator': _pure_translator_mode(),
                'translated': len(bt.report['translated']),
                'skipped': len(bt.report['skipped']),
                'failed': len(bt.report['failed']),
                'syscalls_mapped': mapped,
                'syscalls_total': total,
                'syscalls_unmapped': unmapped,
                'drivers_translated': len(bt.report.get('drivers', [])),
                'core_files': list(CORE_SYSTEM_FILES),
            }, f, indent=2)
        print(f"\n  Manifest: {manifest}")
        if _SYSCALL_TARGET == 'win2000':
            print(f"  Syscalls: {total} Win2000 indices (native x64 SSDT numbering)")
        else:
            print(f"  Syscalls mapped: {mapped}/{total} ({len(unmapped)} Win2000-only/removed)")
def main() -> None:
    ap = argparse.ArgumentParser(
        description='Windows 2000 SP4 x86 → x86-64 Binary Translator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Translate ntdll.dll and show syscall table:
  python3 win2000_64.py --dump-syscalls ntdll.dll

  # Translate a single binary:
  python3 win2000_64.py ntdll.dll ntdll64.dll

  # Batch-translate entire Win2000 system32:
  python3 win2000_64.py --batch /mnt/win2k/windows/system32 ./out64/

  # Production Win2000 x64 tree (native imports, no Win10 shim):
  python3 x86_x64.py --build-system /path/sp4 /path/win2000_x64

  # Dev-only: smoke-test on Win10 host (adds w2kshim64.dll import redirects):
  python3 x86_x64.py cmd.exe cmd64.exe --win10-test-shim

  # Universal pure translator (all Win2000 binaries, no cmd-specific hacks):
  python3 x86_x64.py cmd.exe cmd_pure.exe --pure --win10-test-shim
        """)
    ap.add_argument('input',  nargs='?', help='Input PE32 binary (or directory with --batch)')
    ap.add_argument('output', nargs='?', help='Output PE64 binary (or directory with --batch)')
    ap.add_argument('--batch',        action='store_true', help='Batch mode: translate entire directory tree')
    ap.add_argument('--build-system', action='store_true',
                    help='Build full x64 system tree from SP4 install folder')
    ap.add_argument('--include-drivers', action='store_true',
                    help='Translate kernel .sys drivers (experimental, not boot-ready)')
    ap.add_argument('--static-only',  action='store_true',
                    help='Skip mandatory dynamic analysis (not recommended)')
    ap.add_argument('--dynamic', '-d', action='store_true',
                    help=argparse.SUPPRESS)  # legacy alias; dynamic is now default
    ap.add_argument('--dump-syscalls',action='store_true', help='Dump syscall table from ntdll.dll and exit')
    ap.add_argument('--export-syscalls', metavar='PATH',
                    help='Write Win2000 syscall table JSON (use with --ntdll-ref or input ntdll)')
    ap.add_argument('--pure', action='store_true',
                    help='Universal pure translator for all binaries (no address-pinned '
                         'cmd hacks). Same as CMD_NO_HACKS=1 / PURE=1.')
    ap.add_argument('--win10-test-shim', action='store_true',
                    help='Dev-only: redirect missing Win10 imports to w2kshim64.dll '
                         '(NOT for production Win2000 x64 builds)')
    ap.add_argument('--syscall-target', choices=('win2000', 'win10'), default='win2000',
                    help='ntdll stub syscall index: win2000=native SSDT (default), '
                         'win10=Win10 numbering for host testing (separate from --win10-test-shim)')
    ap.add_argument('--verbose', '-v',action='store_true', help='Verbose translation output')
    ap.add_argument('--win64-table',  help='JSON file overriding Win10 x64 syscall numbers')
    ap.add_argument('--ntdll-ref',    help='Path to Win2000 ntdll.dll for live syscall extraction')
    args = ap.parse_args()

    if args.pure:
        os.environ['CMD_NO_HACKS'] = '1'

    # Pure mode defaults to static analysis: mandatory Unicorn emulation
    # discovers ~3× more entry points and the heal pass produces broken
    # duplicate copies (cmd 0x14E07 → crash at ~669 steps).  Pass --dynamic
    # to opt in; --static-only always wins.
    if args.static_only:
        use_dynamic = False
    elif args.pure and not args.dynamic:
        use_dynamic = False
    else:
        use_dynamic = True
    set_syscall_target(args.syscall_target)
    if args.syscall_target == 'win10':
        auto_load_win10_syscall_table()

    # Load optional Win10 x64 override table
    if args.win64_table:
        with open(args.win64_table, encoding='utf-8') as f:
            overrides = json.load(f)
        apply_win10_syscall_map({k: int(v) for k, v in overrides.items()})
        print(f"[+] Applied {len(overrides)} Win10 x64 overrides from {args.win64_table}")

    if args.dump_syscalls:
        if not args.input:
            print("Error: --dump-syscalls requires an input ntdll.dll path")
            sys.exit(1)
        data = open(args.input, 'rb').read()
        pe   = PE32Image(data)
        dump_syscall_table(pe)
        return

    if args.export_syscalls:
        ntdll_path = args.ntdll_ref or args.input
        if not ntdll_path or not os.path.isfile(ntdll_path):
            print("Error: --export-syscalls requires --ntdll-ref or input ntdll.dll path")
            sys.exit(1)
        with open(ntdll_path, 'rb') as f:
            pe = PE32Image(f.read())
        load_syscall_table_from_ntdll(ntdll_path)
        n = export_syscall_table_json(args.export_syscalls, pe)
        print(f"[+] Exported {n} syscalls ({args.syscall_target} target) → {args.export_syscalls}")
        return

    if not args.input:
        ap.print_help()
        sys.exit(0)

    if not (HAS_CAPSTONE and HAS_KEYSTONE):
        print("\nRequired packages not installed. Install with:")
        print("  pip install capstone keystone-engine unicorn\n")
        sys.exit(1)

    if use_dynamic and not HAS_UNICORN:
        print("\nDynamic analysis is mandatory. Install Unicorn:")
        print("  pip install unicorn")
        print("  Or pass --static-only to skip (not recommended)\n")
        sys.exit(1)

    # Auto-detect ntdll reference for syscall table refresh
    ntdll_ref = args.ntdll_ref
    if not ntdll_ref and args.input:
        candidate = os.path.join(os.path.dirname(os.path.abspath(args.input)), 'ntdll.dll')
        if os.path.isfile(candidate):
            ntdll_ref = candidate
    if ntdll_ref and os.path.isfile(ntdll_ref):
        n = load_syscall_table_from_ntdll(ntdll_ref)
        print(f"[+] Loaded {n} syscall stubs from {ntdll_ref}")

    if args.build_system:
        if not args.input:
            print("Error: --build-system requires SP4 install folder path")
            sys.exit(1)
        out = args.output or os.path.join(
            os.path.dirname(os.path.abspath(args.input)), 'win2000_x64')
        sb = SystemBuilder(args.input, out, dynamic=use_dynamic, verbose=args.verbose,
                          include_drivers=args.include_drivers,
                          win10_test_shim=args.win10_test_shim)
        sb.build()
    elif args.batch:
        bt = BatchTranslator(args.input, args.output or './win2000_64_out',
                             dynamic=use_dynamic, verbose=args.verbose,
                             ntdll_ref=ntdll_ref, include_drivers=args.include_drivers,
                             win10_test_shim=args.win10_test_shim)
        bt.run()
    else:
        if not args.output:
            print("Error: output path required"); sys.exit(1)
        data = open(args.input, 'rb').read()
        pe   = PE32Image(data)
        print(f"\n{'='*60}")
        print(f"  Win2000 SP4 -> PE64 Translator")
        print(f"  Input : {args.input} ({len(data):,} bytes)")
        print(f"  Import shim: {'win10-test' if args.win10_test_shim else 'OFF (native Win2000)'}")
        print(f"  Pure mode  : {'ON' if _pure_translator_mode() else 'OFF'}")
        print(f"{'='*60}")
        is_ntdll = os.path.basename(args.input).lower() == 'ntdll.dll'
        is_kernel = os.path.basename(args.input).lower() in ('ntoskrnl.exe', 'hal.dll', 'halmacpi.dll') or args.input.lower().endswith('.sys')
        dyn_result = DynamicScanResult()
        if use_dynamic:
            print(f"\n[dyn] Running Unicorn emulation (mandatory)…")
            stub_rvas = set()
            if is_ntdll:
                for s in extract_stubs_from_ntdll(pe):
                    stub_rvas.add(s.rva)
            scanner = DynamicScanner(pe, stub_rvas=stub_rvas)
            dyn_result = scanner.scan()
            print(f"[dyn] {dyn_result.entries_emulated} entries, "
                  f"{dyn_result.blocks_executed} blocks, "
                  f"{len(dyn_result.visited_blocks)} visited RVAs, "
                  f"{len(dyn_result.call_targets)} call targets, "
                  f"{len(dyn_result.branch_targets)} branch targets, "
                  f"{len(dyn_result.pointer_values)} pointers, "
                  f"{len(dyn_result.pointer_writes)} write sites")
        translator = Win2000Translator(pe, is_ntdll=is_ntdll, is_kernel=is_kernel,
                                       dynamic_result=dyn_result,
                                       verbose=args.verbose,
                                       win10_test_shim=args.win10_test_shim,
                                       source_path=args.input)
        pe64 = translator.translate()
        if args.win10_test_shim:
            out_dir = os.path.dirname(os.path.abspath(args.output)) or '.'
            ensure_w2kshim_dll(out_dir)
            print(f"  [!] w2kshim64.dll written beside output (Win10 dev-test only)")
        with open(args.output, 'wb') as f:
            f.write(pe64)
        if args.win10_test_shim and os.path.basename(args.input).lower() == 'cmd.exe':
            ubrt_n = translator._cmd_shim_ubrt_fixup(args.output)
            if ubrt_n:
                print(f"  UBRT cmd shim fixups: {ubrt_n}")
        print(f"\n  Output: {args.output} ({len(pe64):,} bytes)")

        # A build that finishes is not the same as a build that loads. Check
        # the invariants the loader checks, on the bytes actually on disk --
        # post-write fixups run above and can break what translate() returned.
        from x86x64.pe import validate_file
        report = validate_file(args.output)
        for finding in report.findings:
            print(f"  [{'X' if finding.is_error else '!'}] {finding.code}: "
                  f"{finding.message}")
        if not report.ok:
            print(f"  [X] {args.output} will be refused by the loader "
                  f"(ERROR_BAD_EXE_FORMAT)")
        print(f"{'='*60}\n")
        if not report.ok:
            sys.exit(1)


__all__ = [
    'BatchTranslator',
    'SystemBuilder',
    'main',
]
