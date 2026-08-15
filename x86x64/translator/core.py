"""The translator itself, composed from the domain mixins.

The mixins are split purely by subject matter; they all operate on
the state this class sets up in ``__init__``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403
from ._frame import FrameMixin
from ._analysis import AnalysisMixin
from ._iat import IatMixin
from ._encoding import EncodingMixin
from ._image import ImageBuilderMixin
from ._quirks_cmd import CmdQuirksMixin
from ._function import FunctionTranslationMixin
from ._healing import HealingMixin
from ._seh import SehMixin
from ._ubrt import UbrtMixin
from ._misc import MiscMixin


class Win2000Translator(
        FrameMixin,
        AnalysisMixin,
        IatMixin,
        EncodingMixin,
        ImageBuilderMixin,
        CmdQuirksMixin,
        FunctionTranslationMixin,
        HealingMixin,
        SehMixin,
        UbrtMixin,
        MiscMixin,
):
    """
    Translate a Win2000 SP4 PE32 binary to a Win64-compatible PE64.

    The translation has four passes:

    Pass A — Identify all NTDLL syscall stubs and their Win10 x64 equivalents.

    Pass B — Disassemble all .text sections with Capstone. For each function:
      • Detect calling convention (stdcall: ends in RET N; cdecl: ends in RET)
      • Detect FS: segment accesses (TEB reads/writes)
      • Detect SEH prolog/epilog patterns
      • Detect CALL targets (for cross-module pointer fixup)
      • Detect data pointer immediates (for relocation)

    Pass C — Translate each function:
      • NTDLL stubs → 3-instruction Win64 syscall wrapper
      • stdcall/cdecl → Windows x64 ABI (args in registers)
      • Branches → fixed-up 64-bit relative branches
      • FS:[n] → GS:[teb64_offset(n)]
      • 32-bit pointer immediates → relocated 64-bit addresses

    Pass D — Emit PE64 with rebuilt IAT, export table, and .reloc section.
    """

    _ALIGN_WRAP = b'\x41\x55\x49\x89\xe5\x48\x83\xec\x20\x48\x83\xe4\xf0'



    def __init__(self, pe: PE32Image, is_ntdll: bool = False,
                 is_kernel: bool = False,
                 dynamic_result: Optional[DynamicScanResult] = None,
                 verbose: bool = False,
                 win10_test_shim: bool = False,
                 source_path: Optional[str] = None):
        if not HAS_CAPSTONE:
            raise RuntimeError("capstone required")
        if not HAS_KEYSTONE:
            raise RuntimeError("keystone required")
        self.pe       = pe
        self.is_ntdll = is_ntdll
        self.is_kernel = is_kernel
        self.dyn      = dynamic_result or DynamicScanResult()
        self.verbose  = verbose
        self.win10_test_shim = win10_test_shim
        self.ks       = Ks(KS_ARCH_X86, KS_MODE_64)
        self.md       = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.stubs: Dict[int, StubInfo] = {}
        self.rva_map: Dict[int, int] = {}
        self._rva_section: Dict[int, int] = {}
        self.fixup_queue: List[Tuple[int,int,str]] = []
        self.warnings: List[str] = []
        self.pe_relocs = pe.parse_relocations()
        self.text_rva = 0
        self._kernel_code: List[Tuple[str, bytes, int, int, int]] = []
        self._final_rva: Dict[int, int] = {}
        self._old_to_new_section: Dict[int, int] = {}
        self._translated_text = b''
        self._text_sec_meta: Dict = {}
        # General prologue callee-save fix (correct, but shifts addresses and
        # desyncs the legacy _fix_cmd_* hack layer). Enable via CMD_PROLOGUE_SAVE_FIX.
        self._prologue_save_fix = bool(os.environ.get('CMD_PROLOGUE_SAVE_FIX'))
        # De-hacking: skip the address-pinned _fix_cmd_* hack layer to bring up
        # the pure core translation. Implies prologue-save fix on.
        # Enabled via --pure or CMD_NO_HACKS / PURE / PURE_TRANSLATOR env.
        self._cmd_no_hacks = _pure_translator_mode()
        _dbgenv = os.environ.get('CMD_DBG_RVA', '')
        self._dbg_rva = int(_dbgenv, 16) if _dbgenv else None
        if self._cmd_no_hacks:
            self._prologue_save_fix = True
        # Defer ALL cross-chunk call/branch resolution to the final pass so they
        # resolve against the stable rva_map (avoids stale targets when a
        # function's entry is remapped after an early caller resolved it).
        # On in pure mode; gated to avoid disturbing the legacy hacked default.
        self._defer_cross_chunk = self._cmd_no_hacks or bool(
            os.environ.get('CMD_DEFER_CROSS_CHUNK'))

        self.old_base = pe.image_base
        # DLLs keep the high base; EXEs go below 4 GiB (see PE64_EXE_BASE) so
        # truncated 32-bit data pointers still resolve correctly.
        is_dll = bool(pe.characteristics & 0x2000)
        self.new_base = PE64_DEFAULT_BASE if is_dll else PE64_EXE_BASE
        self.source_path = source_path
        self._ubrt_ref_db = None
        self._iat_rva_map: Dict[int, int] = {}
        self._iat_name_to_new_rva: Dict[Tuple[str, str], int] = {}
        self._hint_rva_to_old_iat: Dict[int, int] = {}
        self._iat_old_rvas: Set[int] = set()
        self._iat_func_by_rva: Dict[int, str] = {}
        for imp in pe.parse_imports():
            for fn in imp['functions']:
                iat_rva = fn.get('iat_rva')
                if iat_rva:
                    self._iat_old_rvas.add(iat_rva)
                    name = fn.get('name') or ''
                    self._iat_func_by_rva[iat_rva] = name
        self._orphan_blob_out_ranges: List[Tuple[int, int]] = []
        self._code_span_ranges: List[Tuple[int, int]] = []
        self._scope_table_out_ranges: List[Tuple[int, int]] = []
        self._scope_table_old_rva: Dict[int, int] = {}
        self._fn_entry_rvas: Set[int] = set()
        self._seh_scope_anchors: Dict[int, int] = {}
        self._seh_scope_reg_fn: Dict[int, int] = {}
        self._call_target_offs: Optional[Set[int]] = None
        self._runtime_slot_map: Dict[int, int] = {}
        self._seh_eh3_handler_old_vas: Set[int] = set()
        self._w2k_eh3_va = (
            w2kshim_except_handler3_va()
            if win10_test_shim else 0)
        self._cmd_stdout_print_rva: Optional[int] = None
        self._cmd_interactive_startup_rva: Optional[int] = None
        self._x86_cf: Optional[X86TextAnalysis] = None
        self._pure_heal_text: Optional[bytes] = None
        self._pure_heal_text_rva: int = 0
        self._embedded_text_refs: Set[int] = set()
