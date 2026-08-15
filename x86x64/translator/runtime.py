"""Name resolution hub for the translation passes.

The passes were written against one flat module scope. Rather than
rewrite every reference, each pass does ``from .runtime import *``
and this module gathers the pieces back together from the domain
packages they now live in.
"""

from __future__ import annotations

from ._env import *  # noqa: F401,F403
from x86x64.abi.frames import (  # noqa: F401
    ebp_arg_slot_to_rbp_home,
    ebp_disp_to_rbp_home,
    ebp_disp_to_rbp_stack_off,
    ebp_disp_to_win64_arg,
)
from x86x64.analysis.discover import (  # noqa: F401
    _embedded_text_blob_size,
    _is_batch_helper_entry,
    _is_embedded_text_data_at,
    _is_nested_ebp_callee_save,
    _is_post_chkstk_callee_save,
    _is_wchar16le_text_at,
    _msvc_scope_table_size,
    _rva_inside_spans,
    _scope_table_spans,
    discover_crt_data_pointer_slots,
    discover_ff25_jmp_thunks,
    discover_function_rvas,
    discover_image_pointer_sites,
    discover_push_imm_text_data_refs,
    discover_seh_except_handler3_push_vas,
    discover_seh_scope_anchors,
    discover_seh_text_targets,
    discover_static_pointers,
)
from x86x64.analysis.dynamic import (  # noqa: F401
    DynamicScanResult,
    DynamicScanner,
)
from x86x64.analysis.text import (  # noqa: F401
    X86TextAnalysis,
    _collect_x86_branch_edges,
    _is_plausible_x86_insn_start,
    _merge_spans,
    _scan_x86_data_spans,
    _valid_x86_insn_rvas,
    _x64_bytes_for_x86_epilogue,
    analyze_x86_text_section,
)
from x86x64.dispatch.transform import (  # noqa: F401
    transform_imports,
)
from x86x64.pe.fixups import (  # noqa: F401
    fixup_data_section,
    fixup_rsrc_section,
    remap_image_va,
    remap_section_rva,
)
from x86x64.pe.image32 import (  # noqa: F401
    PE32Image,
)
from x86x64.shim.builder import (  # noqa: F401
    _shim_asm,
    build_w2kshim64_dll,
    ensure_w2kshim_dll,
)
from x86x64.syscall.legacy import (  # noqa: F401
    StubInfo,
    apply_win10_syscall_map,
    auto_load_win10_syscall_table,
    count_mapped_syscalls,
    count_syscall_coverage,
    dump_syscall_table,
    export_syscall_table_json,
    extract_stubs_from_ntdll,
    get_syscall_target,
    load_syscall_table_from_ntdll,
    resolve_syscall_nr,
    resolve_win10_syscall,
    set_syscall_target,
)

# Computed rather than listed: several names here are bound inside ``try``
# blocks that probe for optional dependencies, and the underscore-prefixed
# constants have to travel through ``import *`` as well.
__all__ = [_n for _n in dir() if not _n.startswith('__')]
