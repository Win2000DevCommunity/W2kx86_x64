"""Rewrites a PE32 import directory into its PE64 form.
"""

from __future__ import annotations

from x86x64.translator._env import *  # noqa: F401,F403

# Compute correct import hints for w2kshim64 exports.
# The hint is the zero-based index of the export name in the sorted
# export name pointer table.  A wrong hint forces the Windows loader
# into binary-search code paths that can misresolve (observed on Win10:
# hint=0 for __p__fmode resolves to towupper — ordinal off-by-one).
#
# The full export table includes DllMain (always present) plus every
# name in IMPORT_SHIM_EXPORTS. CriticalSection stubs, VirtualQuery etc.
# are present in modern builds and must be included.
_SHIM_ALL_EXPORTS = sorted({'DllMain'} | set(IMPORT_SHIM_EXPORTS.values()))
_SHIM_HINT_MAP = {name: idx for idx, name in enumerate(_SHIM_ALL_EXPORTS)}

# Ordinal import bypass: instead of name-based imports (which the Windows
# loader can misresolve due to binary-search issues), import shim functions
# by their ordinal number.  The ordinal is the 1-based index into the
# shim's function table — stable because the shim builder assigns ordinals
# explicitly (see builder.py: ``func_idx + 1``).
#
# Keyed by (dll_lower, function_name) → ordinal_number.
_SHIM_ORDINAL_MAP: Dict[Tuple[str, str], int] = {}
# Build a reverse map: export_name → function_table_index + 1
# The shim builder assigns ordinals in export_names list order.
_SHIM_EXPORT_NAMES_ORDERED = [
    'DllMain', 'InterlockedExchange',
    '_setjmp3', 'longjmp',
    '_except_handler3', '_seh_longjmp_unwind',
    '_adjust_fdiv', '__p___initenv',
    '__p__commode', '__p__fmode',
    'towupper', 'towlower',
    'VirtualQuery', '_get_osfhandle', 'GetVDMCurrentDirectories',
    'InitializeCriticalSection', 'EnterCriticalSection',
    'LeaveCriticalSection', 'DeleteCriticalSection',
]
for _idx, _nm in enumerate(_SHIM_EXPORT_NAMES_ORDERED):
    _SHIM_ORDINAL_MAP[('w2kshim64.dll', _nm)] = _idx + 1


def _shim_export_hint(name: str) -> int:
    """Return the correct import hint for *name* in w2kshim64's export table."""
    return _SHIM_HINT_MAP.get(name, 0)


def transform_imports(imports: List[Dict]) -> List[Dict]:
    """
    Win10 dev-test only: rewrite imports for smoke tests on modern Windows.

    Production Win2000 x64 builds must NOT call this — they keep original
    kernel32.dll / msvcrt.dll imports and rely on translated system DLLs.
    """
    by_dll: Dict[str, List[Dict]] = {}

    def _add(dll: str, fn: Dict) -> None:
        by_dll.setdefault(dll, []).append(fn)

    for imp in imports:
        dll = imp['dll']
        for fn in imp['functions']:
            name = fn.get('name')
            if not name:
                _add(dll, fn)
                continue
            key = (dll.lower(), name)
            if key in IMPORT_ALIASES:
                new_dll, new_name = IMPORT_ALIASES[key]
                patched = dict(fn)
                patched['name'] = new_name
                patched['hint'] = 0
                patched.pop('ordinal', None)
                _add(new_dll, patched)
            elif key in IMPORT_SHIM_EXPORTS:
                shim_name = IMPORT_SHIM_EXPORTS[key]
                shim_ord = _SHIM_ORDINAL_MAP.get((W2KSHIM_DLL_NAME, shim_name))
                if shim_ord is not None:
                    # Import by ordinal — bypasses the loader's name-lookup
                    # binary search which can misresolve on some Windows versions
                    # (observed: __p__fmode resolves to towupper despite correct
                    # hint, name, and export table).
                    #
                    # IMPORTANT: preserve the original iat_rva so the translator
                    # can map x86 IAT slots to x64 IAT slots.  Without it the
                    # mapping is silently dropped and x86 calls to shim functions
                    # end up calling unrelated MSVCRT functions (e.g. __p__commode
                    # → _ultoa).
                    patched = {
                        'ordinal': shim_ord,
                        'iat_rva': fn.get('iat_rva', 0),
                    }
                else:
                    patched = dict(fn)
                    patched['name'] = shim_name
                    patched['hint'] = _shim_export_hint(shim_name)
                    patched.pop('ordinal', None)
                _add(W2KSHIM_DLL_NAME, patched)
            elif key in IMPORT_RENAMES:
                # In-place rename: same DLL, different function name.
                # IAT slot stays at the same position.
                patched = dict(fn)
                patched['name'] = IMPORT_RENAMES[key]
                patched['hint'] = 0
                patched.pop('ordinal', None)
                _add(dll, patched)
            else:
                _add(dll, fn)

    return [{'dll': dll, 'functions': funcs,
             'iat_rva': 0, 'ilt_rva': 0}
            for dll, funcs in by_dll.items()]
