"""Import dispatch: IAT slots, call sites, and thunks.

Every call site here records a relocation instead of computing a distance, so
moving code or the import table does not invalidate a single emitted byte.
"""

from .iat import (
    DEFAULT_IMPORT_RENAMES,
    ImportRef,
    ImportTable,
    build_import_directory,
    emit_import_call,
    emit_import_fn_load,
    emit_import_jmp,
    emit_import_ptr_load,
    emit_thunk,
)

__all__ = [
    'DEFAULT_IMPORT_RENAMES', 'ImportRef', 'ImportTable',
    'build_import_directory', 'emit_import_call', 'emit_import_fn_load',
    'emit_import_jmp', 'emit_import_ptr_load', 'emit_thunk',
]
