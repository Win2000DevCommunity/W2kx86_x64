"""Relocatable object model and linker -- the framework's address authority.

Nothing outside this package should compute a final address by hand.  Emitters
record symbols and relocations; :class:`~x86x64.core.linker.Linker` decides
where things live and writes the bytes.
"""

from .linker import (
    DEFAULT_FILE_ALIGN,
    DEFAULT_SECTION_ALIGN,
    DEFAULT_SECTION_ORDER,
    Layout,
    LinkResult,
    Linker,
    PlacedSection,
    align_up,
    build_base_reloc_blocks,
)
from .objfile import ObjectFile, Section, SectionFlags
from .relocs import (
    IMAGE_REL_BASED_ABSOLUTE,
    IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGHLOW,
    Relocation,
    RelocKind,
    apply_relocation,
    base_reloc_type,
    compute_value,
    encode_value,
)
from .symbols import Symbol, SymbolKind, SymbolTable, import_symbol_name

__all__ = [
    'DEFAULT_FILE_ALIGN', 'DEFAULT_SECTION_ALIGN', 'DEFAULT_SECTION_ORDER',
    'IMAGE_REL_BASED_ABSOLUTE', 'IMAGE_REL_BASED_DIR64', 'IMAGE_REL_BASED_HIGHLOW',
    'Layout', 'LinkResult', 'Linker', 'ObjectFile', 'PlacedSection',
    'RelocKind', 'Relocation', 'Section', 'SectionFlags', 'Symbol',
    'SymbolKind', 'SymbolTable', 'align_up', 'apply_relocation',
    'base_reloc_type', 'build_base_reloc_blocks', 'compute_value',
    'encode_value', 'import_symbol_name',
]
