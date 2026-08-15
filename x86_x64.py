#!/usr/bin/env python3
"""
Win2000 SP4 x86 PE32 to native x64 PE64 translator.

The implementation lives in the :mod:`x86x64` package; this file is only the
command-line entry point and a compatibility surface for existing scripts that
still do ``from x86_x64 import ...``.

    x86x64/core/       symbols, relocations, object files, linker
    x86x64/pe/         PE32 parsing, PE64 writing, validation
    x86x64/syscall/    syscall tables and stub translation
    x86x64/abi/        TEB remapping and calling conventions
    x86x64/encoding/   x86-64 instruction emitters
    x86x64/dispatch/   import address table dispatch
    x86x64/kernel/     system service descriptor tables
    x86x64/translator/ the translation passes themselves
"""

from x86x64.translator.runtime import *  # noqa: F401,F403
from x86x64.translator import Win2000Translator  # noqa: F401
from x86x64.cli import BatchTranslator, SystemBuilder, main  # noqa: F401

if __name__ == '__main__':
    main()
