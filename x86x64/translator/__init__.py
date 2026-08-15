"""The x86 to x64 translator, split into domain modules.

Attributes resolve lazily. Importing a submodule runs this file first, and the
domain packages under :mod:`x86x64.analysis` and :mod:`x86x64.pe` depend on
:mod:`x86x64.translator._env`; if this eagerly imported ``core`` then reaching
``_env`` would pull in the whole translator and cycle back through them.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # for type checkers and editors only
    from ._analysis import AnalysisMixin
    from ._encoding import EncodingMixin
    from ._frame import FrameMixin
    from ._function import FunctionTranslationMixin
    from ._healing import HealingMixin
    from ._iat import IatMixin
    from ._image import ImageBuilderMixin
    from ._misc import MiscMixin
    from ._quirks_cmd import CmdQuirksMixin
    from ._seh import SehMixin
    from ._ubrt import UbrtMixin
    from .core import Win2000Translator

#: Exported name -> module that defines it.
_LAZY = {
    'Win2000Translator': '.core',
    'AnalysisMixin': '._analysis',
    'CmdQuirksMixin': '._quirks_cmd',
    'EncodingMixin': '._encoding',
    'FrameMixin': '._frame',
    'FunctionTranslationMixin': '._function',
    'HealingMixin': '._healing',
    'IatMixin': '._iat',
    'ImageBuilderMixin': '._image',
    'MiscMixin': '._misc',
    'SehMixin': '._seh',
    'UbrtMixin': '._ubrt',
}


def __getattr__(name: str):
    try:
        where = _LAZY[name]
    except KeyError:
        raise AttributeError(
            f'module {__name__!r} has no attribute {name!r}') from None
    value = getattr(importlib.import_module(where, __name__), name)
    globals()[name] = value  # resolve once
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))


__all__ = sorted(_LAZY)
