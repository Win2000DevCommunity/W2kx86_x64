"""
The passes that ship with the framework.

Importing this package registers them in
:data:`x86x64.pipeline.registry.REGISTRY`. Nothing here is specific to a
particular binary; image-specific work belongs in a pass registered with a
matcher, which is why the engine never needs to change to support a new one.
"""

from . import analyze, load  # noqa: F401  (imported for the side effect)
from .identify import classify, identify, load_source, target_for

__all__ = ['load_source', 'identify', 'classify', 'target_for']
