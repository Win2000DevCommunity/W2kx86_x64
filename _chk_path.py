# Use dbg_trace style but stop at first hit of either site
import sys
sys.path.insert(0, ".")
# Quick: read dbg_trace for hooks
from pathlib import Path
import dbg_trace
# monkeypatch - just run with env?
print("skip")
