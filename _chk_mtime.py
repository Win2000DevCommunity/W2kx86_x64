# Was univ3 built recently? Compare source mtime vs binary
from pathlib import Path
import os
bins=[
"build_univ3/cmd_pure.exe",
"x86x64/translator/_healing.py",
"x86x64/translator/_analysis.py",
]
for p in bins:
    pp=Path(p)
    if pp.exists():
        print(p, "mtime", pp.stat().st_mtime)
