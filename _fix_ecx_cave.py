# Patch ecx heal to append if no cave; add /c flag seed heal
from pathlib import Path

# 1) Fix cave fallback in ecx heal
path = Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")
old = """            cave = self._pure_find_padding_cave(out, 28)
            if cave < 0:
                i = at + 1
                continue
            stub = _build(cave)
            if len(stub) > 28:
                i = at + 1
                continue
            out[cave:cave + len(stub)] = stub"""
new = """            cave = self._pure_find_padding_cave(out, 28)
            if cave < 0:
                cave = len(out)
                out.extend(b\"\\x00\" * 40)
            stub = _build(cave)
            if len(stub) > 40:
                i = at + 1
                continue
            out[cave:cave + len(stub)] = stub"""
if old not in text:
    print("ecx cave block not found exactly")
else:
    text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")
    print("ecx cave fallback ok")
