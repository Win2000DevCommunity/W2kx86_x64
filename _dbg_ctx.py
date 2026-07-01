import re, sys

path = r"build_out80\full.log"
target = sys.argv[1] if len(sys.argv) > 1 else "137C7"
before = int(sys.argv[2]) if len(sys.argv) > 2 else 60

raw = open(path, "rb").read()
if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(raw) > 1 and raw[1] == 0):
    text = raw.decode("utf-16", errors="replace")
else:
    text = raw.decode("utf-8", errors="replace")
lines = text.splitlines()
# instruction lines contain 'rsp='
insn = [ln for ln in lines if "rsp=" in ln and "main+" in ln]
pat = re.compile(r"main\+0x" + target + r"\b")
for i, ln in enumerate(insn):
    if pat.search(ln):
        lo = max(0, i - before)
        for j in range(lo, min(i + 3, len(insn))):
            mark = " <==" if j == i else ""
            print(insn[j].strip() + mark)
        break
else:
    print("not found in instruction stream:", target)
