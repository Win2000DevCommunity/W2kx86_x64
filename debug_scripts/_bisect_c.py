import subprocess, sys, re, pathlib
exes = []
for p in sorted(pathlib.Path(".").glob("build_univ*/cmd_pure.exe")):
    exes.append(str(p))
for p in ["build_univ258/cmd_probe_wfs.exe", "build_univ258/cmd_probe_jcc.exe", "build_univ258/cmd_probe_lj.exe"]:
    if pathlib.Path(p).exists():
        exes.append(p)
print("testing", len(exes), "binaries")
for exe in exes[-12:]:
    try:
        r = subprocess.run([sys.executable, "dbg_fault.py", exe, "/c", "echo", "w2ktest"],
                           capture_output=True, text=True, timeout=35)
    except Exception as e:
        print(exe, "ERR", e); continue
    out = r.stdout or ""
    has = "w2ktest" in out
    exitm = re.search(r"\[exit\] code=0x([0-9A-Fa-f]+)", out)
    exc = re.search(r"code=0x([0-9A-Fa-f]+)", out)
    addr = re.search(r"addr=0x([0-9A-Fa-f]+)", out)
    print(f"{exe}: w2k={has} exit={exitm.group(1) if exitm else '-'} exc={exc.group(1) if exc else '-'} addr={addr.group(1) if addr else '-'}")
