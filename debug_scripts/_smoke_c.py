import subprocess, sys, re
for exe in ["build_univ258/cmd_probe_jcc.exe", "build_univ259/cmd_pure.exe"]:
    r = subprocess.run([sys.executable, "dbg_fault.py", exe, "/c", "echo", "w2ktest"],
                       capture_output=True, text=True, timeout=40)
    out = r.stdout or ""
    has = "w2ktest" in out
    exc = re.search(r"code=0x([0-9A-Fa-f]+).*?addr=0x([0-9A-Fa-f]+)", out, re.S)
    exitm = re.search(r"\[exit\] code=0x([0-9A-Fa-f]+)", out)
    print(f"{exe}: has_w2k={has} exit={exitm.group(1) if exitm else None} exc={exc.groups() if exc else None}")
    # first printable lines
    for ln in out.splitlines()[:8]:
        if ln.strip():
            print(" ", ln[:100])
