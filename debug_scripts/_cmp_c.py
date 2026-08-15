# Compare /c on univ258 probe_jcc (known good) vs univ259
import subprocess, sys
for exe in ["build_univ258/cmd_probe_jcc.exe", "build_univ258/cmd_probe_wfs.exe", "build_univ259/cmd_pure.exe"]:
    r = subprocess.run([sys.executable, "dbg_fault.py", exe, "/c", "echo", "w2ktest"],
                       capture_output=True, text=True, timeout=40)
    lines = [ln for ln in (r.stdout or "").splitlines() if "w2ktest" in ln or "exit" in ln.lower() or "EXCEPTION" in ln or "execute" in ln or "code=0x" in ln]
    print(exe, "rc", r.returncode, lines[-6:])
