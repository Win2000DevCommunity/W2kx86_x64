import subprocess, sys
r = subprocess.run([sys.executable, "dbg_fault.py", "build_univ258/cmd_probe_jcc.exe", "/c", "echo", "w2ktest"],
                   capture_output=True, text=True, timeout=40)
print("=== 258 jcc ===")
print(r.stdout[-600:])
print("rc", r.returncode)

r = subprocess.run([sys.executable, "dbg_fault.py", "build_univ259/cmd_pure.exe", "/c", "echo", "w2ktest"],
                   capture_output=True, text=True, timeout=40)
print("=== 259 ===")
print(r.stdout[:800])
print("---")
print(r.stdout[-800:])
