# What is fault? Check dbg_fault for exception code in last run - re-run with more detail
import subprocess, sys
r = subprocess.run([sys.executable, "dbg_fault.py", "build_univ258/cmd_probe_jcc.exe"],
    input="echo hi\r\nexit\r\n", capture_output=True, text=True, timeout=30)
print(r.stdout)
print('---stderr---')
print(r.stderr)
print('code', r.returncode)
