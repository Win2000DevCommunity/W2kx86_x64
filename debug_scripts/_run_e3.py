import subprocess, sys
cmd = [sys.executable, "dbg_fault.py", r"build_univ256\cmd_probe_echo3.exe", "/c", "echo", "w2ktest"]
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    out, _ = p.communicate(timeout=12)
    status = b"DONE rc=%d\n" % (p.returncode or 0)
except subprocess.TimeoutExpired:
    p.kill()
    out, _ = p.communicate()
    status = b"TIMEOUT\n"
open("_e3c.txt", "wb").write(status + (out or b""))
print(status.decode().strip(), "bytes", len(out or b""))
