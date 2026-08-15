import subprocess, sys, time
# Interactive: start without /c, expect no immediate exit and maybe prompt chars
p = subprocess.Popen([sys.executable, "dbg_fault.py", r"build_univ257\cmd_probe_univ258.exe"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(2.5)
try:
    p.stdin.write(b"exit\r\n"); p.stdin.flush()
except Exception:
    pass
try:
    out, _ = p.communicate(timeout=5)
except subprocess.TimeoutExpired:
    p.kill(); out, _ = p.communicate()
text = out.decode("utf-8","replace").encode("ascii","replace").decode()
print("exit", p.returncode)
print(text[:1200])
