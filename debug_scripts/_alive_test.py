import subprocess, sys, time
exe = r"build_univ258\cmd_probe_jcc.exe"
# No stdin ? just see if interactive stays alive (prompt waiting)
p = subprocess.Popen([sys.executable, "dbg_fault.py", exe],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(4)
alive = p.poll() is None
print("alive_after_4s", alive, "code", p.returncode)
if not alive:
    out = p.stdout.read().decode("utf-8","replace")
    print(out[-1500:])
else:
    # send exit
    try:
        p.stdin  # none
    except Exception:
        pass
    p.terminate()
    out = p.communicate(timeout=3)[0].decode("utf-8","replace")
    print(out[-800:])
