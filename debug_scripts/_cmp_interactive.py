# Compare interactive on univ257 (no lexer sticky exit) vs univ258
import subprocess, sys, time
for name in ["build_univ257/cmd_pure.exe", "build_univ258/cmd_pure.exe", "build_univ258/cmd_probe_rjoin.exe"]:
    p=subprocess.Popen([sys.executable,"dbg_fault.py",name],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    time.sleep(2.0)
    try:
        p.stdin.write(b"echo hi\r\nexit\r\n"); p.stdin.flush()
    except Exception as e:
        pass
    try:
        out,_=p.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        p.kill(); out,_=p.communicate()
    text=out.decode("utf-8","replace").encode("ascii","replace").decode()
    # summarize
    has_so="C00000FD" in text.upper() or "stack" in text.lower()
    has_av="C0000005" in text.upper() or "access-violation" in text
    has_exit="[exit]" in text
    print(f"=== {name} exit={p.returncode} so={has_so} av={has_av} ===")
    for line in text.splitlines()[:12]:
        print(line)
    print("...")
