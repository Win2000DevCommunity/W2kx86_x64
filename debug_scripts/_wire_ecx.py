from pathlib import Path
p = Path("x86x64/translator/_image.py")
t = p.read_text(encoding="utf-8")
needle = """                n_dloc = self._pure_fix_frameless_dual_local_frame(blob)
                if n_dloc:
                    print(f\"        Final pure frameless dual-local frame fixes: {n_dloc}\")"""
insert = """                n_ecxloc = self._pure_fix_missing_push_ecx_local_before_csr(blob)
                if n_ecxloc:
                    print(f\"        Final pure push-ecx-local-before-CSR fixes: {n_ecxloc}\")
                n_dloc = self._pure_fix_frameless_dual_local_frame(blob)
                if n_dloc:
                    print(f\"        Final pure frameless dual-local frame fixes: {n_dloc}\")"""
if "_pure_fix_missing_push_ecx_local_before_csr" in t and "n_ecxloc" in t:
    print("already wired")
elif needle not in t:
    raise SystemExit("needle missing")
else:
    p.write_text(t.replace(needle, insert, 1), encoding="utf-8")
    print("wired")
