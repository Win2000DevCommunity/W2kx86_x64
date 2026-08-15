from pathlib import Path
p = Path("x86x64/translator/_image.py")
t = p.read_text(encoding="utf-8")
needle = """                n_jfar = self._pure_fix_je_far_to_in_function_align_call(blob)
                if n_jfar:
                    print(f\"        Final pure far-je to in-function align-call: {n_jfar}\")
                n_dand2 = self._pure_fix_dropped_rbp_disp8_rbx_scaled_and(blob)"""
insert = """                n_jfar = self._pure_fix_je_far_to_in_function_align_call(blob)
                if n_jfar:
                    print(f\"        Final pure far-je to in-function align-call: {n_jfar}\")
                # After final Jcc retargets: re-apply push-reg residual so a
                # stolen mov-rcx cave tip is restored (cmd 0x18110 Dispatch).
                n_pushrcx3 = self._pure_fix_push_reg_as_win64_arg0(blob)
                if n_pushrcx3:
                    print(f\"        Final pure push-reg->rcx arg0 fixes (last): {n_pushrcx3}\")
                n_dand2 = self._pure_fix_dropped_rbp_disp8_rbx_scaled_and(blob)"""
if needle not in t:
    raise SystemExit("needle missing")
p.write_text(t.replace(needle, insert, 1), encoding="utf-8")
print("image wire ok")
