from pathlib import Path

heal = r'''
    def _pure_fix_reg_arg_join_skips_stdcall_add_rsp(self, out: bytearray) -> int:
        """Skip leftover ``add rsp,8`` when joining CSR epi without stack args.

        x86 shared ``pop ecx; pop ecx; pop edi; ?; ret`` cleanup.  On Win64 a
        success path may pass args only in RCX/RDX (no pushes) but still
        ``jmp`` onto ``add rsp, 8`` before ``pop rdi``, so the return address
        is loaded into RSI and ``ret`` executes a heap node (cmd Echo
        ``0x427fb`` ? ``0x428ce``).
        """
        if not self._cmd_no_hacks:
            return 0
        # add rsp,8; pop rdi; xor rax,rax; pop rsi; ret
        epi = bytes.fromhex('4883c4085f4831c05ec3')
        fixed = 0
        i = 0
        while True:
            at = out.find(epi, i)
            if at < 0:
                break
            skip_to = at + 4  # pop rdi
            for j in range(max(0, at - 0x180), at - 5):
                if out[j] != 0xE9:
                    continue
                rel = struct.unpack_from('<i', out, j + 1)[0]
                if j + 5 + rel != at:
                    continue
                pre = bytes(out[max(0, j - 8):j])
                # Keep cleanup when this join still materializes stack args.
                if len(pre) >= 6 and pre[-6] == 0x57 and pre[-5] == 0x68:
                    continue  # push rdi; push imm32
                if len(pre) >= 3 and pre[-3] == 0x57 and pre[-2] == 0x6a:
                    continue  # push rdi; push imm8
                if pre and 0x50 <= pre[-1] <= 0x57:
                    continue  # trailing push r64
                if len(pre) >= 2 and pre[-2] == 0x41 and 0x50 <= pre[-1] <= 0x57:
                    continue
                struct.pack_into('<i', out, j + 1, skip_to - (j + 5))
                fixed += 1
            i = at + 1
        return fixed

'''

path = Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")
marker = "    def _pure_nop_spurious_stdcall_add_rsp_after_align("
if "_pure_fix_reg_arg_join_skips_stdcall_add_rsp" in text:
    print("already present")
elif marker not in text:
    raise SystemExit("marker missing")
else:
    text = text.replace(marker, heal + "\n" + marker, 1)
    path.write_text(text, encoding="utf-8")
    print("heal inserted")

# wire
p = Path("x86x64/translator/_image.py")
t = p.read_text(encoding="utf-8")
needle = """                n_asr = self._pure_nop_spurious_stdcall_add_rsp_after_align(blob)
                if n_asr:
                    print(f\"        Final pure spurious post-align add-rsp NOPs: {n_asr}\")"""
insert = """                n_rjoin = self._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob)
                if n_rjoin:
                    print(f\"        Final pure reg-arg join add-rsp skips: {n_rjoin}\")
                n_asr = self._pure_nop_spurious_stdcall_add_rsp_after_align(blob)
                if n_asr:
                    print(f\"        Final pure spurious post-align add-rsp NOPs: {n_asr}\")"""
if "n_rjoin" in t:
    print("already wired")
elif needle not in t:
    raise SystemExit("wire needle missing")
else:
    p.write_text(t.replace(needle, insert, 1), encoding="utf-8")
    print("wired")
