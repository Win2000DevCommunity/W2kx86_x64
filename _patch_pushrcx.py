from pathlib import Path
path = Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")
marker = "    def _pure_fix_frameless_local_push_arg1_reg(self, out: bytearray) -> int:"
idx = text.index(marker)
# find the return fixed just before this marker (push_reg's return)
ret = text.rfind("        return fixed\n", 0, idx)
if ret < 0:
    raise SystemExit("return fixed not found")
# ensure it's the push_reg one: look back for Case B comment
chunk = text[ret-200:ret]
if "pre-planted mov-rcx trampoline" not in chunk:
    raise SystemExit("wrong return fixed: " + repr(chunk[-80:]))

residual = r'''
        # Residual: earlier pass NOPed the stdcall push, then a later Jcc
        # retarget stole the mov-rcx cave tip back onto the bare prelude
        # (cmd 0x18110 -> Dispatch with RCX=0 while RSI still holds the node).
        i = 0
        while i < len(out) - 40:
            if out[i] != 0x90:
                i += 1
                continue
            if not (out[i + 1] == 0x0F and out[i + 2] in (0x84, 0x85)):
                i += 1
                continue
            look = bytes(out[max(0, i - 0x30):i])
            if (b"\x8b\x06" in look or b"\x8b\x46" in look
                    or b"\x48\x8b\x06" in look or b"\x48\x8b\x46" in look):
                mov_rcx = bytes([0x48, 0x89, 0xf1])  # mov rcx, rsi
            elif (b"\x8b\x07" in look or b"\x8b\x47" in look
                  or b"\x48\x8b\x07" in look or b"\x48\x8b\x47" in look):
                mov_rcx = bytes([0x48, 0x89, 0xf9])  # mov rcx, rdi
            else:
                i += 1
                continue
            jcc_at = i + 1
            jcc_rel = struct.unpack_from("<i", out, i + 3)[0]
            land = i + 7 + jcc_rel
            if not (0 <= land < len(out) - 20):
                i += 1
                continue
            # Already retargeted onto a mov-rcx cave?
            if (land + 8 <= len(out)
                    and out[land:land + 3] == mov_rcx
                    and out[land + 3] == 0xE9):
                i = land + 8
                continue
            if not (out[land:land + 13] == prelude and out[land + 13] == 0xE8):
                i += 1
                continue
            if mov_rcx in bytes(out[i + 1:land + 1]):
                i += 1
                continue
            rel = struct.unpack_from("<i", out, land + 14)[0]
            targ = land + 18 + rel
            if not (0 <= targ < len(out) - 8):
                i += 1
                continue
            probe = bytes(out[targ:targ + 0x28])
            if (b"\x48\x89\x4d\x10" not in probe
                    and b"\x48\x8b\x5d\x10" not in probe):
                i += 1
                continue
            cave = self._pure_find_padding_cave(out, len(mov_rcx) + 5)
            if cave < 0:
                i += 1
                continue
            body = bytearray(mov_rcx)
            body += b"\xe9" + struct.pack(
                "<i", land - (cave + len(body) + 5))
            out[cave:cave + len(body)] = body
            struct.pack_into(
                "<i", out, jcc_at + 2, cave - (jcc_at + 6))
            fixed += 1
            i = land + 13
'''

text = text[:ret] + residual + "\n        return fixed\n\n" + text[idx:]
path.write_text(text, encoding="utf-8")
print("ok", ret, idx)
