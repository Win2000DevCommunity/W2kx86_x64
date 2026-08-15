from pathlib import Path

NEW = r'''    def _pure_fix_peb_c_sticky_done_on_zero_ret_epi(self, out: bytearray) -> int:
        """Mark PEB-/c sticky done (1->2) on builtin success epilogues.

        After ``/c`` via PEB seed, sticky stays 1 and the interactive lexer
        spins (``fae0 == 0x0A``).  Builtin success often ends with::

            pop rdi; xor rax, rax; pop rsi; ret

        When sticky == 1, bump it to 2 so the lexer entry heal can exit.
        Interactive (sticky == 0) is unchanged.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, "new_base", 0) or 0)
        if not nb:
            return 0
        sticky = nb + 0x5BE00
        for k in range(len(out) - 12):
            if out[k:k + 2] != b"\x49\xbb":
                continue
            v = struct.unpack_from("<Q", out, k + 2)[0]
            if (v & 0xFFFF) == 0xBE00 and (nb + 0x58000) <= v < (nb + 0x66000):
                sticky = v
                break
        epi = bytes.fromhex("5f4831c05ec3")
        fixed = 0
        sites = []
        i = 0
        while True:
            at = out.find(epi, i)
            if at < 0:
                break
            is_join = False
            for j in range(max(0, at - 0x120), at - 4):
                if out[j] == 0xE9:
                    rel = struct.unpack_from("<i", out, j + 1)[0]
                    if j + 5 + rel == at:
                        is_join = True
                        break
                if out[j] == 0x0F and j + 5 < at and 0x80 <= out[j + 1] <= 0x8F:
                    rel = struct.unpack_from("<i", out, j + 2)[0]
                    if j + 6 + rel == at:
                        is_join = True
                        break
            if is_join:
                sites.append(at)
            i = at + 1
        for at in sites:
            stub = bytearray()
            stub += b"\x49\xbb" + struct.pack("<Q", sticky)
            stub += b"\x41\x83\x3b\x01"              # cmp dword [r11], 1
            stub += b"\x75\x07"                      # jne keep
            stub += b"\x41\xc7\x03\x02\x00\x00\x00"  # sticky = 2
            stub += epi                             # keep (ends in ret)
            cave = self._pure_find_padding_cave(out, len(stub) + 4)
            if cave < 0:
                cave = len(out)
                out.extend(b"\x00" * (len(stub) + 8))
            out[cave:cave + len(stub)] = stub
            out[at:at + 6] = (
                b"\xe9" + struct.pack("<i", cave - (at + 5)) + b"\x90")
            fixed += 1
        return fixed

    def _pure_fix_peb_c_lexer_exits_when_sticky_done(self, out: bytearray) -> int:
        """TerminateProcess(0) at the interactive lexer when sticky >= 2.

        The PEB-/c seed sets sticky=1; success-epi heal bumps it to 2 after
        the command.  The lexer (homes then ``fae0``/``fae4`` loads) then
        exits instead of spinning on a leftover ``0x0A`` token.
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, "new_base", 0) or 0)
        if not nb:
            return 0
        term_iat = self._pure_iat_va("terminateprocess", fallback_rva=0x845E0)
        if not term_iat:
            return 0
        sticky = nb + 0x5BE00
        for k in range(len(out) - 12):
            if out[k:k + 2] != b"\x49\xbb":
                continue
            v = struct.unpack_from("<Q", out, k + 2)[0]
            if (v & 0xFFFF) == 0xBE00 and (nb + 0x58000) <= v < (nb + 0x66000):
                sticky = v
                break
        homes = bytes.fromhex("48894c240848895424104c894424184c894c2420")
        fixed = 0
        sites = []
        i = 0
        while True:
            at = out.find(homes, i)
            if at < 0:
                break
            window = out[at + len(homes):at + len(homes) + 0x30]
            hit = False
            for k in range(len(window) - 10):
                if window[k:k + 2] != b"\x49\xbb":
                    continue
                v = struct.unpack_from("<Q", window, k + 2)[0]
                if (v & 0xFFFF) in (0xBAE0, 0xBAE4):
                    hit = True
                    break
            if hit:
                sites.append(at)
            i = at + 1
        for at in sites:
            stub = bytearray()
            stub += b"\x49\xbb" + struct.pack("<Q", sticky)
            stub += b"\x41\x83\x3b\x02"          # cmp dword [r11], 2
            stub += b"\x72\x18"                  # jb keep (sticky < 2)
            stub += b"\x31\xd2"
            stub += b"\x48\xc7\xc1\xff\xff\xff\xff"
            stub += b"\x48\xb8" + struct.pack("<Q", term_iat)
            stub += b"\x48\x8b\x00"
            stub += b"\xff\xe0"
            stub += homes
            stub += b"\xe9" + struct.pack("<i", 0)
            cave = self._pure_find_padding_cave(out, len(stub) + 4)
            if cave < 0:
                cave = len(out)
                out.extend(b"\x00" * (len(stub) + 8))
            fall = at + len(homes)
            struct.pack_into(
                "<i", stub, len(stub) - 4, fall - (cave + len(stub)))
            out[cave:cave + len(stub)] = stub
            repl = bytearray(
                b"\xe9" + struct.pack("<i", cave - (at + 5)))
            repl.extend(b"\x90" * (len(homes) - 5))
            out[at:at + len(homes)] = repl
            fixed += 1
        return fixed

    def _pure_fix_peb_c_infinite_waiter_exits(self, out: bytearray) -> int:
        """Alias: lexer exit when PEB-/c sticky is done."""
        return self._pure_fix_peb_c_lexer_exits_when_sticky_done(out)


'''

p = Path("x86x64/translator/_healing.py")
t = p.read_text(encoding="utf-8")
start = t.find("    def _pure_fix_peb_c_infinite_waiter_exits")
end = t.find("    def _pure_fix_reg_arg_join_skips_stdcall_add_rsp")
assert start > 0 and end > start, (start, end)
p.write_text(t[:start] + NEW + t[end:], encoding="utf-8")
print("ok", end - start, "->", len(NEW))
