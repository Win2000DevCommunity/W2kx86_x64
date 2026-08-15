from pathlib import Path

heal = r'''
    def _pure_fix_missing_push_ecx_local_before_csr(self, out: bytearray) -> int:
        """Restore dropped ``push ecx`` local before CSR pushes (Echo flag helper).

        x86 (cmd ``0x138e2``)::

            push ecx                 ; local
            push ebx; push ebp; push esi; push edi
            push 3; xor ebp,ebp
            cmp [esp+0x1c], ebp     ; arg0 (string*)
            pop ebx
            mov [esp+0x10], ebx     ; local = 3

        Translation emits Win64 homes + four CSR pushes but drops the local,
        so ``mov [rsp+0x10], ebx`` overwrites saved RBP (leave ? AV) and
        ``cmp [rsp+0x1c], ebp`` false-matches ? Echo returns 2 ("ECHO is on").
        """
        if not self._cmd_no_hacks:
            return 0
        homes = bytes.fromhex('48894c240848895424104c894424184c894c2420')
        csr = bytes.fromhex('53555657')
        # xor rbp,rbp; push 3; cmp [rsp+0x1c],ebp; pop rbx; mov [rsp+0x10],ebx
        tip = bytes.fromhex('4831ed6a03396c241c5b895c2410')
        fixed = 0
        i = 0
        while True:
            at = out.find(homes + csr + tip, i)
            if at < 0:
                break
            csr_at = at + len(homes)
            tip_at = csr_at + len(csr)
            end_tip = tip_at + len(tip)
            # Cave: push 0; CSR; xor; push 3; cmp [rsp+0x30],ebp; pop rbx;
            #       mov [rsp+0x20],ebx; jmp fallthrough
            def _build(cave, _fall=end_tip):
                stub = bytearray()
                stub += b'\x6a\x00'          # push 0  (x86 push ecx local)
                stub += csr
                stub += b'\x48\x31\xed'     # xor rbp,rbp
                stub += b'\x6a\x03'         # push 3
                stub += b'\x39\x6c\x24\x30' # cmp [rsp+0x30], ebp  (arg0 home)
                stub += b'\x5b'             # pop rbx
                stub += b'\x89\x5c\x24\x20' # mov [rsp+0x20], ebx  (local)
                stub += b'\xe9' + struct.pack(
                    '<i', _fall - (cave + len(stub) + 5))
                return bytes(stub)
            cave = self._pure_find_padding_cave(out, 28)
            if cave < 0:
                i = at + 1
                continue
            stub = _build(cave)
            if len(stub) > 28:
                i = at + 1
                continue
            out[cave:cave + len(stub)] = stub
            # Replace CSR+tip with jmp cave; nop pad
            span = len(csr) + len(tip)
            out[csr_at:csr_at + span] = (
                b'\xe9' + struct.pack('<i', cave - (csr_at + 5))
                + b'\x90' * (span - 5))
            # Body fixes until ~0x200 bytes or 4-pop epi
            body_end = min(len(out) - 4, end_tip + 0x200)
            j = end_tip
            while j < body_end:
                # cmp dword [rsp+0x10], 3 ? [rsp+0x20]
                if out[j:j + 5] == bytes.fromhex('837c241003'):
                    out[j + 3] = 0x20
                    j += 5
                    continue
                # cmp dword [rsp+0x1c], imm8 ? [rsp+0x38] (arg1 / rdx home)
                if out[j:j + 4] == bytes.fromhex('837c241c'):
                    out[j + 3] = 0x38
                    j += 4
                    continue
                # mov rax, [rsp+0x20] already correct as local with push 0
                # 4-pop epi: 5f5e5d5bc3 ? trampoline with extra pop
                if out[j:j + 5] == bytes.fromhex('5f5e5d5bc3'):
                    epi_cave = self._pure_find_padding_cave(out, 8)
                    if epi_cave >= 0:
                        out[epi_cave:epi_cave + 6] = bytes.fromhex('5f5e5d5b59c3')
                        out[j:j + 5] = (
                            b'\xe9' + struct.pack('<i', epi_cave - (j + 5)))
                    j += 5
                    continue
                # jmp near to shared 4-pop epi (5f5e5d5bc3): retarget
                if out[j] == 0xE9 and j + 5 <= len(out):
                    rel = struct.unpack_from('<i', out, j + 1)[0]
                    dest = j + 5 + rel
                    if (0 <= dest < len(out) - 4
                            and out[dest:dest + 5] == bytes.fromhex('5f5e5d5bc3')):
                        epi_cave = self._pure_find_padding_cave(out, 8)
                        if epi_cave >= 0:
                            out[epi_cave:epi_cave + 6] = bytes.fromhex(
                                '5f5e5d5b59c3')
                            struct.pack_into(
                                '<i', out, j + 1, epi_cave - (j + 5))
                    j += 5
                    continue
                j += 1
            fixed += 1
            i = end_tip
        return fixed

'''

path = Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")
marker = "    def _pure_fix_frameless_dual_local_frame(self, out: bytearray) -> int:"
if marker not in text:
    raise SystemExit("marker missing")
if "_pure_fix_missing_push_ecx_local_before_csr" in text:
    print("already present")
else:
    text = text.replace(marker, heal + "\n" + marker, 1)
    path.write_text(text, encoding="utf-8")
    print("heal inserted")
