from pathlib import Path

heal = r'''
    def _pure_fix_exitprocess_wrapper_via_terminate(self, out: bytearray) -> int:
        """Restore shredded ExitProcess wrappers using TerminateProcess.

        x86 ``AC92`` ends with ``call [ExitProcess]``, but PE64 often drops
        ExitProcess from the IAT and leaves the translated wrapper as::

            <homes>; mov rcx, 0; ret

        so ``/c`` teardown returns into the interactive waiter.  Rewrite to
        ``TerminateProcess(GetCurrentProcess(), code)`` via the existing
        TerminateProcess IAT cell (HANDLE -1 == current process).
        """
        if not self._cmd_no_hacks:
            return 0
        nb = int(getattr(self, "new_base", 0) or 0)
        iat = 0
        name_map = getattr(self, "_iat_name_to_new_rva", None) or {}
        for (dll, fn), rva in name_map.items():
            if fn.lower() == "terminateprocess":
                iat = nb + int(rva)
                break
        if not iat:
            # Fallback: cmd layout TerminateProcess @ .idata tip 0x845e0
            iat = nb + 0x845E0
        dead = bytes.fromhex(
            "48894c240848895424104c894424184c894c2420"  # homes
            "48c7c100000000"  # mov rcx, 0
            "c3"  # ret
        )
        # mov edx, ecx; mov rcx, -1; movabs rax, iat; mov rax,[rax]; jmp rax
        stub = bytearray()
        stub += b"\x89\xca"  # mov edx, ecx
        stub += b"\x48\xc7\xc1\xff\xff\xff\xff"  # mov rcx, -1
        stub += b"\x48\xb8" + struct.pack("<Q", iat)
        stub += b"\x48\x8b\x00"  # mov rax, [rax]
        stub += b"\xff\xe0"  # jmp rax
        if len(stub) > len(dead):
            return 0
        stub.extend(b"\x90" * (len(dead) - len(stub)))
        fixed = 0
        i = 0
        while True:
            at = out.find(dead, i)
            if at < 0:
                break
            out[at:at + len(dead)] = stub
            fixed += 1
            i = at + len(dead)
        return fixed

'''

path = Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")
marker = "    def _pure_fix_reg_arg_join_skips_stdcall_add_rsp(self, out: bytearray) -> int:"
if "_pure_fix_exitprocess_wrapper_via_terminate" in text:
    print("exit heal already present")
elif marker not in text:
    raise SystemExit("marker missing")
else:
    text = text.replace(marker, heal + "\n" + marker, 1)
    path.write_text(text, encoding="utf-8")
    print("exit heal inserted")

# Also seed SingleCommand when sticky:=1 in seed helper
old = """        helper += b'\\x49\\xbb' + struct.pack('<Q', seed_done)
        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'
        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)"""
# use actual bytes from file
old2 = (
    "        helper += b'\\x49\\xbb' + struct.pack('<Q', seed_done)\n"
    "        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'\n"
    "        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)\n"
)
# read exact
idx = text.find("helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'")
print("sticky set idx", idx)
