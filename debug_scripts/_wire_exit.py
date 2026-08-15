from pathlib import Path
path = Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")

# After sticky=1, set SingleCommand (/c exit flag) at .data+0xF64
needle = """        helper += b'\\x49\\xbb' + struct.pack('<Q', seed_done)
        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'
        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)
        helper += b'\\x41\\x8b\\x3b'                          # edi = [c8d8]"""

# The file uses double-quoted bytes sometimes - find exact
import re
m = re.search(
    r"(helper \+= b'\\x49\\xbb' \+ struct\.pack\('<Q', seed_done\)\n"
    r"        helper \+= b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'\n"
    r"        helper \+= b'\\x49\\xbb' \+ struct\.pack\('<Q', c8d8\))",
    text,
)
if not m:
    # try with double quotes for pack
    print("pattern A miss, trying alt")
    idx = text.find("helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'")
    print(repr(text[idx-80:idx+120]))
else:
    insert = m.group(1) + (
        "\n        # /c SingleCommand exit flag (.data+0xF64) ? CheckSwitches may"
        "\n        # never run when the lexer is PEB-seeded past ``/c``."
        "\n        sc_flag = _find_data_va(_data_va(0xF64))"
        "\n        helper += b'\\x49\\xbb' + struct.pack('<Q', sc_flag)"
        "\n        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'"
        "\n        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)"
    )
    # wait that duplicates c8d8 line - fix
    insert = (
        "        helper += b'\\x49\\xbb' + struct.pack('<Q', seed_done)\n"
        "        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'\n"
        "        # /c SingleCommand (.data+0xF64) when PEB-seeded past /c.\n"
        "        sc_flag = _find_data_va(_data_va(0xF64))\n"
        "        helper += b'\\x49\\xbb' + struct.pack('<Q', sc_flag)\n"
        "        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'\n"
        "        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)"
    )
    text = text[:m.start(1)] + insert + text[m.end(1):]
    path.write_text(text, encoding="utf-8")
    print("seed flag ok")

# wire heals in _image.py
p = Path("x86x64/translator/_image.py")
t = p.read_text(encoding="utf-8")
if "n_exitw" not in t:
    needle = """                n_rjoin = self._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob)
                if n_rjoin:
                    print(f\"        Final pure reg-arg join add-rsp skips: {n_rjoin}\")"""
    insert = """                n_exitw = self._pure_fix_exitprocess_wrapper_via_terminate(blob)
                if n_exitw:
                    print(f\"        Final pure ExitProcess via TerminateProcess: {n_exitw}\")
                n_rjoin = self._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob)
                if n_rjoin:
                    print(f\"        Final pure reg-arg join add-rsp skips: {n_rjoin}\")"""
    if needle not in t:
        raise SystemExit("wire needle missing")
    t = t.replace(needle, insert, 1)
    p.write_text(t, encoding="utf-8")
    print("wired exit heal")
else:
    print("exit already wired")
