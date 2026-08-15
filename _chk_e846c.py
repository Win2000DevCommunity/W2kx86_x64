import os, pathlib, sys
sys.path.insert(0, ".")
os.environ["PURE"] = "1"
from x86x64.pe import PE32Image
from x86x64.translator import Win2000Translator
from tools.audit_calls import read_text_section

src = pathlib.Path(
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
)
pe = PE32Image(src.read_bytes())
blob = pathlib.Path("build_univ31/cmd_pure.exe").read_bytes()
trva, data, new_base = read_text_section(blob)
t = Win2000Translator(pe, win10_test_shim=True, source_path=str(src))
t.new_base = new_base
t._cmd_no_hacks = True
t._is_alloca_probe_rva = lambda r: False
# discover
entries = getattr(t, "_fn_entry_rvas", None)
if entries is None:
    # try analyze
    from x86x64.analysis.discover import discover_functions
    try:
        ents = discover_functions(pe)
        print("discover count", len(ents))
        print("e846 in discover", 0xE846 in ents or hex(0xE846))
        print("nearby", [hex(x) for x in sorted(ents) if abs(x - 0xE846) < 0x40])
    except Exception as ex:
        print("discover fail", ex)
        # fallback: check translator method
        pass

# Check mapped_entry / find_sane
if hasattr(t, "find_sane"):
    pass

# Manual: disassemble e846 from pe and see if translate_function works
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sec = pe.section_for_rva(0xE846)
print("section", sec)
# translate single fn if API exists
for name in dir(t):
    if "translat" in name.lower() and "fn" in name.lower():
        print("method", name)
