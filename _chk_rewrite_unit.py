# Offline verify: patch univ96 text with the new helper logic via importing translator
import sys, struct
from pathlib import Path
sys.path.insert(0, ".")
from x86x64.translator.core import X86toX64Translator
# Minimal: just test _rewrite via a lightweight object
from x86x64.pe.pe32 import PE32
from x86x64.pe.fixups import remap_section_rva

pe_path = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
# Build a stub with enough state
class T:
    pass

# Use real translator briefly just for methods - or instantiate properly
# Faster: monkey-patch by reading how translator is constructed

from x86x64.cli.driver import build_translator_from_args
# too heavy - just unit the rewrite on a mock

pe32 = PE32(pe_path.read_bytes())
# Create translator the usual way from package
from x86x64.translator.core import Translator
print("Translator", Translator)
