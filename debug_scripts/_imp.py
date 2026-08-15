import os, sys, struct, pathlib
os.environ["PURE"]="1"
sys.path.insert(0,".")
# Import the actual translator class used by CLI
import x86_x64
# Find Translator / mixin
from x86x64.cli.driver import main
# Build a minimal duck and bind the method
from x86x64.translator import core as tc
print([x for x in dir(tc) if not x.startswith("_")])