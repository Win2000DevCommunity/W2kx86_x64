# At WAIT_LJ print RDX; also compare shim longjmp to fresh build
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import w2kseh64
fresh = w2kseh64.build_longjmp(with_nv_save=True)
shim = pefile.PE("build_univ258/w2kshim64.dll")
for exp in shim.DIRECTORY_ENTRY_EXPORT.symbols:
  if exp.name == b"longjmp":
    got = shim.get_data(exp.address, len(fresh)+10)
    print("match", got[:len(fresh)]==fresh, "len", len(fresh))
    if got[:len(fresh)]!=fresh:
      print("fresh", fresh.hex())
      print("got  ", got[:len(fresh)].hex())
