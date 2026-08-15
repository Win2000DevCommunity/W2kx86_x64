from pathlib import Path
import struct

pe=bytearray(Path('build_univ176/cmd_pure_h.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if pe[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8); break

pat=bytes.fromhex('48c7c07017000048894424284889442430ffd3')
repl=bytes.fromhex('b870170000488944242831c04889442430ffd3')
n=0; i=rp
while True:
    at=pe.find(pat, i)
    if at<0 or at>=rp+rs: break
    pe[at:at+len(repl)]=repl; n+=1; i=at+len(repl)
print('fm homes patched', n)

# Also patch first-call language: look for mov r9, rax before call rbx near PutMsg
# 4c 89 c1 is mov r9,rax? Actually 49 89 c1 = mov r9, rax
# From disasm: mov r9, rax at 261c3 = 49 89 c1
# Change nearby xor: after mov r9,rax before align - replace with 45 31 c9 (xor r9d,r9d)
# Only at the broken first sequence: mov r9,rax; add rsp,8
seq=bytes.fromhex('4989c14883c408')  # mov r9,rax; add rsp,8
rep=bytes.fromhex('4531c94883c408')  # xor r9d,r9d; add rsp,8
n2=0; i=rp
while True:
    at=pe.find(seq, i)
    if at<0 or at>=rp+rs: break
    # only inside PutMsg approx
    rva=va+(at-rp)
    if 0x26100 <= rva <= 0x26600:
        pe[at:at+len(rep)]=rep; n2+=1
    i=at+1
print('r9 fixes', n2)
Path('build_univ176/cmd_pure_i.exe').write_bytes(pe)