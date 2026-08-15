path = r"C:\Users\win2000\.cursor\projects\c-Users-win2000-Desktop-Nouveau-dossier-Nouveau-dossier-9-X86-X64\agent-transcripts\a90e140a-cb48-460a-9563-a5cfa076cfa5\a90e140a-cb48-460a-9563-a5cfa076cfa5.jsonl"
n = 0
for line in open(path, encoding="utf-8"):
    if "build_univ8" in line and ("--pure" in line or "DUMP_RVA" in line):
        i = line.find("command")
        print(line[i:i+1800])
        print("=====")
        n += 1
        if n >= 5:
            break
