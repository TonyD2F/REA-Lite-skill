#!/usr/bin/env bash
# rea-pro recon: route a target by magic bytes and print ONE capped, batched inventory.
# Usage: bash recon.sh <target> [workdir]   (never executes the target; works on a copy)
T=${1:?usage: recon.sh <target> [workdir]}; N=$(basename "$T"); RE=${2:-${TMPDIR:-/tmp}/re/$N}
mkdir -p "$RE"; have(){ command -v "$1" >/dev/null 2>&1; }
HAVE_RG=0; command -v rg >/dev/null 2>&1 && HAVE_RG=1
rg(){ if [ $HAVE_RG = 1 ]; then command rg "$@"; else grep -E "$@"; fi; }  # grep -E fallback when ripgrep is absent
S(){ echo "--- $*"; }; H(){ head -n "${CAP:-80}"; }
if [ -d "$T" ]; then C="$T"; else C="$RE/copy_$N"; [ -e "$C" ] || cp --reflink=auto "$T" "$C"; chmod -x "$C" 2>/dev/null; fi
filetype(){ if [ -z "$REA_NO_FILE" ] && have file; then file -b "$1"; else python3 - "$1" <<'PY'
import sys,zipfile
f=sys.argv[1]; b=open(f,'rb').read(16)
t="data"
if b[:4]==b'\x7fELF': t="ELF %d-bit"%(64 if b[4]==2 else 32)
elif b[:2]==b'MZ': t="PE32 (MS-DOS MZ executable)"
elif b[:4] in (b'\xcf\xfa\xed\xfe',b'\xce\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xfe\xed\xfa\xcf'): t="Mach-O"
elif b[:4]==b'PK\x03\x04':
    try: n=zipfile.ZipFile(f).namelist()
    except Exception: n=[]
    t="Android package (APK), with AndroidManifest.xml" if 'AndroidManifest.xml' in n else "Zip archive"
elif b[:15]==b'SQLite format 3': t="SQLite 3.x database"
elif b[:4] in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\n\r\r\n'): t="pcap capture"
elif b[:4]==b'\0asm': t="WebAssembly (wasm) binary"
elif b[:2]==b'\x1f\x8b': t="gzip compressed data"
else:
    try: open(f,encoding='utf-8').read(2000); t="text"
    except Exception: pass
print(t+" (python fallback; install `file` for detail)")
PY
fi; }
S TYPE; filetype "$C" | cut -c1-300; sha256sum "$C" 2>/dev/null | cut -c1-64; [ -f "$C" ] && { ls -l "$C" | awk '{print $5" bytes"}'; (xxd -l 16 "$C" 2>/dev/null || od -An -tx1 -N16 "$C"); }
M=$(filetype "$C")
case "$M" in
 *ELF*)
  S ELF-HEADER; readelf -h "$C" 2>/dev/null | rg -i 'class|machine|type|entry'
  S NEEDED/RPATH; readelf -dW "$C" 2>/dev/null | rg -i 'NEEDED|RPATH|RUNPATH|SONAME' | H
  S EXPORTS; (nm -D --defined-only "$C" 2>/dev/null || llvm-nm -D --defined-only "$C" 2>/dev/null) | H
  S IMPORTS; (nm -D -u "$C" 2>/dev/null || llvm-nm -D -u "$C" 2>/dev/null) | tr -s ' \n' ' ' | cut -c1-2500; echo
  S SECTIONS; readelf -SW "$C" 2>/dev/null | rg -i 'text|data|rodata|go\.|\.dep|gopclntab|note|debug' | H
  S GO/RUST; have go && go version -m "$C" 2>/dev/null | head -40; strings -a "$C" | rg -o -m3 '/rustc/[0-9a-f]{40}|Go buildinf'
  S STRINGS; strings -a -n 8 "$C" | rg -v '^[_$.]' | CAP=250 H ;;
 *PE32*|*MS-DOS*)
  S PE; (objdump -x "$C" 2>/dev/null || llvm-objdump -x "$C" 2>/dev/null) | rg -i 'DLL Name|subsystem|ImageBase|Characteristics|file format' | H
  S .NET?; filetype "$C" | rg -i 'mono|\.net|CLI' && echo "managed: use ilspycmd -p -o $RE/src $C"
  S STRINGS; strings -a -n 8 "$C" | CAP=200 H ;;
 *Mach-O*)
  S MACHO; (llvm-objdump --macho --private-headers "$C" 2>/dev/null || echo "no llvm-objdump: use strings/xxd") | H
  S STRINGS; strings -a -n 8 "$C" | CAP=200 H ;;
 *Zip*|*Java\ archive*|*Android*|*JAR*)
  S ZIP; unzip -l "$C" | H
  if unzip -l "$C" | rg -q 'AndroidManifest.xml'; then S APK; echo "APK: jadx -d $RE/jadx --show-bad-code $C ; apktool d --no-src -o $RE/res $C"; unzip -l "$C" | rg -o 'lib/[^/]+/lib(flutter|hermes|app|il2cpp|unity)[^ ]*' | sort -u; fi ;;
 *SQLite*) S SQLITE; if have sqlite3; then sqlite3 "file:$C?mode=ro" '.tables' '.schema' 2>&1 | H; else python3 -c 'import sqlite3,sys;c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True);[print(r[0]) for r in c.execute("select sql from sqlite_master where sql not null")]' "$C" 2>&1 | H; fi ;;
 *pcap*|*pcapng*) S PCAP; have tshark && tshark -r "$C" -q -z conv,tcp 2>/dev/null | H || echo "tshark missing" ;;
 *WebAssembly*) S WASM; have wasm-objdump && wasm-objdump -x "$C" | H || echo "install wabt" ;;
 *directory*|*) 
  if [ -d "$C" ] || echo "$M" | rg -qi 'text|JSON|script'; then S TREE; (cd "$C" 2>/dev/null && find . -maxdepth 2 | H); else S UNKNOWN; echo "try: binwalk $C | head ; strings -a -n 8 $C | head -100"; fi ;;
esac
# asar by magic: 4-byte pickle header then JSON; detect by extension
case "$N" in *.asar) S ASAR; (have asar && asar extract "$C" "$RE/asar" || npx -y @electron/asar extract "$C" "$RE/asar") 2>&1 | tail -2; [ -f "$RE/asar/package.json" ] && jq '{name,version,main}' "$RE/asar/package.json"; rg -uu -l --glob '!node_modules' 'exposeInMainWorld|ipcMain' "$RE/asar" 2>/dev/null | H;; esac
echo "--- WORKDIR $RE"
