#!/usr/bin/env bash
# rea-pro doctor: one-shot environment probe. Safe, read-only. Usage: bash doctor.sh
have(){ command -v "$1" >/dev/null 2>&1; }
echo "--- ENV"; uname -m; . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"
tp=$(awk '/^TracerPid:/{print $2}' /proc/self/status 2>/dev/null)
if [ -n "$PROOT_TMP_DIR" ] || [ "${tp:-0}" != 0 ]; then echo "termux/proot: LIKELY (TracerPid=${tp:-?}) -> static-first, no ptrace attach"; else echo "proot: not detected"; fi
awk '/MemAvailable/{printf "mem_avail_MB: %d\n",$2/1024}' /proc/meminfo 2>/dev/null; echo "cpus: $(nproc 2>/dev/null)"; df -Pm "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2{print "tmp_free_MB: "$4}'
echo "--- PTRACE"
if have strace; then o=$(timeout 10 strace -f -e trace=execve true 2>&1)
 if echo "$o" | grep -qiE 'not supported|proot warning|operation not permitted'; then echo "strace: PARTIAL/UNRELIABLE (proot warning) -> never rely on strace/gdb -p/frida attach"
 elif echo "$o" | grep -q execve; then echo "strace: works"; else echo "strace: FAILS"; fi
else echo "strace: not installed"; fi
mem=$(awk '/MemAvailable/{printf "%d",$2/1024}' /proc/meminfo 2>/dev/null); mem=${mem:-0}
echo "--- RAM VERDICT"
if [ "$mem" -lt 1500 ]; then echo "LOW RAM (${mem}MB): NO Ghidra. jadx only with JAVA_OPTS=-Xmx512m and -j1 (big APKs may die). Prefer radare2/objdump, extract selectively, one job at a time."
elif [ "$mem" -lt 3000 ]; then echo "MODERATE RAM (${mem}MB): Ghidra only with -Xmx1g on one small binary; jadx -j1."
else echo "OK RAM (${mem}MB): Ghidra/jadx usable one at a time."; fi
echo "--- TOOLS (core | extra)"
for t in file strings rg jq xxd unzip readelf objdump nm sqlite3 python3 node; do have $t && printf 'ok:%s ' $t || printf 'MISSING:%s ' $t; done; echo
for t in llvm-objdump llvm-nm r2 rizin jadx apktool binwalk unblob wasm-objdump tshark yara capa floss diec ilspycmd go cargo java analyzeHeadless; do have $t && printf 'ok:%s ' $t || printf -- "-%s " $t; done; echo
have java && java -version 2>&1 | head -1
[ -n "$TERMUX_VERSION" ] && echo "note: running in Termux env directly, not inside Ubuntu proot-distro"
miss=""; for t in file rg xxd sqlite3 jq unzip; do have $t || miss="$miss $t"; done; pk=$(echo "$miss" | sed "s/\\brg\\b/ripgrep/")
[ -n "$miss" ] && echo "MISSING CORE -> apt install -y$pk   (recon.sh has fallbacks, but install for best results)"
echo "--- INSTALL HINTS (ask user first; Ubuntu arm64 proot, run as root, no sudo)"
echo "core: apt install -y file binutils ripgrep jq xxd unzip sqlite3 python3 nodejs"
echo "extra: apt install -y radare2 binwalk wabt tshark yara llvm; pip install --break-system-packages unblob (verify aarch64 wheels first); jadx/apktool/ghidra need JDK17+ (apt install -y default-jdk-headless)"
