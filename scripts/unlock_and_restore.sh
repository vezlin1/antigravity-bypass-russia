#!/usr/bin/env bash
# ==============================================================================
# Antigravity Bypass Russia (v2.0.0) for macOS (Apple Silicon & Intel)
# Supports: Antigravity 2.0+ (Core), IDE UI (main.js) & Antigravity CLI (agy)
# Dual-level patching: ARM64 / x64 Opcodes + Strings + Mach-O Code Signing
# Network: /etc/resolver Scoped Domain DNS Routing + VPN Bypass Support
# ==============================================================================

set -e

# Fallback TERM to xterm-256color if current TERM is missing in root terminfo (Ghostty, Kitty, Alacritty, WezTerm, etc.)
if [[ -z "${TERM:-}" ]] || ! infocmp "$TERM" >/dev/null 2>&1; then
    export TERM="xterm-256color"
fi

safe_clear() {
    printf "\033[2J\033[H"
}

# --- Colors & Styling ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

RESOLVER_DIR="/etc/resolver"
RESOLVER_TAG="# ANTIGRAVITY-BYPASS-RUSSIA"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.antigravity.bypass.russia.plist"
INSTALL_DIR="/Library/Application Support/AntigravityBypassRussia"

# --- Domains for Selective DNS Routing ---
DOMAINS=(
    "daily-cloudcode-pa.googleapis.com"
    "cloudcode-pa.googleapis.com"
    "generativelanguage.googleapis.com"
    "gemini.google.com"
    "gemini.google"
    "gemini.gstatic.com"
    "bard.google.com"
    "generativeai.google"
    "aistudio.google.com"
    "ai.studio"
    "ai.google.dev"
    "makersuite.google.com"
    "alkalicore-pa.clients6.google.com"
    "alkalimakersuite-pa.clients6.google.com"
    "webchannel-alkalimakersuite-pa.clients6.google.com"
    "alkalimakersuite-pa.googleapis.com"
    "alkalimakersuiteapplets.pa.googleapis.com"
    "notebooklm-pa.googleapis.com"
    "notebooklm.googleapis.com"
    "notebooklm.google"
    "notebooklm.google.com"
    "jules.google"
    "jules.google.com"
    "aisandbox-pa.googleapis.com"
    "deepmind.com"
    "deepmind.google"
    "aiplatform.googleapis.com"
    "s-aiplatform.googleapis.com"
)

# --- DNS Upstream Providers ---
XBOX_SERVERS=("111.88.96.50" "111.88.96.51" "83.220.169.155" "212.109.195.93" "195.133.25.16")

# --- Privilege Elevation & Real User Resolution ---
if [[ -n "$SUDO_USER" && "$SUDO_USER" != "root" ]]; then
    REAL_HOME=$(eval echo "~$SUDO_USER")
else
    REAL_HOME="$HOME"
fi

ensure_admin() {
    if [[ "$(id -u)" -ne 0 ]]; then
        local script_path
        script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
        if [[ -t 0 ]]; then
            echo -e "${CYAN}[i] Запрос прав администратора (sudo)...${NC}"
            exec sudo bash "$script_path" "$@"
        else
            echo -e "${CYAN}[i] Запрос прав администратора (GUI диалог)...${NC}"
            osascript -e "do shell script \"bash \\\"$script_path\\\"\" with administrator privileges"
            exit 0
        fi
    fi
}

# --- Process Killer (Batched single call) ---
kill_antigravity_processes() {
    echo -e "${GRAY}Завершение запущенных процессов Antigravity...${NC}"
    pkill -15 -f "Antigravity|language_server|agy|ag_dns" 2>/dev/null || true
    killall "Antigravity" "Antigravity IDE" "agy" "language_server_darwin_arm64" \
            "language_server_darwin_x64" "language_server" "ag_dns" 2>/dev/null || true
    sleep 0.2
    pkill -9 -f "Antigravity|language_server|agy|ag_dns" 2>/dev/null || true
}

# --- Cache Cleaner ---
clear_caches() {
    local count=0
    local target_dirs=(
        "$REAL_HOME/Library/Application Support/Antigravity/CachedData"
        "$REAL_HOME/Library/Application Support/Antigravity/Code Cache"
        "$REAL_HOME/Library/Application Support/Antigravity IDE/CachedData"
        "$REAL_HOME/Library/Application Support/Antigravity IDE/Code Cache"
        "$REAL_HOME/Library/Caches/com.google.antigravity"
        "$REAL_HOME/Library/Caches/com.antigravity.ide"
        "$REAL_HOME/Library/Caches/Antigravity"
        "$REAL_HOME/Library/Caches/Antigravity IDE"
    )
    for d in "${target_dirs[@]}"; do
        if [[ -d "$d" ]]; then
            rm -rf "$d"
            count=$((count + 1))
        fi
    done
    echo "$count"
}

# --- Installation Discovery on macOS ---
find_installations() {
    local paths=()
    local candidates=(
        "/Applications/Antigravity.app"
        "/Applications/Antigravity IDE.app"
        "$REAL_HOME/Applications/Antigravity.app"
        "$REAL_HOME/Applications/Antigravity IDE.app"
        "/opt/homebrew/Caskroom/antigravity"
        "/opt/homebrew/Caskroom/antigravity-ide"
        "/opt/homebrew/bin"
        "/usr/local/bin"
        "$REAL_HOME/.local/bin"
    )
    for c in "${candidates[@]}"; do
        if [[ -e "$c" ]]; then
            paths+=("$c")
        fi
    done

    # VS Code / Cursor / Windsurf Extensions
    local ext_roots=(
        "$REAL_HOME/.vscode/extensions"
        "$REAL_HOME/.vscode-insiders/extensions"
        "$REAL_HOME/.cursor/extensions"
        "$REAL_HOME/.windsurf/extensions"
        "$REAL_HOME/.vscodium/extensions"
    )
    for er in "${ext_roots[@]}"; do
        if [[ -d "$er" ]]; then
            for ext in "$er"/*antigravity*; do
                if [[ -d "$ext" ]]; then
                    paths+=("$ext")
                fi
            done
        fi
    done

    printf '%s\n' "${paths[@]}"
}

# --- Target Finder inside App Bundle / Directory ---
find_targets() {
    local root="$1"
    local targets=()

    # Mach-O Language Server Binaries (Core 2.0)
    local ls_candidates=(
        "$root/Contents/Resources/app.asar.unpacked/extensions/antigravity/bin/language_server_darwin_arm64"
        "$root/Contents/Resources/app.asar.unpacked/extensions/antigravity/bin/language_server_darwin_x64"
        "$root/Contents/Resources/app.asar.unpacked/bin/language_server_darwin_arm64"
        "$root/Contents/Resources/app.asar.unpacked/bin/language_server_darwin_x64"
        "$root/Contents/Resources/app.asar.unpacked/bin/language_server"
        "$root/Contents/Resources/app/extensions/antigravity/bin/language_server_darwin_arm64"
        "$root/Contents/Resources/app/extensions/antigravity/bin/language_server_darwin_x64"
        "$root/Contents/Resources/app/extensions/antigravity/bin/language_server"
        "$root/Contents/Resources/bin/language_server"
        "$root/Contents/Resources/language_server"
        "$root/bin/language_server_darwin_arm64"
        "$root/bin/language_server_darwin_x64"
        "$root/bin/language_server"
        "$root/language_server_darwin_arm64"
        "$root/language_server_darwin_x64"
        "$root/language_server"
    )
    for ls in "${ls_candidates[@]}"; do
        if [[ -f "$ls" ]]; then
            targets+=("BIN:$ls")
        fi
    done

    # Dynamic fallback search for any Mach-O binaries if not found above
    if [[ ${#targets[@]} -eq 0 && -d "$root" ]]; then
        while IFS= read -r f; do
            if [[ -f "$f" ]]; then
                targets+=("BIN:$f")
            fi
        done < <(find "$root" -type f \( -name "language_server_darwin_*" -o -name "language_server" \) 2>/dev/null)
    fi

    # CLI Binary (agy)
    local cli_candidates=(
        "$root/Contents/Resources/bin/agy"
        "$root/Contents/Resources/app/bin/agy"
        "$root/bin/agy"
        "$root/agy"
    )
    for cli in "${cli_candidates[@]}"; do
        if [[ -f "$cli" ]]; then
            targets+=("BIN:$cli")
        fi
    done

    # UI JavaScript (main.js / extension.js)
    local js_candidates=(
        "$root/Contents/Resources/app/out/main.js"
        "$root/Contents/Resources/app/main.js"
        "$root/out/main.js"
        "$root/main.js"
        "$root/dist/extension.js"
        "$root/out/extension.js"
        "$root/extension.js"
    )
    for js in "${js_candidates[@]}"; do
        if [[ -f "$js" ]]; then
            targets+=("JS:$js")
        fi
    done

    printf '%s\n' "${targets[@]}"
}

# --- Python Binary Patcher with Quoted Heredoc & Entitlements Preservation ---
patch_binary_py() {
    local file_path="$1"
    local bak_path="${file_path}.bak"
    local dir_path
    dir_path="$(dirname "$file_path")"

    # Unlock directory & files from immutable flags and grant write permissions
    chflags nouchg,noschg "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true
    chmod u+w "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true

    [[ ! -f "$bak_path" ]] && cp "$file_path" "$bak_path" 2>/dev/null || true
    chmod u+w "$file_path" "$bak_path" 2>/dev/null || true

    python3 - "$file_path" <<'EOF'
import sys, re, os

path = sys.argv[1]
with open(path, "rb") as f:
    data = bytearray(f.read())

applied = []

# Core 2.0 Auth Gate (x64)
x64_orig = re.compile(rb'\x80\x78\x08\x00\x74.\x48\x8b.\x24.\x48\x89.\x60', re.DOTALL)
x64_fix = b'\xc6\x40\x08\x01\x90\x90'
for m in x64_orig.finditer(data):
    data[m.start():m.start()+len(x64_fix)] = x64_fix
    applied.append("hasValidAuth(x64)")

# Core 2.0 Auth Gate (ARM64 Apple Silicon M1-M4)
arm_orig = re.compile(rb'\x03\x20\x40\x39[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36(?:....){1,2}\x03\x10\x06\xa9', re.DOTALL)
arm_fix = b'\x23\x00\x80\x52\x03\x20\x00\x39'
for m in arm_orig.finditer(data):
    data[m.start():m.start()+len(arm_fix)] = arm_fix
    applied.append("hasValidAuth(ARM64)")

# CLI Screen Gate (x64)
cli_orig = re.compile(rb'\x48\x85\xc0\x0f\x84.{4}\x80\x78\x08\x00\x0f\x85.{4}', re.DOTALL)
cli_fix = b'\x48\x85\xc0\x90'
for m in cli_orig.finditer(data):
    offset = m.start() + 9
    data[offset:offset+len(cli_fix)] = cli_fix
    applied.append("CLI_GATE(x64)")

# Fallback String Enum (ineligible -> inexigible)
str_from = b'ineligible'
str_to   = b'inexigible'
count = data.count(str_from)
if count > 0:
    data = data.replace(str_from, str_to)
    applied.append(f"string_fix({count})")

if applied:
    tmp_path = path + ".tmp_patch"
    with open(tmp_path, "wb") as f:
        f.write(data)
    try:
        os.chmod(tmp_path, 0o755)
    except Exception:
        pass
    os.replace(tmp_path, path)
    print("успешно (" + " + ".join(applied) + ")")
else:
    print("уже пропатчен или сигнатуры не найдены")
EOF

    # Preserve entitlements during ad-hoc code signing
    codesign --force --sign - --preserve-metadata=entitlements,requirements,flags "$file_path" 2>/dev/null || \
    codesign --force --sign - "$file_path" 2>/dev/null || true
    xattr -d com.apple.quarantine "$file_path" 2>/dev/null || true
}

restore_binary_py() {
    local file_path="$1"
    local bak_path="${file_path}.bak"
    local dir_path
    dir_path="$(dirname "$file_path")"

    chflags nouchg,noschg "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true
    chmod u+w "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true

    if [[ -f "$bak_path" && -s "$bak_path" ]]; then
        cp "$bak_path" "$file_path"
        rm -f "$bak_path"
        echo "восстановлен из резервной копии (.bak, оригинальная подпись сохранена)"
        return
    fi

    python3 - "$file_path" <<'EOF'
import sys, re, os

path = sys.argv[1]
with open(path, "rb") as f:
    data = bytearray(f.read())

restored = []

# x64 Revert
x64_pat = re.compile(rb'\xc6\x40\x08\x01\x90\x90\x48\x8b.\x24.\x48\x89.\x60', re.DOTALL)
x64_rst = b'\x80\x78\x08\x00\x74\x18'
for m in x64_pat.finditer(data):
    data[m.start():m.start()+len(x64_rst)] = x64_rst
    restored.append("opcodes_x64")

# ARM64 Revert
arm_pat = re.compile(rb'\x23\x00\x80\x52\x03\x20\x00\x39\x62\x03\x00\xaa', re.DOTALL)
arm_rst = b'\x03\x20\x40\x39\x04\x00\x00\x14'
for m in arm_pat.finditer(data):
    data[m.start():m.start()+len(arm_rst)] = arm_rst
    restored.append("opcodes_arm64")

# CLI Revert
cli_pat = re.compile(rb'\x48\x85\xc0\x0f\x84.{4}\x48\x85\xc0\x90\x0f\x85.{4}', re.DOTALL)
cli_rst = b'\x80\x78\x08\x00'
for m in cli_pat.finditer(data):
    offset = m.start() + 9
    data[offset:offset+len(cli_rst)] = cli_rst
    restored.append("opcodes_cli")

# Strings Revert
str_from = b'inexigible'
str_to   = b'ineligible'
count = data.count(str_from)
if count > 0:
    data = data.replace(str_from, str_to)
    restored.append(f"strings({count})")

if restored:
    tmp_path = path + ".tmp_patch"
    with open(tmp_path, "wb") as f:
        f.write(data)
    try:
        os.chmod(tmp_path, 0o755)
    except Exception:
        pass
    os.replace(tmp_path, path)
    print("исходные байты восстановлены (" + " + ".join(restored) + ")")
else:
    print("файл уже в исходном состоянии")
EOF

    codesign --force --sign - --preserve-metadata=entitlements,requirements,flags "$file_path" 2>/dev/null || true
}

patch_main_js() {
    local file_path="$1"
    local bak_path="${file_path}.bak"
    local dir_path
    dir_path="$(dirname "$file_path")"

    chflags nouchg,noschg "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true
    chmod u+w "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true

    [[ ! -f "$bak_path" ]] && cp "$file_path" "$bak_path" 2>/dev/null || true

    python3 - "$file_path" <<'EOF'
import sys, re, os

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

if "resetIsTierGCPTos(),true" in content or "resetIsTierGCPTos();true" in content:
    print("уже пропатчен ранее (isGoogleInternal -> true)")
    sys.exit(0)

pattern = r'(resetIsTierGCPTos\(\)\s*[,;]\s*)(?:this|[A-Za-z_$0-9]+)(?:\.[A-Za-z_$0-9]+)*\.isGoogleInternal'
if re.search(pattern, content):
    new_content = re.sub(pattern, r'\g<1>true', content)
    tmp_path = path + ".tmp_patch"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    try:
        os.chmod(tmp_path, 0o644)
    except Exception:
        pass
    os.replace(tmp_path, path)
    print("успешно (isGoogleInternal -> true)")
else:
    print("сигнатура не найдена")
EOF
    clear_caches >/dev/null
}

restore_main_js() {
    local file_path="$1"
    local bak_path="${file_path}.bak"
    local dir_path
    dir_path="$(dirname "$file_path")"

    chflags nouchg,noschg "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true
    chmod u+w "$dir_path" "$file_path" "$bak_path" 2>/dev/null || true

    if [[ -f "$bak_path" && -s "$bak_path" ]]; then
        cp "$bak_path" "$file_path"
        rm -f "$bak_path"
        clear_caches >/dev/null
        echo "восстановлен из резервной копии (.bak)"
        return
    fi

    python3 - "$file_path" <<'EOF'
import sys, re, os

path = sys.argv[1]
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

pattern = r'(resetIsTierGCPTos\(\)\s*[,;]\s*)true'
if re.search(pattern, content):
    new_content = re.sub(pattern, r'\g<1>this.isGoogleInternal', content)
    tmp_path = path + ".tmp_patch"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    try:
        os.chmod(tmp_path, 0o644)
    except Exception:
        pass
    os.replace(tmp_path, path)
    print("исходное состояние восстановлено")
else:
    print("патч не обнаружен")
EOF
    clear_caches >/dev/null
}

rank_proxies_and_apply_hosts() {
    local hosts_file="/etc/hosts"
    echo -e "\n${CYAN}Замер задержки TLS и выбор быстрейшего узла Cloud Code (SmartDNS / SNI Proxy)...${NC}"

    local leader_ip
    leader_ip=$(python3 - <<'EOF'
import socket, ssl, time, sys

host = "daily-cloudcode-pa.googleapis.com"
candidates = [
    ("195.133.25.16",  "XboxDNS Relay #3"),
    ("83.220.169.155", "XboxDNS Relay #2"),
    ("212.109.195.93", "XboxDNS Relay #1"),
    ("193.233.112.67", "Comss Anycast #1"),
    ("193.233.112.68", "Comss Anycast #2"),
    ("87.228.47.194",  "Hetzner Proxy #1"),
    ("87.228.47.202",  "Hetzner Proxy #2"),
    ("45.155.204.190", "Geohide SNI #1"),
    ("37.230.192.51",  "Geohide SNI #2"),
]

results = []
for ip, label in candidates:
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            rtt = int((time.perf_counter() - t0) * 1000)
            results.append((rtt, ip, label))
            sys.stderr.write(f"  • {ip:<15} ({label:<16}) ➔ \033[92m{rtt} мс\033[0m\n")
    except Exception:
        sys.stderr.write(f"  • {ip:<15} ({label:<16}) ➔ \033[90mтаймаут / недоступен\033[0m\n")

if results:
    results.sort(key=lambda x: x[0])
    best_rtt, best_ip, best_label = results[0]
    sys.stderr.write(f"\n\033[92m  [✓] Выбран самый быстрый лидер: {best_ip} ({best_label}, {best_rtt} мс)\033[0m\n")
    print(best_ip)
else:
    print("195.133.25.16")
EOF
)

    if [[ -z "$leader_ip" ]]; then
        leader_ip="195.133.25.16"
    fi

    if grep -q "BEGIN ANTIGRAVITY-BYPASS-RUSSIA" "$hosts_file" 2>/dev/null; then
        sed -i '' '/# BEGIN ANTIGRAVITY-BYPASS-RUSSIA/,/# END ANTIGRAVITY-BYPASS-RUSSIA/d' "$hosts_file" 2>/dev/null || true
    fi

    cat <<EOF >> "$hosts_file"
# BEGIN ANTIGRAVITY-BYPASS-RUSSIA
$leader_ip daily-cloudcode-pa.googleapis.com
$leader_ip cloudcode-pa.googleapis.com
$leader_ip generativelanguage.googleapis.com
# END ANTIGRAVITY-BYPASS-RUSSIA
EOF
    echo -e "${GREEN}  [✓] /etc/hosts настроен (активный лидер: $leader_ip)${NC}"
}

apply_ide_settings() {
    local settings_dirs=(
        "$REAL_HOME/Library/Application Support/Antigravity/User"
        "$REAL_HOME/Library/Application Support/Antigravity IDE/User"
        "$REAL_HOME/Library/Application Support/Google Antigravity/User"
    )
    for sdir in "${settings_dirs[@]}"; do
        mkdir -p "$sdir" 2>/dev/null || true
        local sfile="$sdir/settings.json"
        if [[ ! -f "$sfile" ]]; then
            echo '{}' > "$sfile"
        fi
        python3 - "$sfile" <<'EOF'
import sys, json

path = sys.argv[1]
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
except Exception:
    data = {}

data["jetski.cloudCodeUrl"] = "https://daily-cloudcode-pa.googleapis.com"

with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
EOF
        if [[ -n "$SUDO_USER" && "$SUDO_USER" != "root" ]]; then
            chown "$SUDO_USER" "$sfile" 2>/dev/null || true
        fi
        echo -e "${GREEN}  [✓] Настройки IDE обновлены: $sfile${NC}"
    done
}

remove_ide_settings() {
    local settings_dirs=(
        "$REAL_HOME/Library/Application Support/Antigravity/User"
        "$REAL_HOME/Library/Application Support/Antigravity IDE/User"
        "$REAL_HOME/Library/Application Support/Google Antigravity/User"
    )
    for sdir in "${settings_dirs[@]}"; do
        local sfile="$sdir/settings.json"
        if [[ -f "$sfile" ]]; then
            python3 - "$sfile" <<'EOF'
import sys, json

path = sys.argv[1]
try:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if "jetski.cloudCodeUrl" in data:
        del data["jetski.cloudCodeUrl"]
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
except Exception:
    pass
EOF
        fi
    done
}

# --- DNS & Scoped Resolver Management (Subshell-free file generation) ---
apply_dns_resolvers() {
    local label="$1"
    shift
    local servers=("$@")

    # Очистка устаревших/ошибочных записей в /etc/hosts от предыдущих версий
    if [[ -f "/etc/hosts" ]] && grep -q "BEGIN ANTIGRAVITY-BYPASS-RUSSIA" "/etc/hosts" 2>/dev/null; then
        sed -i '' '/# BEGIN ANTIGRAVITY-BYPASS-RUSSIA/,/# END ANTIGRAVITY-BYPASS-RUSSIA/d' "/etc/hosts" 2>/dev/null || true
    fi

    apply_ide_settings

    echo -e "${YELLOW}Применение селективной DNS-маршрутизации...${NC}"
    mkdir -p "$RESOLVER_DIR"

    # If an older build left a LaunchDaemon, stop it: Mac should not keep
    # a process running while the lid is closed.
    if [[ -f "$LAUNCHD_PLIST" ]]; then
        launchctl bootout system/com.antigravity.bypass.russia 2>/dev/null || \
        launchctl unload -w "$LAUNCHD_PLIST" 2>/dev/null || true
        rm -f "$LAUNCHD_PLIST"
    fi
    pkill -f "ag_dns --dns-forwarder" 2>/dev/null || true

    local old_umask
    old_umask=$(umask)
    umask 022

    for d in "${DOMAINS[@]}"; do
        local res_file="$RESOLVER_DIR/$d"
        {
            echo "$RESOLVER_TAG"
            for s in "${servers[@]}"; do
                echo "nameserver $s"
            done
            echo "port 53"
            echo "timeout 2"
            echo "search_order 1"
        } > "$res_file"
    done

    umask "$old_umask"

    # Flush macOS DNS cache
    dscacheutil -flushcache
    killall -HUP mDNSResponder 2>/dev/null || true
    echo -e "${GREEN}  [✓] Создано ${#DOMAINS[@]} правил в /etc/resolver/${NC}"
}

remove_dns_resolvers() {
    echo -e "${YELLOW}Удаление правил /etc/resolver/...${NC}"
    local to_remove=()

    if [[ -d "$RESOLVER_DIR" ]]; then
        for res_file in "$RESOLVER_DIR"/*; do
            if [[ -f "$res_file" ]]; then
                if grep -q "$RESOLVER_TAG" "$res_file" 2>/dev/null; then
                    to_remove+=("$res_file")
                fi
            fi
        done
    fi

    if [[ ${#to_remove[@]} -gt 0 ]]; then
        rm -f "${to_remove[@]}"
    fi

    # Stop launchd daemon and remove plist
    if [[ -f "$LAUNCHD_PLIST" ]]; then
        launchctl bootout system/com.antigravity.bypass.russia 2>/dev/null || \
        launchctl unload -w "$LAUNCHD_PLIST" 2>/dev/null || true
        rm -f "$LAUNCHD_PLIST"
    fi

    rm -rf "$INSTALL_DIR"
    rm -f "/var/log/antigravity_bypass_russia_err.log"

    # Clean hosts file
    if [[ -f "/etc/hosts" ]]; then
        if grep -q "BEGIN ANTIGRAVITY-BYPASS-RUSSIA" "/etc/hosts" 2>/dev/null; then
            sed -i '' '/# BEGIN ANTIGRAVITY-BYPASS-RUSSIA/,/# END ANTIGRAVITY-BYPASS-RUSSIA/d' "/etc/hosts" 2>/dev/null || true
        fi
    fi

    remove_ide_settings

    dscacheutil -flushcache
    killall -HUP mDNSResponder 2>/dev/null || true
    echo -e "${GREEN}  [✓] Удалено ${#to_remove[@]} правил DNS, служба остановлена, hosts очищен, настройки IDE сброшены.${NC}"
}

WATCHER_PID_FILE="/tmp/antigravity_bypass_watcher.pid"

# --- Status Dashboard ---
show_dashboard() {
    local hosts_configured=0
    if grep -q "BEGIN ANTIGRAVITY-BYPASS-RUSSIA" "/etc/hosts" 2>/dev/null; then
        hosts_configured=1
    fi

    local rule_count=0
    if [[ -d "$RESOLVER_DIR" ]]; then
        rule_count=$(grep -l "$RESOLVER_TAG" "$RESOLVER_DIR"/* 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    fi

    echo -e "${GRAY}  ┌──────────────────── ТЕКУЩИЙ СТАТУС ────────────────────┐${NC}"
    echo -e "${GRAY}  • Права процесса:       ${GREEN}[✓] Администратор${NC}"

    if [[ "$hosts_configured" -eq 1 && "$rule_count" -gt 0 ]]; then
        echo -e "${GRAY}  • Сеть и DNS:           ${GREEN}[✓] Настроено (/etc/hosts + /etc/resolver)${NC}"
    elif [[ "$hosts_configured" -eq 1 ]]; then
        echo -e "${GRAY}  • Сеть и DNS:           ${GREEN}[✓] Настроено (/etc/hosts)${NC}"
    elif [[ "$rule_count" -gt 0 ]]; then
        echo -e "${GRAY}  • Сеть и DNS:           ${GREEN}[✓] Настроено (/etc/resolver)${NC}"
    else
        echo -e "${GRAY}  • Сеть и DNS:           ${GRAY}[Не настроено]${NC}"
    fi

    echo -e "${GRAY}  • DNS-релей:            ${GRAY}[-- Без фона (/etc/hosts + /etc/resolver)]${NC}"

    local watcher_active=0
    if [[ -f "$WATCHER_PID_FILE" ]]; then
        local wpid
        wpid=$(cat "$WATCHER_PID_FILE" 2>/dev/null || true)
        if [[ -n "$wpid" ]] && kill -0 "$wpid" 2>/dev/null; then
            watcher_active=1
        fi
    fi
    if [[ "$watcher_active" -eq 1 ]]; then
        echo -e "${GRAY}  • Авто-репатчер:        ${GREEN}[✓] Активен (авто-репатч)${NC}"
    else
        echo -e "${GRAY}  • Авто-репатчер:        ${GRAY}[-- Отключен]${NC}"
    fi

    local arch
    arch=$(uname -m)
    if [[ "$arch" == "arm64" ]]; then
        echo -e "${GRAY}  • Архитектура CPU:      ${CYAN}[$arch] (Apple Silicon M-Series)${NC}"
    else
        echo -e "${GRAY}  • Архитектура CPU:      ${CYAN}[$arch] (Intel x86_64)${NC}"
    fi

    local comp_json
    comp_json=$(python3 - <<'EOF'
import os, glob, json

def check_bin(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if b"inexigible" in data or b"\x23\x00\x80\x52" in data or b"\xc6\x40\x08\x01\x90\x90" in data:
            return "Patched"
        if b"ineligible" in data:
            return "Stock"
        return "Unknown"
    except Exception:
        return "Unknown"

def check_js(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if b"true||" in data or b"inexigible" in data or b"isSupportedRegion" in data or b"return!0" in data:
            return "Patched"
        return "Stock"
    except Exception:
        return "Unknown"

installs = [
    "/Applications/Antigravity.app",
    "/Applications/Antigravity IDE.app",
    os.path.expanduser("~/Applications/Antigravity.app"),
    os.path.expanduser("~/Applications/Antigravity IDE.app"),
]

core = None
ide = None
cli = None

for inst in installs:
    if not os.path.exists(inst):
        continue
    for p in glob.glob(f"{inst}/**/language_server_darwin_*", recursive=True):
        if os.path.isfile(p):
            st = check_bin(p)
            if core is None or core == "Stock":
                core = st
            break
    if core is None:
        for p in glob.glob(f"{inst}/**/language_server", recursive=True):
            if os.path.isfile(p):
                st = check_bin(p)
                if core is None or core == "Stock":
                    core = st
                break

    for p in glob.glob(f"{inst}/**/main.js", recursive=True):
        if os.path.isfile(p):
            st = check_js(p)
            if ide is None or ide == "Stock":
                ide = st
            break

    for p in [f"{inst}/Contents/Resources/bin/agy", "/usr/local/bin/agy", "/opt/homebrew/bin/agy", os.path.expanduser("~/.local/bin/agy")]:
        if os.path.isfile(p):
            st = check_bin(p)
            if cli is None or cli == "Stock":
                cli = st
            break

print(json.dumps({"core": core, "ide": ide, "cli": cli}))
EOF
)

    local core_val ide_val cli_val
    core_val=$(echo "$comp_json" | grep -o '"core": "[^"]*"' | cut -d'"' -f4 || echo "")
    ide_val=$(echo "$comp_json" | grep -o '"ide": "[^"]*"' | cut -d'"' -f4 || echo "")
    cli_val=$(echo "$comp_json" | grep -o '"cli": "[^"]*"' | cut -d'"' -f4 || echo "")

    if [[ "$core_val" == "Patched" ]]; then
        echo -e "${GRAY}  • Antigravity 2.0 Core: ${GREEN}[✓] Пропатчен${NC}"
    elif [[ "$core_val" == "Stock" ]]; then
        echo -e "${GRAY}  • Antigravity 2.0 Core: ${YELLOW}[Исходный]${NC}"
    else
        echo -e "${GRAY}  • Antigravity 2.0 Core: ${GRAY}[Не установлено]${NC}"
    fi

    if [[ "$ide_val" == "Patched" ]]; then
        echo -e "${GRAY}  • Antigravity IDE UI:   ${GREEN}[✓] Пропатчен${NC}"
    elif [[ "$ide_val" == "Stock" ]]; then
        echo -e "${GRAY}  • Antigravity IDE UI:   ${YELLOW}[Исходный]${NC}"
    else
        echo -e "${GRAY}  • Antigravity IDE UI:   ${GRAY}[Неизвестно]${NC}"
    fi

    if [[ "$cli_val" == "Patched" ]]; then
        echo -e "${GRAY}  • Antigravity CLI:      ${GREEN}[✓] Пропатчен${NC}"
    elif [[ "$cli_val" == "Stock" ]]; then
        echo -e "${GRAY}  • Antigravity CLI:      ${YELLOW}[Исходный]${NC}"
    else
        echo -e "${GRAY}  • Antigravity CLI:      ${GRAY}[Не установлено]${NC}"
    fi

    echo -e "${GRAY}  └────────────────────────────────────────────────────────┘\n${NC}"
}

# --- Main Menu Loop ---
ask_enable_watcher() {
    echo -e "\n${MAGENTA}[?] Включить автоматический репатч при обновлениях Antigravity ?${NC}"
    echo "  1. Да"
    echo "  2. Нет"
    read -rp "Выберите [1-2, по умолчанию 2]: " ans
    if [[ "$ans" == "1" || "$ans" =~ ^[YyДд] ]]; then
        if [[ -f "$WATCHER_PID_FILE" ]]; then
            local old_pid
            old_pid=$(cat "$WATCHER_PID_FILE" 2>/dev/null || true)
            if [[ -n "$old_pid" ]]; then
                kill "$old_pid" 2>/dev/null || true
            fi
        fi
        (
            while true; do
                sleep 10
                while IFS= read -r inst; do
                    [[ -z "$inst" ]] && continue
                    while IFS= read -r item; do
                        [[ -z "$item" ]] && continue
                        local type="${item%%:*}"
                        local path="${item#*:}"
                        if [[ "$type" == "JS" ]]; then
                            patch_main_js "$path" >/dev/null 2>&1 || true
                        else
                            patch_binary_py "$path" >/dev/null 2>&1 || true
                        fi
                    done < <(find_targets "$inst" 2>/dev/null)
                done < <(find_installations 2>/dev/null)
            done
        ) >/dev/null 2>&1 &
        local wpid=$!
        echo "$wpid" > "$WATCHER_PID_FILE"
        echo -e "  ${GREEN}[✓] Автоматический репатч включен (фоновый процесс, PID: $wpid).${NC}\n"
    else
        echo -e "  ${GRAY}[--] Автоматический репатч пропущен.${NC}\n"
    fi
}

main_menu() {
    while true; do
        safe_clear
        echo -e "${CYAN}=====================================================${NC}"
        echo -e "${CYAN}          ANTIGRAVITY-BYPASS-RUSSIA (v2.0.0)         ${NC}"
        echo -e "${CYAN}=====================================================${NC}"
        echo -e "Утилита обхода региональных ограничений и чистый откат\n"

        show_dashboard

        echo -e "${GREEN}1. Полная разблокировка${NC}"
        echo -e "${CYAN}2. Только файлы (Работа без смены страны аккаунта)${NC}"
        echo -e "${YELLOW}3. Только DNS и сеть (Работа без VPN)${NC}"
        echo -e "4. Указать путь к Antigravity вручную"
        echo -e "5. Диагностика и проверка связи"
        echo -e "${RED}6. ПОЛНЫЙ ОТКАТ (вернуть всё в исходное состояние)${NC}"
        echo -e "0. Выход\n"

        read -rp "Выберите действие [0-6]: " action

        case "$action" in
            1)
                ask_enable_watcher
                DNS_LABEL="SmartDNS"
                DNS_SERVERS=("${XBOX_SERVERS[@]}")
                kill_antigravity_processes
                while IFS= read -r inst; do
                    [[ -z "$inst" ]] && continue
                    echo -e "\n${CYAN}Обработка: $inst${NC}"
                    xattr -dr com.apple.quarantine "$inst" 2>/dev/null || true
                    chflags -R nouchg,noschg "$inst" 2>/dev/null || true
                    chmod -R u+w "$inst" 2>/dev/null || true
                    while IFS= read -r item; do
                        [[ -z "$item" ]] && continue
                        local type="${item%%:*}"
                        local path="${item#*:}"
                        local name
                        name=$(basename "$path")
                        if [[ "$type" == "JS" ]]; then
                            local res
                            res=$(patch_main_js "$path")
                            echo -e "  ${GREEN}[✓] $name (IDE UI) - $res${NC}"
                        else
                            local res
                            res=$(patch_binary_py "$path")
                            echo -e "  ${GREEN}[✓] $name (Binary) - $res${NC}"
                        fi
                    done < <(find_targets "$inst")
                    if [[ "$inst" == *".app"* ]]; then
                        xattr -cr "$inst" 2>/dev/null || true
                    fi
                done < <(find_installations)

                apply_dns_resolvers "$DNS_LABEL" "${DNS_SERVERS[@]}"
                echo -e "\n${GREEN}[✓] Готово! Запустите Antigravity и авторизуйтесь.${NC}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
                ask_enable_watcher
                kill_antigravity_processes
                while IFS= read -r inst; do
                    [[ -z "$inst" ]] && continue
                    echo -e "\n${CYAN}Обработка: $inst${NC}"
                    xattr -dr com.apple.quarantine "$inst" 2>/dev/null || true
                    chflags -R nouchg,noschg "$inst" 2>/dev/null || true
                    chmod -R u+w "$inst" 2>/dev/null || true
                    while IFS= read -r item; do
                        [[ -z "$item" ]] && continue
                        local type="${item%%:*}"
                        local path="${item#*:}"
                        local name
                        name=$(basename "$path")
                        if [[ "$type" == "JS" ]]; then
                            local res
                            res=$(patch_main_js "$path")
                            echo -e "  ${GREEN}[✓] $name (IDE UI) - $res${NC}"
                        else
                            local res
                            res=$(patch_binary_py "$path")
                            echo -e "  ${GREEN}[✓] $name (Binary) - $res${NC}"
                        fi
                    done < <(find_targets "$inst")
                    if [[ "$inst" == *".app"* ]]; then
                        xattr -cr "$inst" 2>/dev/null || true
                    fi
                done < <(find_installations)
                apply_ide_settings
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                ask_enable_watcher
                DNS_LABEL="SmartDNS"
                DNS_SERVERS=("${XBOX_SERVERS[@]}")
                apply_dns_resolvers "$DNS_LABEL" "${DNS_SERVERS[@]}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            4)
                read -rp "Введите путь к папке или файлу Antigravity (.app): " custom_path
                custom_path="${custom_path/#\~/$HOME}"
                if [[ -e "$custom_path" ]]; then
                    kill_antigravity_processes
                    xattr -dr com.apple.quarantine "$custom_path" 2>/dev/null || true
                    chflags -R nouchg,noschg "$custom_path" 2>/dev/null || true
                    chmod -R u+w "$custom_path" 2>/dev/null || true
                    if [[ -f "$custom_path" ]]; then
                        local name
                        name=$(basename "$custom_path")
                        if [[ "$name" == *"main.js"* ]]; then
                            local res
                            res=$(patch_main_js "$custom_path")
                            echo -e "  ${GREEN}[✓] $name - $res${NC}"
                        else
                            local res
                            res=$(patch_binary_py "$custom_path")
                            echo -e "  ${GREEN}[✓] $name - $res${NC}"
                        fi
                    else
                        while IFS= read -r item; do
                            [[ -z "$item" ]] && continue
                            local type="${item%%:*}"
                            local path="${item#*:}"
                            local name
                            name=$(basename "$path")
                            if [[ "$type" == "JS" ]]; then
                                local res
                                res=$(patch_main_js "$path")
                                echo -e "  ${GREEN}[✓] $name - $res${NC}"
                            else
                                local res
                                res=$(patch_binary_py "$path")
                                echo -e "  ${GREEN}[✓] $name - $res${NC}"
                            fi
                        done < <(find_targets "$custom_path")
                        if [[ "$custom_path" == *".app"* ]]; then
                            xattr -cr "$custom_path" 2>/dev/null || true
                        fi
                    fi
                else
                    echo -e "${RED}[!] Путь не существует: $custom_path${NC}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                safe_clear
                echo -e "${CYAN}================ ДИАГНОСТИКА СИСТЕМЫ ================${NC}\n"

                echo -e "  1. Права процесса:       ${GREEN}[✓] Администратор${NC}"

                local hosts_configured=0
                if grep -q "BEGIN ANTIGRAVITY-BYPASS-RUSSIA" "/etc/hosts" 2>/dev/null; then
                    hosts_configured=1
                fi
                local rule_count=0
                if [[ -d "$RESOLVER_DIR" ]]; then
                    rule_count=$(grep -l "$RESOLVER_TAG" "$RESOLVER_DIR"/* 2>/dev/null | wc -l | tr -d ' ' || echo 0)
                fi

                if [[ "$hosts_configured" -eq 1 ]]; then
                    echo -e "  2. Сеть и DNS:           ${GREEN}[✓] Настроено (/etc/hosts + /etc/resolver)${NC} (правил: $rule_count)"
                else
                    echo -e "  2. Сеть и DNS:           ${GRAY}[Не настроено]${NC}"
                fi

                echo -e "  3. Служба DNS-релея:     ${GRAY}[-- Без фона (/etc/hosts + /etc/resolver)]${NC}"

                local arch
                arch=$(uname -m)
                if [[ "$arch" == "arm64" ]]; then
                    echo -e "  4. Архитектура CPU:      ${CYAN}[$arch] Apple Silicon M-Series${NC}"
                else
                    echo -e "  4. Архитектура CPU:      ${CYAN}[$arch] Intel x86_64${NC}"
                fi

                echo -e "\n  5. Связь с Google API:"
                python3 - <<'EOF'
import socket, ssl, time, sys

targets = [
    ("cloudcode-pa.googleapis.com", 443),
    ("generativelanguage.googleapis.com", 443),
]

for host, port in targets:
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5)
        sock.connect((host, port))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            rtt = int((time.perf_counter() - t0) * 1000)
            peer_ip = sock.getpeername()[0]
            print(f"     \033[92m[✓]\033[0m Доступен ({rtt} мс, IPv4) — {host} ({peer_ip})")
    except Exception as e:
        print(f"     \033[91m[✗]\033[0m Ошибка подключения к {host}: {e}")
EOF

                echo -e "\n  6. Тестирование скорости всех прокси и релеев:"
                python3 - <<'EOF'
import socket, ssl, time, sys

host = "daily-cloudcode-pa.googleapis.com"
candidates = [
    ("195.133.25.16",  "XboxDNS Relay #3"),
    ("83.220.169.155", "XboxDNS Relay #2"),
    ("212.109.195.93", "XboxDNS Relay #1"),
    ("193.233.112.67", "Comss Anycast #1"),
    ("193.233.112.68", "Comss Anycast #2"),
    ("87.228.47.194",  "Hetzner Proxy #1"),
    ("87.228.47.202",  "Hetzner Proxy #2"),
    ("45.155.204.190", "Geohide SNI #1"),
    ("37.230.192.51",  "Geohide SNI #2"),
]

for ip, label in candidates:
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.7)
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            rtt = int((time.perf_counter() - t0) * 1000)
            print(f"     • {ip:<15} ({label:<16}) ➔ \033[92m{rtt} мс\033[0m")
    except Exception:
        print(f"     • {ip:<15} ({label:<16}) ➔ \033[90mтаймаут\033[0m")
EOF

                echo ""
                read -rp "Нажмите Enter для продолжения..."
                ;;
            6)
                if [[ -f "$WATCHER_PID_FILE" ]]; then
                    local wpid
                    wpid=$(cat "$WATCHER_PID_FILE" 2>/dev/null || true)
                    if [[ -n "$wpid" ]]; then
                        kill "$wpid" 2>/dev/null || true
                    fi
                    rm -f "$WATCHER_PID_FILE"
                fi
                kill_antigravity_processes
                while IFS= read -r inst; do
                    [[ -z "$inst" ]] && continue
                    echo -e "\n${CYAN}Откат: $inst${NC}"
                    chflags -R nouchg,noschg "$inst" 2>/dev/null || true
                    chmod -R u+w "$inst" 2>/dev/null || true
                    while IFS= read -r item; do
                        [[ -z "$item" ]] && continue
                        local type="${item%%:*}"
                        local path="${item#*:}"
                        local name
                        name=$(basename "$path")
                        if [[ "$type" == "JS" ]]; then
                            local res
                            res=$(restore_main_js "$path")
                            echo -e "  ${GREEN}[✓] $name - $res${NC}"
                        else
                            local res
                            res=$(restore_binary_py "$path")
                            echo -e "  ${GREEN}[✓] $name - $res${NC}"
                        fi
                    done < <(find_targets "$inst")

                    local app_dir="$inst/Contents/Resources/app"
                    local app_asar="$inst/Contents/Resources/app.asar"
                    if [[ -d "$app_dir" && -f "$app_asar" ]]; then
                        rm -rf "$app_dir"
                        echo -e "  ${GREEN}[✓] Contents/Resources/app удален (возврат к app.asar)${NC}"
                    fi
                done < <(find_installations)

                remove_dns_resolvers
                clear_caches >/dev/null
                echo -e "\n${GREEN}[✓] Полный откат завершен. Всё возвращено в исходное состояние.${NC}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

# --- Entry Point ---
ensure_admin "$@"
main_menu
