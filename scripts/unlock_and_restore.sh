#!/usr/bin/env bash
# ==============================================================================
# Antigravity Bypass Russia (v1.0.1) for macOS (Apple Silicon & Intel)
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
    "cloudcode-pa.googleapis.com"
    "daily-cloudcode-pa.googleapis.com"
    "daily-cloudcode-pa.sandbox.googleapis.com"
    "antigravity-pa.googleapis.com"
    "antigravity.googleapis.com"
    "antigravity.google"
    "antigravity-unleash.goog"
    "cloudaicompanion.googleapis.com"
    "cloudaicompanion.sandbox.googleapis.com"
    "optimizationguide-pa.googleapis.com"
    "developerprofiles-pa.googleapis.com"
    "aicode.googleapis.com"
    "aida.googleapis.com"
    "geller-pa.googleapis.com"
    "proactivebackend-pa.googleapis.com"
    "robinfrontend-pa.googleapis.com"
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
    "people-pa.clients6.google.com"
    "notebooklm-pa.googleapis.com"
    "notebooklm.googleapis.com"
    "notebooklm.google"
    "notebooklm.google.com"
    "notebook.google.com"
    "jules.google"
    "jules.google.com"
    "opal.google"
    "opal.google.com"
    "labs.google"
    "labs.google.com"
    "flow.google"
    "aisandbox-pa.googleapis.com"
    "deepmind.com"
    "deepmind.google"
    "stitch.withgoogle.com"
    "iamcredentials.googleapis.com"
    "cloudresourcemanager.googleapis.com"
    "sts.googleapis.com"
    "aiplatform.googleapis.com"
    "s-aiplatform.googleapis.com"
    "play.googleapis.com"
    "oauth2.googleapis.com"
    "accounts.google.com"
    "sheets.googleapis.com"
    "docs.googleapis.com"
    "drive.googleapis.com"
    "script.google.com"
    "script.googleusercontent.com"
    "spreadsheets.google.com"
    "docs.google.com"
    "drive.google.com"
    "apis.google.com"
    "www.googleapis.com"
    "googleapis.com"
    "google.com"
)

# --- DNS Upstream Providers ---
XBOX_SERVERS=("111.88.96.50" "111.88.96.51")

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
    killall "Antigravity" "Antigravity IDE" "agy" "language_server_darwin_arm64" \
            "language_server_darwin_x64" "language_server" "ag_dns" 2>/dev/null || true
    sleep 0.1
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
arm_orig = re.compile(rb'\x03\x20\x40\x39\x04\x00\x00\x14\x62\x03\x00\xaa', re.DOTALL)
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
        codesign --force --sign - --preserve-metadata=entitlements,requirements,flags "$file_path" 2>/dev/null || true
        echo "восстановлен из резервной копии (.bak)"
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

# --- DNS & Scoped Resolver Management (Subshell-free file generation) ---
apply_dns_resolvers() {
    local label="$1"
    shift
    local servers=("$@")

    echo -e "${YELLOW}Применение селективной DNS-маршрутизации через ${label}...${NC}"
    mkdir -p "$RESOLVER_DIR"

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
    echo -e "${GREEN}  [✓] Создано ${#DOMAINS[@]} правил в /etc/resolver/ (${label})${NC}"
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

    dscacheutil -flushcache
    killall -HUP mDNSResponder 2>/dev/null || true
    echo -e "${GREEN}  [✓] Удалено ${#to_remove[@]} правил DNS, служба остановлена, hosts очищен.${NC}"
}

# --- Status Dashboard ---
show_dashboard() {
    local rule_count=0
    if [[ -d "$RESOLVER_DIR" ]]; then
        rule_count=$(grep -l "$RESOLVER_TAG" "$RESOLVER_DIR"/* 2>/dev/null | wc -l | tr -d ' ' || echo 0)
    fi

    echo -e "${GRAY}  ┌──────────────────── ТЕКУЩИЙ СТАТУС ────────────────────┐${NC}"
    echo -e "${GRAY}  • Права процесса:       ${GREEN}[✓] Администратор${NC}"
    
    if [[ "$rule_count" -gt 0 ]]; then
        echo -e "${GRAY}  • Сеть и DNS (NRPT):    ${GREEN}[✓] (Xbox-DNS.ru)${NC}"
    else
        echo -e "${GRAY}  • Сеть и DNS (NRPT):    ${GRAY}[Не настроено]${NC}"
    fi

    local arch
    arch=$(uname -m)
    if [[ "$arch" == "arm64" ]]; then
        echo -e "${GRAY}  • Архитектура CPU:      ${CYAN}[$arch] (Apple Silicon M1-M4 / Darwin)${NC}"
    else
        echo -e "${GRAY}  • Архитектура CPU:      ${CYAN}[$arch] (Intel x86_64 / Darwin)${NC}"
    fi

    local installs
    installs=$(find_installations)
    if [[ -n "$installs" ]]; then
        echo -e "${GRAY}  • Установка Antigravity:${GREEN}[✓ Обнаружена]${NC}"
    else
        echo -e "${GRAY}  • Установка Antigravity:${YELLOW}[? Не найдена в /Applications]${NC}"
    fi
    echo -e "${GRAY}  └────────────────────────────────────────────────────────┘\n${NC}"
}

select_dns() {
    echo -e "\n${CYAN}Выберите DNS-провайдер для маршрутизации:${NC}"
    echo -e "  ${YELLOW}1. Xbox-DNS.ru (111.88.96.50, 111.88.96.51)${NC}"
    echo -e "  ${GREEN}2. Ввести свой DNS / IP адрес личного VPS${NC}"
    read -rp "Ваш выбор [1-2] (Enter - Xbox-DNS): " dns_choice

    case "$dns_choice" in
        2)
            read -rp "Введите IP адрес(а) DNS через запятую или пробел: " custom_ip
            if [[ -z "$custom_ip" ]]; then
                DNS_LABEL="Xbox-DNS.ru"
                DNS_SERVERS=("${XBOX_SERVERS[@]}")
            else
                DNS_LABEL="Пользовательский DNS"
                custom_ip="${custom_ip//,/ }"
                read -r -a DNS_SERVERS <<< "$custom_ip"
            fi
            ;;
        *) DNS_LABEL="Xbox-DNS.ru"; DNS_SERVERS=("${XBOX_SERVERS[@]}") ;;
    esac
}

# --- Main Menu Loop ---
main_menu() {
    while true; do
        safe_clear
        echo -e "${CYAN}=====================================================${NC}"
        echo -e "${CYAN}    ANTIGRAVITY-BYPASS-RUSSIA (v1.0.1) FOR macOS     ${NC}"
        echo -e "${CYAN}=====================================================${NC}"
        echo -e "Утилита обхода региональных ограничений и чистый откат\n"

        show_dashboard

        echo -e "${GREEN}1. Полная разблокировка (Файлы Core 2.0/IDE/CLI + /etc/resolver DNS)${NC}"
        echo -e "${CYAN}2. Только файлы (Работа без смены страны аккаунта)${NC}"
        echo -e "${YELLOW}3. Только DNS и сеть (Работа без VPN)${NC}"
        echo -e "4. Указать путь к Antigravity вручную"
        echo -e "5. Диагностика и проверка связи"
        echo -e "${RED}6. ПОЛНЫЙ ОТКАТ (вернуть всё в исходное состояние)${NC}"
        echo -e "0. Выход\n"

        read -rp "Выберите действие [0-6]: " action

        case "$action" in
            1)
                select_dns
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
                        codesign --force --deep --sign - --preserve-metadata=entitlements,requirements,flags "$inst" 2>/dev/null || true
                    fi
                done < <(find_installations)

                apply_dns_resolvers "$DNS_LABEL" "${DNS_SERVERS[@]}"
                echo -e "\n${GREEN}[✓] Готово! Запустите Antigravity и авторизуйтесь.${NC}"
                read -rp "Нажмите Enter для продолжения..."
                ;;
            2)
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
                        codesign --force --deep --sign - --preserve-metadata=entitlements,requirements,flags "$inst" 2>/dev/null || true
                    fi
                done < <(find_installations)
                read -rp "Нажмите Enter для продолжения..."
                ;;
            3)
                select_dns
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
                            codesign --force --deep --sign - --preserve-metadata=entitlements,requirements,flags "$custom_path" 2>/dev/null || true
                        fi
                    fi
                else
                    echo -e "${RED}[!] Путь не существует: $custom_path${NC}"
                fi
                read -rp "Нажмите Enter для продолжения..."
                ;;
            5)
                echo -e "\n${CYAN}--- Проверка связи с Google API ---${NC}"
                if nc -z -G 3 cloudcode-pa.googleapis.com 443 2>/dev/null; then
                    echo -e "  ${GREEN}[✓] Google API доступен (TCP 443 -> cloudcode-pa.googleapis.com)${NC}"
                elif curl -Is --connect-timeout 3 https://cloudcode-pa.googleapis.com 2>/dev/null | head -n 1 | grep -q "HTTP"; then
                    echo -e "  ${GREEN}[✓] Google API доступен (HTTPS -> cloudcode-pa.googleapis.com)${NC}"
                else
                    echo -e "  ${RED}[✗] Таймаут / ошибка соединения с Google API (cloudcode-pa.googleapis.com)${NC}"
                fi
                echo -e "\n${CYAN}--- Активные scoped резолверы (/etc/resolver) ---${NC}"
                scutil --dns | grep -A 4 "resolver #" | head -n 25 || true
                read -rp "Нажмите Enter для продолжения..."
                ;;
            6)
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
