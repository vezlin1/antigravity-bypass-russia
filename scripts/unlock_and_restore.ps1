# ANTIGRAVITY-BYPASS-RUSSIA (v1.0.1) - PowerShell Bypass & Rollback Tool
# Поддержка: Antigravity 2.0+ (Core), IDE UI (main.js) & Antigravity CLI (agy)
# Двухуровневый патчинг (Опкоды x64/ARM64 + Строки) + Высокоскоростной C# движок + Обход VPN

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Авто-элевация процесса (UAC)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Запрос прав Администратора (UAC)..." -ForegroundColor Cyan
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } catch {
        Write-Host "[!] Запрос прав Администратора отклонен." -ForegroundColor Yellow
    }
    exit
}

# Блокировка параллельного запуска (Single Instance Mutex)
try {
    $createdNew = $false
    $script:appMutex = New-Object System.Threading.Mutex($true, "Global\AntigravityBypassRussia_PS_Lock", [ref]$createdNew)
    if (-not $createdNew) {
        Write-Host "[!] Antigravity Bypass Russia уже запущен в другом окне." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 1500
        exit
    }
} catch {
    # Игнорировать, если глобальный мьютекс недоступен
}

# Встраивание высокоскоростного C# класса для мгновенного патчинга 150MB бинарников и опкодов
if (-not ([System.Management.Automation.PSTypeName]'AgFastEngine').Type) {
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class AgFastEngine {
    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = true)]
    public static extern int DnsFlushResolverCache();

    [DllImport("shell32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsUserAnAdmin();

    public static readonly byte[] StringFrom = Encoding.ASCII.GetBytes("ineligible");
    public static readonly byte[] StringTo   = Encoding.ASCII.GetBytes("inexigible");

    private static readonly byte[] MgrX64OrigHead = new byte[] { 0x80, 0x78, 0x08, 0x00, 0x74 };
    private static readonly byte[] MgrX64Fix      = new byte[] { 0xC6, 0x40, 0x08, 0x01, 0x90, 0x90 };
    private static readonly byte[] MgrX64Restore  = new byte[] { 0x80, 0x78, 0x08, 0x00, 0x74, 0x18 };
    private static readonly byte[] MgrX64PatHead  = new byte[] { 0xC6, 0x40, 0x08, 0x01, 0x90, 0x90, 0x48, 0x8B };

    private static readonly byte[] MgrArm64Orig    = new byte[] { 0x03, 0x20, 0x40, 0x39, 0x04, 0x00, 0x00, 0x14, 0x62, 0x03, 0x00, 0xAA };
    private static readonly byte[] MgrArm64Fix     = new byte[] { 0x23, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0x39 };
    private static readonly byte[] MgrArm64Restore = new byte[] { 0x03, 0x20, 0x40, 0x39, 0x04, 0x00, 0x00, 0x14 };
    private static readonly byte[] MgrArm64Patched = new byte[] { 0x23, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0x39, 0x62, 0x03, 0x00, 0xAA };

    private static readonly byte[] CliX64OrigHead = new byte[] { 0x48, 0x85, 0xC0, 0x0F, 0x84 };
    private static readonly byte[] CliX64Fix      = new byte[] { 0x48, 0x85, 0xC0, 0x90 };
    private static readonly byte[] CliX64Restore  = new byte[] { 0x80, 0x78, 0x08, 0x00 };
    private static readonly byte[] CliX64PatMid   = new byte[] { 0x48, 0x85, 0xC0, 0x90, 0x0F, 0x85 };

    public static bool IsAdmin() {
        try {
            return IsUserAnAdmin();
        } catch {
            using (var id = WindowsIdentity.GetCurrent()) {
                var principal = new WindowsPrincipal(id);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }

    public static void ClearReadOnly(string path) {
        if (File.Exists(path)) {
            FileAttributes attrs = File.GetAttributes(path);
            if ((attrs & FileAttributes.ReadOnly) != 0) {
                File.SetAttributes(path, attrs & ~FileAttributes.ReadOnly);
            }
        }
    }

    public static int IndexOfSequence(byte[] buffer, byte[] pattern, int startIndex = 0) {
        if (buffer == null || pattern == null || buffer.Length < pattern.Length) return -1;
        int end = buffer.Length - pattern.Length;
        byte first = pattern[0];
        for (int i = startIndex; i <= end; i++) {
            if (buffer[i] == first) {
                bool match = true;
                for (int j = 1; j < pattern.Length; j++) {
                    if (buffer[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return i;
            }
        }
        return -1;
    }

    public static int ReplaceSlice(byte[] data, byte[] from, byte[] to) {
        if (from.Length != to.Length || data.Length < from.Length || from.Length == 0) return 0;
        int count = 0;
        int idx = 0;
        while ((idx = IndexOfSequence(data, from, idx)) != -1) {
            Buffer.BlockCopy(to, 0, data, idx, to.Length);
            count++;
            idx += from.Length;
        }
        return count;
    }

    public static List<int> FindMgrX64Orig(byte[] data) {
        var matches = new List<int>();
        int idx = 0;
        while ((idx = IndexOfSequence(data, MgrX64OrigHead, idx)) != -1) {
            if (idx + 15 <= data.Length &&
                data[idx + 6] == 0x48 && data[idx + 7] == 0x8B &&
                data[idx + 9] == 0x24 &&
                data[idx + 11] == 0x48 && data[idx + 12] == 0x89 &&
                data[idx + 14] == 0x60) {
                matches.Add(idx);
            }
            idx++;
        }
        return matches;
    }

    public static List<int> FindCliX64Orig(byte[] data) {
        var matches = new List<int>();
        int idx = 0;
        while ((idx = IndexOfSequence(data, CliX64OrigHead, idx)) != -1) {
            if (idx + 15 <= data.Length &&
                data[idx + 9] == 0x80 && data[idx + 10] == 0x78 &&
                data[idx + 11] == 0x08 && data[idx + 12] == 0x00 &&
                data[idx + 13] == 0x0F && data[idx + 14] == 0x85) {
                matches.Add(idx);
            }
            idx++;
        }
        return matches;
    }

    public static string CheckState(string path) {
        if (!File.Exists(path)) return "missing";
        try {
            byte[] data = File.ReadAllBytes(path);
            if (IndexOfSequence(data, MgrX64PatHead) != -1 ||
                IndexOfSequence(data, MgrArm64Patched) != -1 ||
                IndexOfSequence(data, CliX64PatMid) != -1 ||
                IndexOfSequence(data, StringTo) != -1) {
                return "patched";
            }
            if (FindMgrX64Orig(data).Count > 0 ||
                IndexOfSequence(data, MgrArm64Orig) != -1 ||
                FindCliX64Orig(data).Count > 0 ||
                IndexOfSequence(data, StringFrom) != -1) {
                return "stock";
            }
        } catch {}
        return "unknown";
    }

    public static string PatchBinary(string path) {
        ClearReadOnly(path);
        byte[] data = File.ReadAllBytes(path);
        string name = Path.GetFileName(path).ToLower();
        var details = new List<string>();

        bool matchedX64 = false;
        bool matchedArm = false;

        if (!name.Contains("agy")) {
            var x64Hits = FindMgrX64Orig(data);
            foreach (int idx in x64Hits) {
                if (idx + MgrX64Fix.Length <= data.Length) {
                    Buffer.BlockCopy(MgrX64Fix, 0, data, idx, MgrX64Fix.Length);
                    matchedX64 = true;
                }
            }
            if (matchedX64) details.Add("hasValidAuth(x64)");

            int armIdx = 0;
            while ((armIdx = IndexOfSequence(data, MgrArm64Orig, armIdx)) != -1) {
                Buffer.BlockCopy(MgrArm64Fix, 0, data, armIdx, MgrArm64Fix.Length);
                matchedArm = true;
                armIdx += MgrArm64Orig.Length;
            }
            if (matchedArm) details.Add("hasValidAuth(ARM64)");
        }

        if (name.Contains("agy") || (!matchedX64 && !matchedArm)) {
            var cliHits = FindCliX64Orig(data);
            bool matchedCli = false;
            foreach (int idx in cliHits) {
                int offset = idx + 9;
                if (offset + CliX64Fix.Length <= data.Length) {
                    Buffer.BlockCopy(CliX64Fix, 0, data, offset, CliX64Fix.Length);
                    matchedCli = true;
                }
            }
            if (matchedCli) details.Add("CLI_GATE(x64)");
        }

        int strCount = ReplaceSlice(data, StringFrom, StringTo);
        if (strCount > 0) details.Add("string_fix(" + strCount + ")");

        if (details.Count == 0) return "уже пропатчен или сигнатуры не найдены";

        File.WriteAllBytes(path, data);
        return "успешно (" + string.Join(" + ", details.ToArray()) + ")";
    }

    public static string RestoreBinary(string path) {
        ClearReadOnly(path);
        byte[] data = File.ReadAllBytes(path);
        string name = Path.GetFileName(path).ToLower();
        var details = new List<string>();

        if (name.Contains("language_server")) {
            int idx = 0;
            bool matchedX64 = false;
            while ((idx = IndexOfSequence(data, MgrX64PatHead, idx)) != -1) {
                Buffer.BlockCopy(MgrX64Restore, 0, data, idx, MgrX64Restore.Length);
                matchedX64 = true;
                idx += MgrX64Restore.Length;
            }
            if (matchedX64) details.Add("opcodes_x64");

            int armIdx = 0;
            bool matchedArm = false;
            while ((armIdx = IndexOfSequence(data, MgrArm64Patched, armIdx)) != -1) {
                Buffer.BlockCopy(MgrArm64Restore, 0, data, armIdx, MgrArm64Restore.Length);
                matchedArm = true;
                armIdx += MgrArm64Restore.Length;
            }
            if (matchedArm) details.Add("opcodes_arm64");
        }

        if (name.Contains("agy")) {
            int idx = 0;
            bool matchedCli = false;
            while ((idx = IndexOfSequence(data, CliX64PatMid, idx)) != -1) {
                Buffer.BlockCopy(CliX64Restore, 0, data, idx, CliX64Restore.Length);
                matchedCli = true;
                idx += CliX64Restore.Length;
            }
            if (matchedCli) details.Add("opcodes_cli");
        }

        int strCount = ReplaceSlice(data, StringTo, StringFrom);
        if (strCount > 0) details.Add("strings(" + strCount + ")");

        if (details.Count == 0) return "файл уже в исходном состоянии";

        File.WriteAllBytes(path, data);
        return "исходные байты восстановлены (" + string.Join(" + ", details.ToArray()) + ")";
    }
}
"@
}

$NRPT_TAG = "ANTIGRAVITY-BYPASS-RUSSIA"

$NRPT_DOMAINS = @(
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.sandbox.googleapis.com",
    "antigravity-pa.googleapis.com",
    "antigravity.googleapis.com",
    "antigravity.google",
    "antigravity-unleash.goog",
    "cloudaicompanion.googleapis.com",
    "cloudaicompanion.sandbox.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "developerprofiles-pa.googleapis.com",
    "aicode.googleapis.com",
    "aida.googleapis.com",
    "geller-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "gemini.google.com",
    "gemini.google",
    "gemini.gstatic.com",
    "bard.google.com",
    "generativeai.google",
    "aistudio.google.com",
    "ai.studio",
    "ai.google.dev",
    "makersuite.google.com",
    "alkalicore-pa.clients6.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "webchannel-alkalimakersuite-pa.clients6.google.com",
    "alkalimakersuite-pa.googleapis.com",
    "alkalimakersuiteapplets.pa.googleapis.com",
    "people-pa.clients6.google.com",
    "notebooklm-pa.googleapis.com",
    "notebooklm.googleapis.com",
    "notebooklm.google",
    "notebooklm.google.com",
    "notebook.google.com",
    "jules.google",
    "jules.google.com",
    "opal.google",
    "opal.google.com",
    "labs.google",
    "labs.google.com",
    "flow.google",
    "aisandbox-pa.googleapis.com",
    "deepmind.com",
    "deepmind.google",
    "stitch.withgoogle.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "sts.googleapis.com",
    "aiplatform.googleapis.com",
    "s-aiplatform.googleapis.com",
    "play.googleapis.com"
)

$ALL_DNS_IPS        = @("111.88.96.50", "111.88.96.51", "176.108.243.68", "176.108.243.69", "176.108.243.70", "176.108.243.71")
$XBOX_SERVERS       = @("111.88.96.50", "111.88.96.51", "2a00:ab00:1233:26::50", "2a00:ab00:1233:26::51")

function Stop-AntigravityProcesses {
    Write-Host "Завершение процессов..." -ForegroundColor Gray
    Stop-ScheduledTask -TaskName 'AntigravityBypassRussia' -ErrorAction SilentlyContinue | Out-Null
    taskkill /F /T /IM ag_dns.exe 2>$null | Out-Null
    $procs = @("Antigravity", "Antigravity IDE", "Antigravity CLI", "antigravity", "antigravity-ide", "agy", "language_server", "language_server_windows_x64", "language_server_windows_arm64", "ag_dns")
    foreach ($p in $procs) {
        Stop-Process -Name $p -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 150
}

function Clear-IdeCaches {
    $cleared = 0
    $targets = @(
        "$env:APPDATA\Antigravity IDE\CachedData",
        "$env:APPDATA\Antigravity IDE\Code Cache\js",
        "$env:APPDATA\Antigravity IDE\Code Cache\wasm",
        "$env:APPDATA\Antigravity\CachedData",
        "$env:APPDATA\Antigravity\Code Cache\js",
        "$env:LOCALAPPDATA\Antigravity IDE\CachedData",
        "$env:LOCALAPPDATA\Antigravity IDE\Code Cache\js",
        "$env:USERPROFILE\scoop\persist\antigravity-ide\data\user-data\CachedData",
        "$env:USERPROFILE\scoop\persist\antigravity-ide\data\user-data\Code Cache\js"
    )
    foreach ($t in $targets) {
        if (Test-Path -LiteralPath $t) {
            Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction SilentlyContinue
            $cleared++
        }
    }
    return $cleared
}

function Find-Installations {
    $paths = [System.Collections.Generic.List[string]]::new()
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Antigravity",
        "$env:LOCALAPPDATA\Programs\antigravity",
        "$env:LOCALAPPDATA\Programs\Antigravity IDE",
        "$env:LOCALAPPDATA\Antigravity",
        "$env:LOCALAPPDATA\Antigravity IDE",
        "$env:LOCALAPPDATA\agy",
        "$env:LOCALAPPDATA\agy\bin",
        "$env:ProgramFiles\Antigravity",
        "$env:ProgramFiles\Antigravity IDE",
        "${env:ProgramFiles(x86)}\Antigravity",
        "${env:ProgramFiles(x86)}\Antigravity IDE",
        "$env:USERPROFILE\scoop\apps\antigravity-ide\current",
        "$env:USERPROFILE\scoop\apps\agy\current"
    )

    foreach ($cand in $candidates) {
        if (Test-Path -LiteralPath $cand) {
            $full = (Get-Item -LiteralPath $cand).FullName
            $exists = $false
            foreach ($p in $paths) {
                if ($p.Equals($full, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $exists = $true
                    break
                }
            }
            if (-not $exists) {
                $paths.Add($full)
            }
        }
    }

    $extRoots = @(
        "$env:USERPROFILE\.vscode\extensions",
        "$env:USERPROFILE\.vscode-insiders\extensions",
        "$env:USERPROFILE\.cursor\extensions",
        "$env:USERPROFILE\.windsurf\extensions",
        "$env:USERPROFILE\.vscodium\extensions"
    )
    foreach ($er in $extRoots) {
        if (Test-Path -LiteralPath $er) {
            Get-ChildItem -LiteralPath $er -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*antigravity*" } | ForEach-Object {
                $full = $_.FullName
                $exists = $false
                foreach ($p in $paths) {
                    if ($p.Equals($full, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $exists = $true
                        break
                    }
                }
                if (-not $exists) {
                    $paths.Add($full)
                }
            }
        }
    }
    return $paths
}

function Find-AllTargets($rootPath) {
    $targets = [System.Collections.Generic.List[PSObject]]::new()

    $binTargets = @(
        @{ Path = "$rootPath\resources\bin\language_server.exe"; Name = "language_server.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\resources\app\extensions\antigravity\bin\language_server_windows_x64.exe"; Name = "language_server_windows_x64.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\resources\app\extensions\antigravity\bin\language_server_windows_arm64.exe"; Name = "language_server_windows_arm64.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\resources\app\extensions\antigravity\bin\language_server.exe"; Name = "language_server.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\bin\language_server_windows_x64.exe"; Name = "language_server_windows_x64.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\bin\language_server_windows_arm64.exe"; Name = "language_server_windows_arm64.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\bin\language_server.exe"; Name = "language_server.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\language_server.exe"; Name = "language_server.exe (Core 2.0)"; Type = "Binary" },
        @{ Path = "$rootPath\agy.exe"; Name = "agy.exe (Antigravity CLI)"; Type = "Binary" },
        @{ Path = "$rootPath\bin\agy.exe"; Name = "agy.exe (Antigravity CLI)"; Type = "Binary" }
    )
    foreach ($bt in $binTargets) {
        if (Test-Path -LiteralPath $bt.Path) {
            $targets.Add([PSCustomObject]$bt)
        }
    }

    $jsTargets = @(
        "$rootPath\resources\app\out\vs\code\electron-main\main.js",
        "$rootPath\resources\app\out\main.js",
        "$rootPath\resources\app\main.js",
        "$rootPath\out\vs\code\electron-main\main.js",
        "$rootPath\out\main.js",
        "$rootPath\main.js",
        "$rootPath\dist\extension.js",
        "$rootPath\out\extension.js",
        "$rootPath\extension.js"
    )
    foreach ($jt in $jsTargets) {
        if (Test-Path -LiteralPath $jt) {
            $targets.Add([PSCustomObject]@{ Path = $jt; Name = "main.js / extension.js (Antigravity UI)"; Type = "MainJs" })
            break
        }
    }

    return $targets
}

function Patch-MainJsFile($filePath) {
    $bak = "$filePath.bak"
    if (-not (Test-Path -LiteralPath $bak)) {
        Copy-Item -LiteralPath $filePath -Destination $bak -Force
    }

    if (Test-Path -LiteralPath $filePath) {
        $fileItem = Get-Item -LiteralPath $filePath
        if ($fileItem.IsReadOnly) { $fileItem.IsReadOnly = $false }
    }

    $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
    if ($content.Contains("resetIsTierGCPTos(),true") -or $content.Contains("resetIsTierGCPTos();true")) {
        Clear-IdeCaches | Out-Null
        return "уже пропатчен ранее (isGoogleInternal -> true)"
    }

    $pattern = "(resetIsTierGCPTos\(\)\s*[,;]\s*)(?:this|[A-Za-z_`$0-9]+)(?:\.[A-Za-z_`$0-9]+)*\.isGoogleInternal"
    if ($content -match $pattern) {
        $newContent = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, '${1}true')
        [System.IO.File]::WriteAllText($filePath, $newContent, [System.Text.Encoding]::UTF8)
        $caches = Clear-IdeCaches
        return "успешно (isGoogleInternal -> true, кэш V8 сброшен: $caches папок)"
    }

    return "сигнатура не найдена"
}

function Restore-MainJsFile($filePath) {
    $bak = "$filePath.bak"
    if (Test-Path -LiteralPath $bak) {
        if ((Get-Item -LiteralPath $bak).Length -gt 0) {
            Copy-Item -LiteralPath $bak -Destination $filePath -Force
            Remove-Item -LiteralPath $bak -Force
            Clear-IdeCaches | Out-Null
            return "восстановлен из резервной копии (.bak)"
        }
    }

    if (Test-Path -LiteralPath $filePath) {
        $fileItem = Get-Item -LiteralPath $filePath
        if ($fileItem.IsReadOnly) { $fileItem.IsReadOnly = $false }
    }

    $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
    $pattern = "(resetIsTierGCPTos\(\)\s*[,;]\s*)true"
    if ($content -match $pattern) {
        $newContent = [System.Text.RegularExpressions.Regex]::Replace($content, $pattern, '${1}this.isGoogleInternal')
        [System.IO.File]::WriteAllText($filePath, $newContent, [System.Text.Encoding]::UTF8)
        Clear-IdeCaches | Out-Null
        return "исходное состояние восстановлено"
    }

    return "патч не обнаружен (файл уже в исходном состоянии)"
}

function Patch-BinaryFile($filePath) {
    $bak = "$filePath.bak"
    if (-not (Test-Path -LiteralPath $bak)) {
        Copy-Item -LiteralPath $filePath -Destination $bak -Force
    }
    return [AgFastEngine]::PatchBinary($filePath)
}

function Restore-BinaryFile($filePath) {
    $bak = "$filePath.bak"
    if (Test-Path -LiteralPath $bak) {
        if ((Get-Item -LiteralPath $bak).Length -gt 0) {
            Copy-Item -LiteralPath $bak -Destination $filePath -Force
            Remove-Item -LiteralPath $bak -Force
            return "восстановлен из резервной копии (.bak)"
        }
    }
    return [AgFastEngine]::RestoreBinary($filePath)
}

function Get-PhysicalEgress {
    $phys = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'WireGuard|TAP|Wintun|OpenVPN|Tailscale|Cisco|GlobalProtect|PANGP' } | ForEach-Object { $_.ifIndex })
    $def = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    $mine = @($def | Where-Object { $phys -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0' })
    if ($mine.Count -gt 0) {
        $best = $mine | Sort-Object { [int]$_.RouteMetric + [int](Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric } | Select-Object -First 1
        return $best
    }
    return $null
}

function Add-DirectDnsRoutes($customServers) {
    $egress = Get-PhysicalEgress
    if ($egress -and $egress.NextHop -match '\d+\.\d+\.\d+\.\d+') {
        $targets = [System.Collections.Generic.List[string]]::new($ALL_DNS_IPS)
        if ($customServers) {
            foreach ($s in $customServers) {
                if ($s -match '^\d+\.\d+\.\d+\.\d+$' -and -not $targets.Contains($s)) {
                    $targets.Add($s)
                }
            }
        }
        foreach ($ip in $targets) {
            route add $ip mask 255.255.255.255 $egress.NextHop if $egress.ifIndex | Out-Null
        }
    }
}

function Remove-DirectDnsRoutes {
    $ips = $ALL_DNS_IPS
    $conf = "$env:ProgramData\AntigravityBypassRussia\upstream.conf"
    if (Test-Path -LiteralPath $conf) {
        $lines = Get-Content -LiteralPath $conf -ErrorAction SilentlyContinue
        if ($lines) { $ips += @($lines) }
    }
    foreach ($ip in ($ips | Select-Object -Unique)) {
        if (-not [string]::IsNullOrWhiteSpace($ip)) {
            route delete $ip | Out-Null
        }
    }
}

function Take-OverConflictingRules {
    $ours = $NRPT_DOMAINS | ForEach-Object { $_.ToLower() }
    $foreign = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -ne $NRPT_TAG }
    foreach ($r in $foreign) {
        $hit = @()
        $rest = @()
        foreach ($n in $r.Namespace) {
            $k = $n.Trim().TrimStart('.').TrimEnd('.').ToLower()
            if ($ours -contains $k -or $ours -contains ".$k" -or $ours -contains $n.Trim().ToLower()) { 
                $hit += $n 
            } else { 
                $rest += $n 
            }
        }
        if ($hit.Count -gt 0) {
            if ($rest.Count -eq 0) {
                Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction SilentlyContinue
            } else {
                Set-DnsClientNrptRule -Name $r.Name -Namespace $rest -ErrorAction SilentlyContinue
            }
        }
    }
}

function Select-DnsServers {
    Write-Host "`nВыберите DNS-провайдер для маршрутизации:" -ForegroundColor Cyan
    Write-Host "  1. Xbox-DNS.ru (111.88.96.50, 111.88.96.51)" -ForegroundColor Yellow
    Write-Host "  2. Ввести свой DNS / IP адрес личного VPS" -ForegroundColor Green
    
    $c = Read-Host "Ваш выбор [1-2] (Enter - Xbox-DNS)"
    switch ($c) {
        "2" {
            $ip = Read-Host "Введите IP-адрес(а) DNS через запятую"
            if ([string]::IsNullOrWhiteSpace($ip)) {
                return [PSCustomObject]@{ Label = "Xbox-DNS.ru"; Servers = $XBOX_SERVERS }
            }
            $customServers = @($ip.Split(", ") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            return [PSCustomObject]@{ Label = "Пользовательский DNS"; Servers = $customServers }
        }
        Default {
            Write-Host "Выбран: Xbox-DNS.ru" -ForegroundColor Yellow
            return [PSCustomObject]@{ Label = "Xbox-DNS.ru"; Servers = $XBOX_SERVERS }
        }
    }
}

function Apply-DnsSettings($servers, $label) {
    Remove-DnsSettings
    Take-OverConflictingRules
    
    $pool = [runspacefactory]::CreateRunspacePool(1, [System.Math]::Min(16, [Environment]::ProcessorCount * 2))
    $pool.Open()

    $tasks = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($domain in $NRPT_DOMAINS) {
        $ps = [powershell]::Create().AddScript({
            param($d, $s, $tag, $lbl)
            Add-DnsClientNrptRule -Namespace $d -NameServers $s -Comment $tag -DisplayName "Antigravity Bypass Russia DNS ($lbl)" -ErrorAction SilentlyContinue | Out-Null
        }).AddArgument($domain).AddArgument($servers).AddArgument($NRPT_TAG).AddArgument($label)
        $ps.RunspacePool = $pool
        $tasks.Add([PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() })
    }

    foreach ($t in $tasks) {
        $t.Pipe.EndInvoke($t.Handle)
        $t.Pipe.Dispose()
    }
    $pool.Close()
    $pool.Dispose()

    Add-DirectDnsRoutes $servers
    [AgFastEngine]::DnsFlushResolverCache() | Out-Null
    netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 46 4 | Out-Null
}

function Remove-DnsSettings {
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $NRPT_TAG } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
    Remove-DirectDnsRoutes
    [AgFastEngine]::DnsFlushResolverCache() | Out-Null
    netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 35 4 | Out-Null

    # Откат фоновых задач и служб
    Stop-Process -Name 'ag_dns' -Force -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName 'AntigravityBypassRussia' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'AntigravityBypassRussia' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path "$env:ProgramData\AntigravityBypassRussia") { Remove-Item -LiteralPath "$env:ProgramData\AntigravityBypassRussia" -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$env:LOCALAPPDATA\AntigravityBypassRussia") { Remove-Item -LiteralPath "$env:LOCALAPPDATA\AntigravityBypassRussia" -Recurse -Force -ErrorAction SilentlyContinue }

    # Очистка hosts
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hostsPath) {
        [AgFastEngine]::ClearReadOnly($hostsPath)
        $content = [System.IO.File]::ReadAllText($hostsPath, [System.Text.Encoding]::UTF8)
        $newHosts = [System.Text.RegularExpressions.Regex]::Replace($content, "(?s)# BEGIN ANTIGRAVITY-BYPASS-RUSSIA.*?# END ANTIGRAVITY-BYPASS-RUSSIA\r?\n?", "")
        if ($newHosts -ne $content) {
            [System.IO.File]::WriteAllText($hostsPath, $newHosts, [System.Text.Encoding]::UTF8)
        }
    }
}

function Test-GoogleConnectivity {
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect("cloudcode-pa.googleapis.com", 443, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(3000, $false)
        if ($wait) {
            $tcp.EndConnect($iar)
            $sw.Stop()
            $remoteIp = $tcp.Client.RemoteEndPoint.ToString()
            $tcp.Close()
            return "[✓] Доступен ($($sw.ElapsedMilliseconds) мс) — cloudcode-pa.googleapis.com ($remoteIp)"
        } else {
            $tcp.Close()
            return "[✗] Таймаут подключения к cloudcode-pa.googleapis.com:443"
        }
    } catch {
        return "[✗] Ошибка соединения: $_"
    }
}

function Print-Dashboard {
    $rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $NRPT_TAG }
    $dnsStr = "[Не настроено]"
    if ($rules) {
        $ns = ($rules | Select-Object -First 1).NameServers -join ','
        if ($ns -like "*127.0.0.53*" -or $ns -like "*127.0.0.1*") {
            $conf = "$env:ProgramData\AntigravityBypassRussia\upstream.conf"
            if (Test-Path -LiteralPath $conf) {
                $ns = (Get-Content -LiteralPath $conf -ErrorAction SilentlyContinue) -join ','
            } else {
                $ns = "111.88.96.50"
            }
        }
        $prov = if ($ns -like "*111.88.96.50*" -or $ns -like "*176.108.243.68*" -or $ns -like "*111.88.96.51*") {
            "Xbox-DNS.ru"
        } else {
            "Пользовательский DNS"
        }
        $dnsStr = "[✓] ($prov)"
    }

    $coreState = "[Не установлено]"
    $ideState  = "[Не установлено]"
    $cliState  = "[Не установлено]"

    $installs = Find-Installations
    foreach ($inst in $installs) {
        $targets = Find-AllTargets $inst
        foreach ($t in $targets) {
            if ($t.Type -eq "MainJs") {
                $c = [System.IO.File]::ReadAllText($t.Path, [System.Text.Encoding]::UTF8)
                if ($c.Contains("resetIsTierGCPTos(),true") -or $c.Contains("resetIsTierGCPTos();true")) { 
                    $ideState = "[✓] Пропатчен" 
                } elseif ($ideState -eq "[Не установлено]") { 
                    $ideState = "[Исходный]" 
                }
            } elseif ($t.Name -like "*language_server*") {
                $st = [AgFastEngine]::CheckState($t.Path)
                if ($st -eq "patched") { $coreState = "[✓] Пропатчен" }
                elseif ($st -eq "stock" -and $coreState -eq "[Не установлено]") { $coreState = "[Исходный]" }
                elseif ($coreState -eq "[Не установлено]") { $coreState = "[Исходный]" }
            } elseif ($t.Name -like "*agy*") {
                $st = [AgFastEngine]::CheckState($t.Path)
                if ($st -eq "patched") { $cliState = "[✓] Пропатчен" }
                elseif ($st -eq "stock" -and $cliState -eq "[Не установлено]") { $cliState = "[Исходный]" }
                elseif ($cliState -eq "[Не установлено]") { $cliState = "[Исходный]" }
            }
        }
    }

    Write-Host "  ┌──────────────────── ТЕКУЩИЙ СТАТУС ────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  • Права процесса:       " -NoNewline
    if ([AgFastEngine]::IsAdmin()) {
        Write-Host "[✓] Администратор" -ForegroundColor Green
    } else {
        Write-Host "[!] Нет прав (запустите с правами администратора)" -ForegroundColor Yellow
    }

    Write-Host "  • Сеть и DNS (NRPT):    " -NoNewline
    if ($rules) { Write-Host $dnsStr -ForegroundColor Green } else { Write-Host $dnsStr -ForegroundColor DarkGray }

    Write-Host "  • Antigravity 2.0 Core: " -NoNewline
    if ($coreState -like "*Пропатчен*") { Write-Host $coreState -ForegroundColor Green } elseif ($coreState -like "*Исходный*") { Write-Host $coreState -ForegroundColor Yellow } else { Write-Host $coreState -ForegroundColor DarkGray }

    Write-Host "  • Antigravity IDE UI:   " -NoNewline
    if ($ideState -like "*Пропатчен*") { Write-Host $ideState -ForegroundColor Green } elseif ($ideState -like "*Исходный*") { Write-Host $ideState -ForegroundColor Yellow } else { Write-Host $ideState -ForegroundColor DarkGray }

    Write-Host "  • Antigravity CLI:      " -NoNewline
    if ($cliState -like "*Пропатчен*") { Write-Host $cliState -ForegroundColor Green } elseif ($cliState -like "*Исходный*") { Write-Host $cliState -ForegroundColor Yellow } else { Write-Host $cliState -ForegroundColor DarkGray }
    Write-Host "  └────────────────────────────────────────────────────────┘`n" -ForegroundColor DarkGray
}

function Show-Diagnostics {
    Clear-Host
    Write-Host "================ ДИАГНОСТИКА СИСТЕМЫ ================" -ForegroundColor Cyan
    Write-Host "  1. Права процесса:     [✓] Администратор" -ForegroundColor Green

    $rules = (Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $NRPT_TAG } | Measure-Object).Count
    if ($rules -gt 0) {
        Write-Host "  2. Правила NRPT DNS:   [✓] АКТИВНЫ (правил: $rules)" -ForegroundColor Green
    } else {
        Write-Host "  2. Правила NRPT DNS:   [--] Отключены (0 правил)" -ForegroundColor Gray
    }

    $egress = Get-PhysicalEgress
    if ($egress) {
        Write-Host "  3. Физический шлюз:    $($egress.NextHop) (ifIndex: $($egress.ifIndex))" -ForegroundColor Cyan
    }

    $conn = Test-GoogleConnectivity
    Write-Host "  4. Связь с Google API: $conn" -ForegroundColor Green

    Write-Host "`n--- Статус файлов Antigravity ---" -ForegroundColor Yellow
    $installs = Find-Installations
    foreach ($inst in $installs) {
        Write-Host "  Папка: $inst" -ForegroundColor Cyan
        $targets = Find-AllTargets $inst
        foreach ($t in $targets) {
            Write-Host "    • $($t.Name)" -ForegroundColor Green
        }
    }
    Write-Host "=====================================================" -ForegroundColor Cyan
    Pause
}

function Show-Menu {
    Clear-Host
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "          ANTIGRAVITY-BYPASS-RUSSIA (v1.0.1)         " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "Открытая утилита обхода блокировок и чистого отката`n"

    Print-Dashboard

    Write-Host "1. Полная разблокировка (Файлы Core 2.0/IDE/CLI + Сеть/DNS)" -ForegroundColor Green
    Write-Host "2. Только файлы (Работа без смены страны аккаунта)" -ForegroundColor Cyan
    Write-Host "3. Только DNS и сеть (Работа без VPN)" -ForegroundColor Yellow
    Write-Host "4. Указать путь к Antigravity вручную" -ForegroundColor White
    Write-Host "5. Диагностика и проверка связи" -ForegroundColor Cyan
    Write-Host "6. ПОЛНЫЙ ОТКАТ (вернуть всё в исходное состояние)" -ForegroundColor Red
    Write-Host "0. Выход`n"

    $choice = Read-Host "Выберите действие [0-6]"
    switch ($choice) {
        "1" {
            $dnsInfo = Select-DnsServers
            $dnsLabel = $dnsInfo.Label
            $dnsServers = $dnsInfo.Servers

            Stop-AntigravityProcesses
            $installs = Find-Installations
            foreach ($inst in $installs) {
                Write-Host "`nПапка: $inst" -ForegroundColor Cyan
                $targets = Find-AllTargets $inst
                foreach ($t in $targets) {
                    if ($t.Type -eq "MainJs") {
                        $res = Patch-MainJsFile $t.Path
                        Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                    } else {
                        $res = Patch-BinaryFile $t.Path
                        Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                    }
                }
            }
            Clear-IdeCaches | Out-Null
            Write-Host "`nНастройка селективной DNS-маршрутизации через $dnsLabel..." -ForegroundColor Yellow
            Apply-DnsSettings $dnsServers $dnsLabel
            Write-Host "  [✓] Правила DNS ($dnsLabel) и прямые маршруты успешно применены!" -ForegroundColor Green
            Write-Host "`nГотово! Запустите Antigravity и войдите в аккаунт." -ForegroundColor Green
            Pause
        }
        "2" {
            Stop-AntigravityProcesses
            $installs = Find-Installations
            foreach ($inst in $installs) {
                Write-Host "`nПапка: $inst" -ForegroundColor Cyan
                $targets = Find-AllTargets $inst
                foreach ($t in $targets) {
                    if ($t.Type -eq "MainJs") {
                        $res = Patch-MainJsFile $t.Path
                        Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                    } else {
                        $res = Patch-BinaryFile $t.Path
                        Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                    }
                }
            }
            $caches = Clear-IdeCaches
            Write-Host "  [✓] Кэш V8 сброшен ($caches папок)" -ForegroundColor Green
            Pause
        }
        "3" {
            $dnsInfo = Select-DnsServers
            Apply-DnsSettings $dnsInfo.Servers $dnsInfo.Label
            Write-Host "[✓] Правила DNS ($($dnsInfo.Label)), статические маршруты и IPv4 применены!" -ForegroundColor Green
            Pause
        }
        "4" {
            $customPath = Read-Host "Введите путь к папке или файлу Antigravity"
            if (-not [string]::IsNullOrWhiteSpace($customPath)) {
                $expanded = [System.Environment]::ExpandEnvironmentVariables($customPath.Trim('"').Trim("'"))
                if (Test-Path -LiteralPath $expanded) {
                    Stop-AntigravityProcesses
                    $targets = Find-AllTargets $expanded
                    if ($targets.Count -eq 0 -and (Test-Path -PathType Leaf -LiteralPath $expanded)) {
                        $name = [System.IO.Path]::GetFileName($expanded)
                        if ($name -like "*main.js*") {
                            $res = Patch-MainJsFile $expanded
                            Write-Host "  [✓] $name - $res" -ForegroundColor Green
                        } else {
                            $res = Patch-BinaryFile $expanded
                            Write-Host "  [✓] $name - $res" -ForegroundColor Green
                        }
                    } else {
                        foreach ($t in $targets) {
                            if ($t.Type -eq "MainJs") {
                                $res = Patch-MainJsFile $t.Path
                                Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                            } else {
                                $res = Patch-BinaryFile $t.Path
                                Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                            }
                        }
                    }
                    Clear-IdeCaches | Out-Null
                } else {
                    Write-Host "[!] Путь не существует: $expanded" -ForegroundColor Red
                }
            }
            Pause
        }
        "5" {
            Show-Diagnostics
        }
        "6" {
            Stop-AntigravityProcesses
            $installs = Find-Installations
            foreach ($inst in $installs) {
                Write-Host "`nПапка: $inst" -ForegroundColor Cyan
                $targets = Find-AllTargets $inst
                foreach ($t in $targets) {
                    if ($t.Type -eq "MainJs") {
                        $res = Restore-MainJsFile $t.Path
                        Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                    } else {
                        $res = Restore-BinaryFile $t.Path
                        Write-Host "  [✓] $($t.Name) - $res" -ForegroundColor Green
                    }
                }
                $appDir = Join-Path $inst "resources\app"
                $appAsar = Join-Path $inst "resources\app.asar"
                if ((Test-Path -LiteralPath $appDir) -and (Test-Path -LiteralPath $appAsar)) {
                    Remove-Item -LiteralPath $appDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  [✓] resources\app удален (возврат к оригинальному app.asar)" -ForegroundColor Green
                }
            }
            Clear-IdeCaches | Out-Null
            Write-Host "`nУдаление правил DNS, статических маршрутов, служб и переменных..." -ForegroundColor Yellow
            Remove-DnsSettings
            [Environment]::SetEnvironmentVariable('GEMINI_API_BASE_URL', $null, 'User')
            [Environment]::SetEnvironmentVariable('GOOGLE_GEMINI_ENDPOINT', $null, 'User')
            Write-Host "[✓] Полный откат выполнен. Всё возвращено в исходное состояние." -ForegroundColor Green
            Pause
        }
        "0" { exit }
    }
}

while ($true) {
    Show-Menu
}
