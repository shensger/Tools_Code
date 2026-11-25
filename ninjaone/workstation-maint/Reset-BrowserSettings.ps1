#Requires -Version 5.1
<#
.SYNOPSIS
    Workstation maintenance step 6a - audits browsers for hijacks / unwanted extensions, removes
    named extensions, or resets browser settings for every (or one) user profile.

.DESCRIPTION
    Built for NinjaOne (runs as SYSTEM, Windows PowerShell 5.1); also runs interactively as admin.
    Covers Chrome, Edge, Brave (Chromium) and Firefox, for every local user profile or just
    targetUser.

    Mode Audit (default) - read-only:
      - Per browser profile: homepage, startup pages, custom default search engine, and every
        installed extension (ID, name, version, install source). Flags extensions that were
        sideloaded (unpacked / external installs not from the store) and non-default search
        engines / startup pages.
      - Browser policies in HKLM and each user's hive: ExtensionInstallForcelist, homepage /
        startup / search-provider policies. Adware often sets these; GPO/Intune legitimately do.

    Mode RemoveExtensions - removeExtensionIds (comma-separated):
      - Chromium IDs (32 letters a-p) are added to HKLM ExtensionInstallBlocklist for the
        selected browsers (this is what makes Chrome/Edge uninstall it and stop sync from
        bringing it back), and the extension folders are deleted from closed browsers.
      - Firefox IDs: the add-on .xpi / folder is removed from closed Firefox profiles.
      If the client manages browser policy with GPO/Intune, add the ID there as well - a policy
      refresh can replace local blocklist values.

    Mode Reset - the equivalent of the browser's own "Reset settings", per profile:
      - Chromium: moves Preferences and Secure Preferences to a backup folder. Startup pages,
        homepage, search engine, pinned tabs, site permissions and extension registrations
        reset to defaults. KEPT: bookmarks, saved passwords, history, cookies, autofill.
        Users signed in to browser sync may need to sign in again, and synced settings or
        extensions return from the cloud.
      - Firefox: moves prefs.js, user.js, add-ons (extensions folder, extensions.json,
        addonStartup.json.lz4) and search.json.mozlz4. KEPT: bookmarks, history, passwords,
        cookies.
      Backups: C:\ProgramData\Netrique\Maint\BrowserReset\<user>\<browser>_<profile>_<timestamp>\
      To undo, close the browser and copy the files back into the profile folder.

    RemoveExtensions and Reset only touch a browser for a user while that browser is closed.
    Set closeBrowsers to force-close it first (unsaved form data / tabs in that window are lost;
    Chromium restores tabs only if "continue where you left off" is set).

    Ninja script variables:
      mode                    Dropdown  Audit (default) | RemoveExtensions | Reset
      browsers                Text      Comma list: Chrome, Edge, Brave, Firefox. Default Chrome,Edge,Firefox
      targetUser              Text      Profile folder name (C:\Users\<name>). Blank = all users.
      removeExtensionIds      Text      Comma-separated IDs (RemoveExtensions mode)
      closeBrowsers           Checkbox  Force-close the browser for the target users first
      ninjaField              Text      Device text field for the one-line result. Default none.

.OUTPUTS
    Exit codes: 0 nothing flagged / all done, 1 findings (Audit) or something skipped/failed,
    2 error or bad input.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'RemoveExtensions', 'Reset', '')]
    [string]$Mode = $env:mode,
    [string]$Browsers = $env:browsers,
    [string]$TargetUser = $env:targetUser,
    [string]$RemoveExtensionIds = $env:removeExtensionIds,
    [switch]$CloseBrowsers,
    [string]$NinjaField = $env:ninjaField
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Write-Log([string]$Msg) { Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg) }
function Set-ResultField([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($NinjaField) -or $NinjaField -eq 'none') { return }
    if (-not (Get-Command -Name Set-NinjaProperty -ErrorAction SilentlyContinue)) { return }
    if ($Value.Length -gt 200) { $Value = $Value.Substring(0, 200) }
    try { Set-NinjaProperty -Name $NinjaField -Value $Value } catch { Write-Log "WARN: could not write field '$NinjaField': $($_.Exception.Message)" }
}

if ([string]::IsNullOrWhiteSpace($Mode))     { $Mode = 'Audit' }
if ([string]::IsNullOrWhiteSpace($Browsers)) { $Browsers = 'Chrome,Edge,Firefox' }
if ($env:closeBrowsers -eq 'true')           { $CloseBrowsers = $true }

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run as SYSTEM (NinjaOne) or from an elevated prompt.'
    exit 2
}

# PS 5.1 ConvertFrom-Json fails on large files; JavaScriptSerializer with a raised limit does not.
Add-Type -AssemblyName System.Web.Extensions
$script:Json = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$script:Json.MaxJsonLength = [int]::MaxValue

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return $script:Json.DeserializeObject([IO.File]::ReadAllText($Path)) } catch { return $null }
}
function Get-JsonValue($Obj, [string]$DotPath) {
    $cur = $Obj
    foreach ($k in ($DotPath -split '\.')) {
        if ($cur -is [System.Collections.IDictionary] -and $cur.ContainsKey($k)) { $cur = $cur[$k] } else { return $null }
    }
    return $cur
}

$BrowserDefs = @{
    Chrome  = @{ Kind = 'Chromium'; Data = 'AppData\Local\Google\Chrome\User Data';                 Proc = 'chrome.exe';  Policy = 'SOFTWARE\Policies\Google\Chrome' }
    Edge    = @{ Kind = 'Chromium'; Data = 'AppData\Local\Microsoft\Edge\User Data';                Proc = 'msedge.exe';  Policy = 'SOFTWARE\Policies\Microsoft\Edge' }
    Brave   = @{ Kind = 'Chromium'; Data = 'AppData\Local\BraveSoftware\Brave-Browser\User Data';   Proc = 'brave.exe';   Policy = 'SOFTWARE\Policies\BraveSoftware\Brave' }
    Firefox = @{ Kind = 'Firefox';  Data = 'AppData\Roaming\Mozilla\Firefox\Profiles';              Proc = 'firefox.exe'; Policy = 'SOFTWARE\Policies\Mozilla\Firefox' }
}
$KnownSearch = '(?i)google\.|bing\.com|duckduckgo\.com|yahoo\.com|ecosia\.org|startpage\.com|brave\.com'

$script:Flags   = 0
$script:Skipped = 0
$script:Changed = 0
$Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

function Get-UserProfiles {
    Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special=False' -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) -and $_.SID -match '^S-1-5-21-' } |
        ForEach-Object { [pscustomobject]@{ Name = (Split-Path -Path $_.LocalPath -Leaf); Path = $_.LocalPath; Sid = $_.SID } }
}

function Get-BrowserPids([string]$ProcName, [string]$Sid) {
    $ids = @()
    foreach ($p in (Get-CimInstance -ClassName Win32_Process -Filter "Name='$ProcName'" -ErrorAction SilentlyContinue)) {
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
            if ($o.Sid -eq $Sid) { $ids += [int]$p.ProcessId }
        } catch { }
    }
    return $ids
}

function Confirm-BrowserClosed([string]$Browser, $UserProfile) {
    # Returns $true when the browser is not running for this user (closing it if allowed).
    $procName = $BrowserDefs[$Browser].Proc
    $pids = @(Get-BrowserPids $procName $UserProfile.Sid)
    if ($pids.Count -eq 0) { return $true }
    if (-not $CloseBrowsers) {
        Write-Log "  SKIPPED: $Browser is running for $($UserProfile.Name) (set closeBrowsers to force-close)"
        $script:Skipped++
        return $false
    }
    Write-Log "  Closing $Browser for $($UserProfile.Name) ($($pids.Count) processes)"
    foreach ($id in $pids) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 4
    return (@(Get-BrowserPids $procName $UserProfile.Sid).Count -eq 0)
}

function Get-ChromiumExtName([string]$VersionDir) {
    $m = Read-JsonFile (Join-Path $VersionDir 'manifest.json')
    if (-not $m) { return $null }
    $n = [string]$m['name']
    if ($n -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        $locales = @('en', 'en_US')
        if ($m.ContainsKey('default_locale')) { $locales += [string]$m['default_locale'] }
        foreach ($l in $locales) {
            $msgs = Read-JsonFile (Join-Path $VersionDir "_locales\$l\messages.json")
            if (-not $msgs) { continue }
            foreach ($k in $msgs.Keys) { if ($k -ieq $key) { return [string]$msgs[$k]['message'] } }
        }
    }
    return $n
}

function Get-ChromiumProfiles([string]$UserData) {
    if (-not (Test-Path -LiteralPath $UserData)) { return @() }
    Get-ChildItem -LiteralPath $UserData -Directory -ErrorAction SilentlyContinue |
        Where-Object { ($_.Name -eq 'Default' -or $_.Name -like 'Profile *') -and (Test-Path -LiteralPath (Join-Path $_.FullName 'Preferences')) }
}

function Invoke-ChromiumAudit([string]$Browser, $ProfileDir) {
    $prefs  = Read-JsonFile (Join-Path $ProfileDir.FullName 'Preferences')
    $secure = Read-JsonFile (Join-Path $ProfileDir.FullName 'Secure Preferences')
    $label  = Get-JsonValue $prefs 'profile.name'
    Write-Log ("  [{0} / {1} '{2}']" -f $Browser, $ProfileDir.Name, $label)

    $homePage = Get-JsonValue $prefs 'homepage'
    $hpNtp = Get-JsonValue $prefs 'homepage_is_newtabpage'
    if ($homePage -and $hpNtp -ne $true) { Write-Log "    Homepage: $homePage" }
    $restore = Get-JsonValue $prefs 'session.restore_on_startup'
    $urls = @(Get-JsonValue $prefs 'session.startup_urls')
    if ($restore -eq 4 -and $urls.Count -gt 0) {
        Write-Log ("    Startup pages: {0}" -f ($urls -join ', '))
        foreach ($u in $urls) { if ($u -notmatch $KnownSearch) { Write-Log "    FLAG: unusual startup page $u"; $script:Flags++ } }
    }
    $search = Get-JsonValue $prefs 'default_search_provider_data.template_url_data.url'
    if ($search) {
        Write-Log "    Default search: $search"
        if ($search -notmatch $KnownSearch) { Write-Log '    FLAG: non-standard default search engine'; $script:Flags++ }
    }

    $settings = @{}
    foreach ($src in @($prefs, $secure)) {
        $s = Get-JsonValue $src 'extensions.settings'
        if ($s -is [System.Collections.IDictionary]) { foreach ($k in $s.Keys) { $settings[$k] = $s[$k] } }
    }
    $extRoot = Join-Path $ProfileDir.FullName 'Extensions'
    $exts = @()
    if (Test-Path -LiteralPath $extRoot) { $exts = @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[a-p]{32}$' }) }
    foreach ($e in $exts) {
        $ver = Get-ChildItem -LiteralPath $e.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
        $name = $null
        if ($ver) { $name = Get-ChromiumExtName $ver.FullName }
        $loc = $null; $fromStore = $null; $state = 'enabled'
        if ($settings.ContainsKey($e.Name)) {
            $st = $settings[$e.Name]
            $loc = Get-JsonValue $st 'location'
            $fromStore = Get-JsonValue $st 'from_webstore'
            $dr = Get-JsonValue $st 'disable_reasons'
            if ($dr) { $state = 'disabled' }
        }
        # location: 1 store/internal, 2-3 external registry/pref, 4 unpacked, 5/10 component, 6-9 policy/external
        $src = switch ($loc) { 1 { 'store' } 4 { 'UNPACKED' } 5 { 'component' } 10 { 'component' } 2 { 'external(registry)' } 3 { 'external(pref)' } 6 { 'external(pref-download)' } 7 { 'external(policy)' } 8 { 'external(policy)' } default { 'unknown' } }
        if ($loc -eq 5 -or $loc -eq 10) { continue }
        $flag = ''
        if ($loc -in @(2, 3, 4, 6)) { $flag = '  FLAG: sideloaded'; $script:Flags++ }
        $verName = ''
        if ($ver) { $verName = $ver.Name }
        Write-Log ("    Ext {0}  {1} {2}  [{3}, {4}]{5}" -f $e.Name, $name, $verName, $src, $state, $flag)
    }
    if ($exts.Count -eq 0) { Write-Log '    No extensions' }
}

function Get-FirefoxProfiles([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'prefs.js') }
}

function Invoke-FirefoxAudit($ProfileDir) {
    Write-Log ("  [Firefox / {0}]" -f $ProfileDir.Name)
    $prefsText = ''
    try { $prefsText = [IO.File]::ReadAllText((Join-Path $ProfileDir.FullName 'prefs.js')) } catch { }
    if ($prefsText -match 'user_pref\("browser\.startup\.homepage",\s*"([^"]*)"\)') {
        $hp = $Matches[1]
        Write-Log "    Homepage: $hp"
        if ($hp -notmatch $KnownSearch -and $hp -notmatch '^(about:|chrome:)') { Write-Log '    FLAG: unusual homepage'; $script:Flags++ }
    }
    $ext = Read-JsonFile (Join-Path $ProfileDir.FullName 'extensions.json')
    $addons = @()
    if ($ext) { $addons = @(Get-JsonValue $ext 'addons') }
    $shown = 0
    foreach ($a in $addons) {
        if ($a['type'] -ne 'extension') { continue }
        $loc = [string]$a['location']
        if ($loc -in @('app-builtin', 'app-system-defaults', 'app-system-addons', 'app-builtin-addons')) { continue }
        $name = Get-JsonValue $a 'defaultLocale.name'
        $state = 'enabled'
        if ($a['active'] -ne $true) { $state = 'disabled' }
        $flag = ''
        if ($loc -ne 'app-profile') { $flag = "  FLAG: installed from $loc"; $script:Flags++ }
        Write-Log ("    Add-on {0}  {1} {2}  [{3}]{4}" -f $a['id'], $name, $a['version'], $state, $flag)
        $shown++
    }
    if ($shown -eq 0) { Write-Log '    No add-ons' }
}

function Write-PolicyAudit([string]$Browser, $Users) {
    $rel = $BrowserDefs[$Browser].Policy
    $roots = @(@{ Label = 'HKLM'; Path = "HKLM:\$rel" })
    foreach ($u in $Users) { $roots += @{ Label = "HKU:$($u.Name)"; Path = "Registry::HKEY_USERS\$($u.Sid)\$rel" } }
    foreach ($r in $roots) {
        if (-not (Test-Path -Path $r.Path)) { continue }
        $key = Get-Item -Path $r.Path
        foreach ($v in @('HomepageLocation', 'NewTabPageLocation', 'DefaultSearchProviderSearchURL', 'DefaultSearchProviderName', 'RestoreOnStartup')) {
            $val = $key.GetValue($v)
            if ($null -ne $val) { Write-Log ("  POLICY {0} [{1}] {2} = {3}" -f $Browser, $r.Label, $v, $val) }
        }
        foreach ($sub in @('ExtensionInstallForcelist', 'RestoreOnStartupURLs', 'ExtensionInstallBlocklist')) {
            $sp = Join-Path $r.Path $sub
            if (-not (Test-Path -Path $sp)) { continue }
            $sk = Get-Item -Path $sp
            $vals = @($sk.GetValueNames() | ForEach-Object { [string]$sk.GetValue($_) })
            if ($vals.Count -eq 0) { continue }
            $flag = ''
            if ($sub -eq 'ExtensionInstallForcelist') { $flag = '  REVIEW: force-installed extensions - confirm GPO/Intune set these'; $script:Flags++ }
            Write-Log ("  POLICY {0} [{1}] {2}: {3}{4}" -f $Browser, $r.Label, $sub, ($vals -join ' ; '), $flag)
        }
    }
}

function Add-ChromiumBlocklist([string]$Browser, [string[]]$Ids) {
    $key = "HKLM:\$($BrowserDefs[$Browser].Policy)\ExtensionInstallBlocklist"
    if (-not (Test-Path -Path $key)) { New-Item -Path $key -Force | Out-Null }
    $k = Get-Item -Path $key
    $names = @($k.GetValueNames())
    $existing = @($names | ForEach-Object { [string]$k.GetValue($_) })
    if ($existing.Count -gt 0) { Write-Log "  NOTE: $Browser blocklist already has $($existing.Count) entries - if GPO/Intune manages it, add these IDs there too" }
    $next = 1
    $nums = @($names | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
    if ($nums.Count -gt 0) { $next = ($nums | Measure-Object -Maximum).Maximum + 1 }
    foreach ($id in $Ids) {
        if ($existing -contains $id) { Write-Log "  $Browser blocklist: $id already present"; continue }
        New-ItemProperty -Path $key -Name ([string]$next) -Value $id -PropertyType String -Force | Out-Null
        Write-Log "  $Browser blocklist: added $id (value $next)"
        $next++
        $script:Changed++
    }
}

function Backup-Items([string]$SourceDir, [string[]]$Items, [string]$Dest) {
    $moved = 0
    foreach ($i in $Items) {
        $src = Join-Path $SourceDir $i
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if (-not (Test-Path -LiteralPath $Dest)) { New-Item -Path $Dest -ItemType Directory -Force | Out-Null }
        Move-Item -LiteralPath $src -Destination (Join-Path $Dest $i) -Force
        $moved++
    }
    return $moved
}

try {
    $browserList = @($Browsers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($b in $browserList) {
        if (-not $BrowserDefs.ContainsKey($b)) { Write-Error "Unknown browser '$b'. Use Chrome, Edge, Brave, Firefox."; exit 2 }
    }
    # Normalise casing to the dictionary keys
    $browserList = @($browserList | ForEach-Object { $n = $_; ($BrowserDefs.Keys | Where-Object { $_ -ieq $n }) })

    $users = @(Get-UserProfiles)
    if (-not [string]::IsNullOrWhiteSpace($TargetUser)) {
        $users = @($users | Where-Object { $_.Name -ieq $TargetUser.Trim() })
        if ($users.Count -eq 0) { Write-Error "No local profile folder named '$TargetUser'."; exit 2 }
    }

    $ids = @()
    if ($Mode -eq 'RemoveExtensions') {
        $ids = @($RemoveExtensionIds -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($ids.Count -eq 0) { Write-Error 'RemoveExtensions mode needs removeExtensionIds.'; exit 2 }
    }
    $chromiumIds = @($ids | Where-Object { $_ -match '^[a-p]{32}$' })
    $firefoxIds  = @($ids | Where-Object { $_ -notmatch '^[a-p]{32}$' })

    Write-Log "Org: $env:NINJA_ORGANIZATION_NAME  Device: $env:COMPUTERNAME  Mode=$Mode  Browsers=$($browserList -join ',')  Users=$($users.Count)  CloseBrowsers=$CloseBrowsers"

    if ($Mode -eq 'Audit') {
        foreach ($b in $browserList) { Write-PolicyAudit $b $users }
    }
    if ($Mode -eq 'RemoveExtensions') {
        foreach ($b in $browserList) {
            if ($BrowserDefs[$b].Kind -eq 'Chromium' -and $chromiumIds.Count -gt 0) { Add-ChromiumBlocklist $b $chromiumIds }
        }
    }

    foreach ($u in $users) {
        Write-Log "User: $($u.Name)"
        foreach ($b in $browserList) {
            $def  = $BrowserDefs[$b]
            $root = Join-Path $u.Path $def.Data
            if ($def.Kind -eq 'Chromium') { $profs = @(Get-ChromiumProfiles $root) } else { $profs = @(Get-FirefoxProfiles $root) }
            if ($profs.Count -eq 0) { continue }

            if ($Mode -eq 'Audit') {
                foreach ($pd in $profs) {
                    if ($def.Kind -eq 'Chromium') { Invoke-ChromiumAudit $b $pd } else { Invoke-FirefoxAudit $pd }
                }
                continue
            }

            if (-not (Confirm-BrowserClosed $b $u)) { continue }

            foreach ($pd in $profs) {
                if ($Mode -eq 'RemoveExtensions') {
                    if ($def.Kind -eq 'Chromium') {
                        foreach ($id in $chromiumIds) {
                            $d = Join-Path $pd.FullName "Extensions\$id"
                            if (Test-Path -LiteralPath $d) {
                                Remove-Item -LiteralPath $d -Recurse -Force
                                Write-Log "  Removed $id from $b / $($pd.Name)"
                                $script:Changed++
                            }
                        }
                    }
                    else {
                        foreach ($id in $firefoxIds) {
                            foreach ($cand in @("extensions\$id.xpi", "extensions\$id")) {
                                $d = Join-Path $pd.FullName $cand
                                if (Test-Path -LiteralPath $d) {
                                    Remove-Item -LiteralPath $d -Recurse -Force
                                    Write-Log "  Removed $id from Firefox / $($pd.Name)"
                                    $script:Changed++
                                }
                            }
                        }
                    }
                }
                elseif ($Mode -eq 'Reset') {
                    $dest = Join-Path $env:ProgramData ("Netrique\Maint\BrowserReset\{0}\{1}_{2}_{3}" -f $u.Name, $b, ($pd.Name -replace '\s', ''), $Stamp)
                    if ($def.Kind -eq 'Chromium') { $items = @('Preferences', 'Secure Preferences') }
                    else { $items = @('prefs.js', 'user.js', 'extensions', 'extensions.json', 'addonStartup.json.lz4', 'search.json.mozlz4') }
                    $n = Backup-Items $pd.FullName $items $dest
                    if ($n -gt 0) {
                        Write-Log "  RESET $b / $($pd.Name): moved $n item(s) to $dest"
                        $script:Changed++
                    }
                }
            }
        }
    }

    Write-Log "RESULT: mode=$Mode flagged=$($script:Flags) changed=$($script:Changed) skipped=$($script:Skipped)"
    Set-ResultField ("{0} | {1:yyyy-MM-dd HH:mm} | flagged={2} changed={3} skipped={4}" -f $Mode.ToUpper(), (Get-Date), $script:Flags, $script:Changed, $script:Skipped)
    if ($Mode -eq 'Audit' -and $script:Flags -gt 0) { exit 1 }
    if ($script:Skipped -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Error "Browser maintenance failed: $($_.Exception.Message)"
    Set-ResultField ("ERROR | {0:yyyy-MM-dd HH:mm} | {1}" -f (Get-Date), $_.Exception.Message)
    exit 2
}
