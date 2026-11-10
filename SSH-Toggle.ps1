<#
.SYNOPSIS
    On-demand SSH for Windows. One click turns SSH ON, closing it turns SSH OFF,
    and a live view shows who is connected.

.DESCRIPTION
    While the window is open:
      - OpenSSH Server (sshd) is running
      - a dedicated, scoped firewall rule allows the SSH port
      - a live dashboard shows the connect command, connected users and login attempts
    When you press Q or Ctrl+C (or the window closes):
      - sshd is stopped, remaining SSH sessions are killed
      - the firewall rules created by this script are removed

    Works on Windows 10 (1809+), Windows 11 and Windows Server 2019+, with
    Windows PowerShell 5.1 or PowerShell 7. Any SSH client can connect (macOS, Linux,
    Windows, iOS/Android apps).

.PARAMETER Port
    TCP port for SSH. Default 22.
.PARAMETER AllowedRemote
    Who may reach the port while SSH is ON. Default 'LocalSubnet' (same LAN/Wi-Fi).
    Safest: a single device, e.g. '192.168.1.12'. Also accepts 'a.b.c.d/24', ranges,
    and comma-separated lists.
.PARAMETER AllowInternet
    Required if AllowedRemote is 'Any' (open to every address). Not recommended.
.PARAMETER MaxFailures
    Auto-block a remote IP after this many failed logins during this session. 0 = off.
.PARAMETER KeepPasswordLogin
    Do not disable password login even when a usable SSH key is installed.
.PARAMETER AllowAnyUser
    Do not restrict SSH logins to the target user.
.PARAMETER CreateShortcut
    Create a Desktop shortcut for the current user, then exit.
.PARAMETER LockFolder
    Make this script's folder writable by administrators only (needs admin), then exit.
.PARAMETER Revert
    Remove everything this script added and restore the saved original settings, then exit.
.PARAMETER TargetUser
    Windows account that will log in over SSH. Default: the current user.

.EXAMPLE
    .\SSH-Toggle.ps1
.EXAMPLE
    .\SSH-Toggle.ps1 -AllowedRemote 192.168.1.12
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)][int]$Port = 22,
    [string]$AllowedRemote = 'LocalSubnet',
    [switch]$AllowInternet,
    [ValidateRange(0, 100)][int]$MaxFailures = 5,
    [switch]$KeepPasswordLogin,
    [switch]$AllowAnyUser,
    [switch]$CreateShortcut,
    [switch]$LockFolder,
    [switch]$Revert,
    [string]$TargetUser = $env:USERNAME,
    [string]$TargetProfile = $env:USERPROFILE,
    [ValidateRange(0, 86400)][int]$TestSeconds = 0     # testing: stop automatically after N seconds
)

# NOTE: keep this file ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI).

$RuleName    = 'SSH-Toggle-Inbound'
$BlockPrefix = 'SSH-Toggle-Block-'
$BuiltinRule = 'OpenSSH-Server-In-TCP'
$WinPS       = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$SshDir      = Join-Path $env:ProgramData 'ssh'
$SshdConfig  = Join-Path $SshDir 'sshd_config'
$StateDir    = Join-Path $env:ProgramData 'SSH-Toggle'
$StatePath   = Join-Path $StateDir 'original-state.json'
$BeginMark   = '# >>> SSH-Toggle managed block (do not edit by hand) >>>'
$EndMark     = '# <<< SSH-Toggle managed block <<<'
$AdminSid    = 'S-1-5-32-544'
$SystemSid   = 'S-1-5-18'

# Cleanup text: used by the finally block, the exit event and -Revert. Idempotent.
$CleanupText = @'
$ErrorActionPreference = 'SilentlyContinue'
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
Get-Process -Name sshd, sshd-session -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name 'SSH-Toggle-Inbound' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name 'SSH-Toggle-Block-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
'@

# ======================================================================
#  Helper functions
# ======================================================================

function Wait-ForKey([string]$Message = 'Press any key to close...') {
    Write-Host ''
    Write-Host "  $Message" -ForegroundColor Yellow
    try { [void][Console]::ReadKey($true) } catch { Start-Sleep -Seconds 8 }
}

# Remote-controlled text (usernames, IPs from the log) must never reach the console raw:
# control characters / ANSI escapes could rewrite the screen and fake log lines.
function Get-SafeText([string]$Text, [int]$Max = 40) {
    if ($null -eq $Text) { return '' }
    $t = $Text -replace '[^\x20-\x7E]', '?'
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Test-RemoteSpec([string]$Spec) {
    if ([string]::IsNullOrWhiteSpace($Spec)) { return $false }
    $tmp = $null
    foreach ($part in ($Spec -split ',')) {
        $p = $part.Trim()
        if ($p -ieq 'LocalSubnet' -or $p -ieq 'Any') { continue }
        $ok = $false
        if ($p -match '^([^/\-]+)/(\d{1,3})$') {
            $ok = [System.Net.IPAddress]::TryParse($Matches[1], [ref]$tmp)
        } elseif ($p -match '^([^/\-]+)-([^/\-]+)$') {
            $ok = ([System.Net.IPAddress]::TryParse($Matches[1], [ref]$tmp) -and [System.Net.IPAddress]::TryParse($Matches[2], [ref]$tmp))
        } else {
            $ok = [System.Net.IPAddress]::TryParse($p, [ref]$tmp)
        }
        if (-not $ok) { return $false }
    }
    return $true
}

function Test-RemoteSpecIsOpen([string]$Spec) {
    return [bool]($Spec -match '(?i)(^|,)\s*(any|\*)\s*(,|$)|0\.0\.0\.0/0|::/0')
}

# Parse one sshd event-log message. Patterns are anchored to the START of the message so
# text inside an attacker-chosen username cannot fake an "Accepted ..." line.
function ConvertFrom-SshdMessage([string]$Message) {
    if ([string]::IsNullOrEmpty($Message)) { return $null }
    $m = ($Message -split "`r?`n")[0]
    # The user name is attacker-controlled for failures, so it is matched greedily (.+): the
    # IP/port come from the LAST "from <ip> port <n>", which sshd itself appends. For a
    # successful login the account must really exist, so a lazy match is used.
    if ($m -match '^(?:sshd:\s+)?Accepted (\S+) for (.+?) from (\S+) port (\d+)') {
        return [pscustomobject]@{ Type = 'accept'; Method = $Matches[1]; User = $Matches[2]; Ip = $Matches[3]; Port = $Matches[4] }
    }
    if ($m -match '^(?:sshd:\s+)?Failed (\S+) for (?:invalid user )?(.+) from (\S+) port (\d+)') {
        return [pscustomobject]@{ Type = 'fail'; Method = $Matches[1]; User = $Matches[2]; Ip = $Matches[3]; Port = $Matches[4] }
    }
    if ($m -match '^(?:sshd:\s+)?User (.+) from (\S+) not allowed because') {
        return [pscustomobject]@{ Type = 'denied'; Method = ''; User = $Matches[1]; Ip = $Matches[2]; Port = '' }
    }
    if ($m -match '^(?:sshd:\s+)?Invalid user (.+) from (\S+)') {
        return [pscustomobject]@{ Type = 'invalid'; Method = ''; User = $Matches[1]; Ip = $Matches[2]; Port = '' }
    }
    if ($m -match '^(?:sshd:\s+)?Disconnected from user (.+) (\S+) port (\d+)') {
        return [pscustomobject]@{ Type = 'disconnect'; Method = ''; User = $Matches[1]; Ip = $Matches[2]; Port = $Matches[3] }
    }
    if ($m -match '^(?:sshd:\s+)?Disconnected from (\S+) port (\d+)') {
        return [pscustomobject]@{ Type = 'disconnect'; Method = ''; User = ''; Ip = $Matches[1]; Port = $Matches[2] }
    }
    if ($m -match '^(?:sshd:\s+)?Connection (?:closed|reset) by (?:authenticating |invalid )?user (.+) (\S+) port (\d+)') {
        return [pscustomobject]@{ Type = 'closed'; Method = ''; User = $Matches[1]; Ip = $Matches[2]; Port = $Matches[3] }
    }
    return $null
}

# Returns a reason string if non-admin code could modify $Path (and so tamper with a script
# that later runs elevated), or $null if only SYSTEM / Administrators / TrustedInstaller can.
function Get-UnsafeAclReason([string]$Path) {
    $safe = @($SystemSid, $AdminSid, 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Integer math on purpose: ACEs can carry GENERIC_ALL (0x10000000) / GENERIC_WRITE
    # (0x40000000), which are not valid values of the FileSystemRights enum.
    $named = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $mask = ([int]$named) -bor 0x50000000
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($safe -notcontains $owner) { return "owner is not an administrator ($($acl.Owner))" }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ((([int]$ace.FileSystemRights) -band $mask) -eq 0) { continue }
            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($safe -notcontains $sid) { return "write access is granted to $($ace.IdentityReference)" }
        }
    } catch {
        return "permissions could not be read ($($_.Exception.Message))"
    }
    return $null
}

function Get-SshdPath {
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.PathName) {
        $pn = $svc.PathName.Trim()
        if ($pn.StartsWith('"')) {
            $end = $pn.IndexOf('"', 1)
            if ($end -gt 1) { $exe = $pn.Substring(1, $end - 1) } else { $exe = $null }
        } else {
            $exe = ($pn -split '\s+')[0]
        }
        if ($exe -and (Test-Path -LiteralPath $exe)) { return $exe }
    }
    $fallback = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    return $null
}

function Test-TargetIsAdmin {
    # $true / $false, or $null if it cannot be determined. Uses SIDs, so it works on any
    # Windows language (the group is called "Administrators" only on English systems).
    try {
        $members = @(Get-LocalGroupMember -SID $AdminSid -ErrorAction Stop)
        $leaf = $TargetUser
        if ($leaf -match '\\') { $leaf = ($leaf -split '\\')[-1] }
        $mySid = $null
        try { $mySid = (New-Object System.Security.Principal.NTAccount($TargetUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        foreach ($mem in $members) {
            if ($mySid -and $mem.SID -and $mem.SID.Value -eq $mySid) { return $true }
            if ($mem.Name -match ('(^|\\)' + [regex]::Escape($leaf) + '$')) { return $true }
        }
        return $false
    } catch { return $null }
}

function Test-KeyFileUsable([string]$Path, [string[]]$AllowedSids) {
    # A key counts only if the file holds a key AND its ACL is strict (sshd ignores keys in
    # files other users can modify). Fail-safe: when unsure, password login stays enabled
    # rather than locking you out.
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $has = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(ssh-|ecdsa-|sk-)' }
    if (-not $has) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($AllowedSids -notcontains $sid) { return $false }
        }
    } catch { return $false }
    return $true
}

function Get-KeyStatus {
    # Returns @{ Usable = bool; Note = string }
    $isAdmin = Test-TargetIsAdmin
    $adminFile = Join-Path $SshDir 'administrators_authorized_keys'
    $userFile  = Join-Path $TargetProfile '.ssh\authorized_keys'
    $mySid = $null
    try { $mySid = (New-Object System.Security.Principal.NTAccount($TargetUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
    $userSids = @($SystemSid, $AdminSid)
    if ($mySid) { $userSids += $mySid }

    if ($isAdmin -eq $true) {
        $ok = Test-KeyFileUsable $adminFile @($SystemSid, $AdminSid)
        if ($ok) { return @{ Usable = $true; Note = '' } }
        if (Test-Path -LiteralPath $adminFile) { return @{ Usable = $false; Note = 'administrators_authorized_keys exists but is empty or has loose permissions' } }
        return @{ Usable = $false; Note = '' }
    }
    $ok = Test-KeyFileUsable $userFile $userSids
    if ($ok) { return @{ Usable = $true; Note = '' } }
    if (Test-Path -LiteralPath $userFile) { return @{ Usable = $false; Note = 'authorized_keys exists but is empty or has loose permissions' } }
    return @{ Usable = $false; Note = '' }
}

function Get-ConfigWithoutBlock([string[]]$Lines) {
    # Removes our managed block(s), including blocks written by older versions of this script
    # (their begin-marker text differed). SAFETY: a block is only removed up to an end marker
    # that really exists within 40 lines. A block with a missing end marker is NEVER treated as
    # "everything until the end of the file" (that would delete the rest of the config).
    $beginRx   = '^\s*# >>> SSH-Toggle managed block'
    $endRx     = '^\s*# <<< SSH-Toggle managed block <<<\s*$'
    $managedRx = '^\s*(Port|MaxAuthTries|LoginGraceTime|PermitEmptyPasswords|ClientAliveInterval|ClientAliveCountMax|PasswordAuthentication|AuthenticationMethods|AllowUsers)\b'
    $clean = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $Lines.Count) {
        $line = $Lines[$i]
        if ($line -match $beginRx) {
            $endIdx = -1
            $limit = [math]::Min($Lines.Count, $i + 40)
            for ($j = $i + 1; $j -lt $limit; $j++) { if ($Lines[$j] -match $endRx) { $endIdx = $j; break } }
            if ($endIdx -ge 0) {
                $i = $endIdx + 1
            } else {
                # damaged block (no end marker): drop only the begin line and the directives right after it
                $i++
                while ($i -lt $Lines.Count -and $Lines[$i] -match $managedRx) { $i++ }
            }
            # the blank separator line(s) we add after a block
            while ($i -lt $Lines.Count -and $Lines[$i].Trim() -eq '') { $i++ }
            continue
        }
        if ($line -match $endRx) { $i++; continue }    # orphan end marker
        $clean.Add($line)
        $i++
    }
    return ,$clean
}

function Write-ConfigLines([string]$Path, $Lines) {
    [System.IO.File]::WriteAllLines($Path, [string[]]$Lines, (New-Object System.Text.UTF8Encoding($false)))
}

# Adds a managed block at the TOP of sshd_config (sshd uses the first value it sees).
# Returns @{ KeyOnly; UserRestricted; Notes }
function Set-SshdHardening([string]$SshdExe) {
    $notes = New-Object System.Collections.Generic.List[string]
    $ks = Get-KeyStatus
    if ($ks.Note) { $notes.Add($ks.Note) }
    $keyOnly = ($ks.Usable -and -not $KeepPasswordLogin)

    $block = New-Object System.Collections.Generic.List[string]
    $block.Add($BeginMark)
    $block.Add("Port $Port")
    $block.Add('MaxAuthTries 3')
    $block.Add('LoginGraceTime 30')
    $block.Add('PermitEmptyPasswords no')
    $block.Add('ClientAliveInterval 60')
    $block.Add('ClientAliveCountMax 3')
    if ($keyOnly) {
        $block.Add('PasswordAuthentication no')
        # PasswordAuthentication alone is NOT enough: keyboard-interactive stays enabled by default
        # and is a second credential path. AuthenticationMethods publickey allows keys and nothing else.
        $block.Add('AuthenticationMethods publickey')
    }

    $restricted = $false
    if (-not $AllowAnyUser) {
        if ($TargetUser -match '^[A-Za-z0-9._@\\-]+$') {
            # Names are matched case-sensitively and clients may type any case: allow the exact
            # and the lower-case spelling (other spellings are refused; fail closed).
            $names = @($TargetUser)
            if ($TargetUser.ToLowerInvariant() -cne $TargetUser) { $names += $TargetUser.ToLowerInvariant() }
            $block.Add('AllowUsers ' + ($names -join ' '))
            $restricted = $true
        } else {
            $notes.Add('AllowUsers skipped: unusual user name')
        }
    }
    $block.Add($EndMark)

    if (-not (Test-Path -LiteralPath $SshdConfig)) {
        $default = Join-Path $env:WINDIR 'System32\OpenSSH\sshd_config_default'
        if (Test-Path -LiteralPath $default) {
            if (-not (Test-Path -LiteralPath $SshDir)) { New-Item -ItemType Directory -Path $SshDir -Force | Out-Null }
            Copy-Item -LiteralPath $default -Destination $SshdConfig -Force
        } else {
            throw "sshd_config not found at $SshdConfig and no default to copy."
        }
    }

    $orig = @(Get-Content -LiteralPath $SshdConfig -ErrorAction Stop)
    $backup = "$SshdConfig.bak-ssh-toggle"
    if (-not (Test-Path -LiteralPath $backup)) { Copy-Item -LiteralPath $SshdConfig -Destination $backup -Force }

    $clean = Get-ConfigWithoutBlock $orig
    $new = New-Object System.Collections.Generic.List[string]
    $new.AddRange($block)
    $new.Add('')
    $new.AddRange($clean)
    Write-ConfigLines $SshdConfig $new

    # Validate; if sshd rejects the result, put the original back.
    if ($SshdExe) {
        $null = & $SshdExe -t 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-ConfigLines $SshdConfig $orig
            Write-Host '  ! The edited sshd_config was rejected by sshd; the original was restored.' -ForegroundColor Yellow
            $notes.Add('hardening skipped (sshd rejected the config)')
            return @{ KeyOnly = $false; UserRestricted = $false; Notes = $notes }
        }
    }
    return @{ KeyOnly = $keyOnly; UserRestricted = $restricted; Notes = $notes }
}

function Save-OriginalState {
    if (Test-Path -LiteralPath $StatePath) { return }
    try {
        $svc = Get-Service -Name sshd -ErrorAction Stop
        $rule = Get-NetFirewallRule -Name $BuiltinRule -ErrorAction SilentlyContinue
        $state = [ordered]@{
            SshdStartType  = $svc.StartType.ToString()
            BuiltinExists  = [bool]$rule
            BuiltinEnabled = [bool]($rule -and $rule.Enabled -eq 'True')
            SavedAt        = (Get-Date).ToString('s')
        }
        if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        [System.IO.File]::WriteAllText($StatePath, ($state | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    } catch { }
}

function Invoke-RevertMode {
    Write-Host '  Removing everything SSH-Toggle added...' -ForegroundColor Cyan
    & ([scriptblock]::Create($CleanupText))
    if (Test-Path -LiteralPath $SshdConfig) {
        $lines = @(Get-Content -LiteralPath $SshdConfig)
        Write-ConfigLines $SshdConfig (Get-ConfigWithoutBlock $lines)
        Write-Host '  - hardening block removed from sshd_config' -ForegroundColor Gray
    }
    if (Test-Path -LiteralPath $StatePath) {
        try {
            $st = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
            if (@('Automatic', 'Manual', 'Disabled') -contains [string]$st.SshdStartType) {
                Set-Service -Name sshd -StartupType ([string]$st.SshdStartType) -ErrorAction SilentlyContinue
                Write-Host ("  - sshd startup type restored to {0}" -f $st.SshdStartType) -ForegroundColor Gray
            }
            if ($st.BuiltinExists -eq $true -and (Get-NetFirewallRule -Name $BuiltinRule -ErrorAction SilentlyContinue)) {
                $en = 'False'; if ($st.BuiltinEnabled -eq $true) { $en = 'True' }
                Set-NetFirewallRule -Name $BuiltinRule -Enabled $en -ErrorAction SilentlyContinue
                Write-Host ("  - built-in OpenSSH firewall rule restored to Enabled={0}" -f $en) -ForegroundColor Gray
            }
            Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host '  ! Saved original state could not be read; startup type and built-in rule left as they are.' -ForegroundColor Yellow
        }
    } else {
        Write-Host '  - no saved original state: startup type and built-in rule left as they are' -ForegroundColor Gray
    }
    Write-Host '  Done.' -ForegroundColor Green
}

function Invoke-LockFolder {
    $dir = $PSScriptRoot
    $allowed = @('SSH-Toggle.ps1', 'SSH-Toggle.bat', 'README.md')
    $extra = @(Get-ChildItem -LiteralPath $dir -Force | Where-Object { $allowed -notcontains $_.Name })
    if ($extra.Count -gt 0) {
        throw ("Refusing to change permissions: the folder contains other files ({0}). Put the script in its own folder first." -f (($extra | Select-Object -First 3 -ExpandProperty Name) -join ', '))
    }
    Write-Host "  Locking $dir (administrators write, everyone else read-only)..." -ForegroundColor Cyan
    $null = & icacls.exe $dir /setowner "*$AdminSid" /T /C
    if ($LASTEXITCODE -ne 0) { throw 'icacls /setowner failed.' }
    $null = & icacls.exe $dir /inheritance:r /grant:r "*${SystemSid}:(OI)(CI)F" "*${AdminSid}:(OI)(CI)F" '*S-1-5-32-545:(OI)(CI)RX'
    if ($LASTEXITCODE -ne 0) { throw 'icacls /grant failed.' }
    $null = & icacls.exe (Join-Path $dir '*') /reset /T /C
    $reason = Get-UnsafeAclReason $dir
    if ($reason) { Write-Host "  ! Still not locked: $reason" -ForegroundColor Yellow } else { Write-Host '  Locked. Editing the script now requires an elevated editor.' -ForegroundColor Green }
}

function Get-LocalIPs {
    $r = @()
    try {
        $r = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | ForEach-Object { $_.IPv4Address[0].IPAddress })
    } catch { }
    if ($r.Count -eq 0) {
        $r = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress })
    }
    return $r
}

# Do NOT use Get-NetTCPConnection -State Listen for this: on some machines it does not
# report sshd's listener even though it is listening. A direct TCP connect is reliable.
# (Loopback proves sshd listens; it does NOT prove the firewall lets other devices in.)
function Test-PortOpen([int]$P) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect('127.0.0.1', $P, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(800) -and $c.Connected) { return $true }
        return $false
    } catch { return $false }
    finally { $c.Close() }
}

function Test-BlockableIp([string]$Ip) {
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $false }
    if ([System.Net.IPAddress]::IsLoopback($addr)) { return $false }
    if ($script:ips -contains $addr.ToString()) { return $false }
    return $true
}

function Add-IpBlock([string]$Ip) {
    $name = $BlockPrefix + ($Ip -replace '[^0-9a-fA-F\.]', '_')
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { return }
    New-NetFirewallRule -Name $name -DisplayName "SSH Toggle block $Ip" -Direction Inbound -Action Block `
        -Protocol TCP -LocalPort $Port -RemoteAddress $Ip -Profile Any | Out-Null
}

# ---------------- dashboard state ----------------
$script:start     = Get-Date
$script:seen      = New-Object 'System.Collections.Generic.HashSet[long]'
$script:sessions  = @{}      # "ip:port" -> user name
$script:events    = New-Object System.Collections.Generic.List[object]   # @(text, color)
$script:failCount = 0
$script:failByIp  = @{}
$script:blocked   = New-Object 'System.Collections.Generic.HashSet[string]'
$script:lastHash  = ''
$script:ips       = @()
$script:keyOnly   = $false
$script:restricted = $false
$script:warnings  = New-Object System.Collections.Generic.List[string]

function Add-EventLine([string]$Text, [string]$Color) {
    $script:events.Insert(0, @($Text, $Color))
    while ($script:events.Count -gt 40) { $script:events.RemoveAt($script:events.Count - 1) }
}

function Update-Events {
    $ev = @()
    try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'OpenSSH/Operational'; StartTime = $script:start } -ErrorAction Stop) } catch { $ev = @() }
    foreach ($e in ($ev | Sort-Object RecordId)) {
        if (-not $script:seen.Add([long]$e.RecordId)) { continue }
        $r = ConvertFrom-SshdMessage $e.Message
        if (-not $r) { continue }
        $t  = $e.TimeCreated.ToString('HH:mm:ss')
        $u  = Get-SafeText $r.User 32
        $ip = Get-SafeText $r.Ip 45
        $countFail = $false

        if ($r.Type -eq 'accept') {
            $script:sessions["$($r.Ip):$($r.Port)"] = $u
            Add-EventLine ("{0}  LOGIN OK      {1} from {2} ({3})" -f $t, $u, $ip, (Get-SafeText $r.Method 20)) 'Green'
        }
        elseif ($r.Type -eq 'fail') {
            $countFail = $true
            Add-EventLine ("{0}  LOGIN FAILED  {1} from {2} ({3})" -f $t, $u, $ip, (Get-SafeText $r.Method 20)) 'Red'
        }
        elseif ($r.Type -eq 'denied') {
            $countFail = $true
            Add-EventLine ("{0}  DENIED         {1} from {2} (not an allowed user)" -f $t, $u, $ip) 'Red'
        }
        elseif ($r.Type -eq 'invalid') {
            Add-EventLine ("{0}  UNKNOWN USER   {1} from {2}" -f $t, $u, $ip) 'Red'
        }
        elseif ($r.Type -eq 'disconnect') {
            $who = $u
            if (-not $who) { $who = $script:sessions["$($r.Ip):$($r.Port)"] }
            if (-not $who) { $who = '?' }
            Add-EventLine ("{0}  DISCONNECTED   {1} from {2}" -f $t, $who, $ip) 'DarkYellow'
        }
        elseif ($r.Type -eq 'closed') {
            Add-EventLine ("{0}  CLOSED          {1} from {2}" -f $t, $u, $ip) 'DarkYellow'
        }

        if ($countFail) {
            $script:failCount++
            $addr = $null
            if ($MaxFailures -gt 0 -and [System.Net.IPAddress]::TryParse($r.Ip, [ref]$addr)) {
                $key = $addr.ToString()
                $script:failByIp[$key] = 1 + [int]$script:failByIp[$key]
                if ($script:failByIp[$key] -ge $MaxFailures -and -not $script:blocked.Contains($key) -and (Test-BlockableIp $key)) {
                    try {
                        Add-IpBlock $key
                        [void]$script:blocked.Add($key)
                        Add-EventLine ("{0}  IP BLOCKED      {1} after {2} failed logins" -f $t, (Get-SafeText $key 45), $script:failByIp[$key]) 'Magenta'
                    } catch { }
                }
            }
        }
    }
}

function Render {
    $mins = [int][math]::Floor(((Get-Date) - $script:start).TotalMinutes)
    $conns = @(Get-NetTCPConnection -LocalPort $Port -State Established -ErrorAction SilentlyContinue)
    $buf = New-Object System.Collections.Generic.List[object]
    $sep = '  ' + ('-' * 62)

    $buf.Add(@('  ==============================================================', 'Cyan'))
    $buf.Add(@('   SSH IS ON   |  press Q or Ctrl+C to turn SSH OFF', 'Cyan'))
    $buf.Add(@('  ==============================================================', 'Cyan'))
    $buf.Add(@('', 'Gray'))
    $buf.Add(@('   Connect from your other device:', 'Gray'))
    $pOpt = ''
    if ($Port -ne 22) { $pOpt = "-p $Port " }
    if ($script:ips.Count -eq 0) {
        $buf.Add(@('       (no IP detected - check your network connection)', 'Yellow'))
    } else {
        foreach ($ip in $script:ips) { $buf.Add(@(("       ssh {0}{1}@{2}" -f $pOpt, $TargetUser, $ip), 'White')) }
    }
    $buf.Add(@('', 'Gray'))
    if ($script:keyOnly) {
        $buf.Add(@('   Login     : SSH KEY ONLY (password login disabled)', 'Green'))
    } else {
        $buf.Add(@('   Login     : Windows account password (install an SSH key to disable passwords)', 'Yellow'))
    }
    if ($script:restricted) {
        $buf.Add(@(("   Users     : only {0} may log in" -f $TargetUser), 'Gray'))
    } else {
        $buf.Add(@('   Users     : any local account may log in', 'Yellow'))
    }
    $buf.Add(@(("   Firewall  : TCP {0} open to [{1}] only" -f $Port, $AllowedRemote), 'Gray'))
    $buf.Add(@(("   Started   : {0}   (on for {1} min)" -f $script:start.ToString('HH:mm:ss'), $mins), 'Gray'))
    foreach ($w in $script:warnings) { $buf.Add(@(("   ! " + $w), 'Yellow')) }
    $buf.Add(@($sep, 'DarkGray'))

    $buf.Add(@(("   CONNECTED NOW ({0})" -f $conns.Count), 'White'))
    if ($conns.Count -eq 0) {
        $buf.Add(@('       (nobody connected yet)', 'DarkGray'))
    } else {
        $shown = @($conns | Select-Object -First 6)
        for ($i = 0; $i -lt $shown.Count; $i++) {
            $c = $shown[$i]
            $ra = ($c.RemoteAddress -replace '^::ffff:', '')
            $key = "{0}:{1}" -f $ra, $c.RemotePort
            $who = $script:sessions[$key]
            if (-not $who) { $who = '(authenticating)' }
            $since = ''
            try { $since = $c.CreationTime.ToString('HH:mm:ss') } catch { }
            $buf.Add(@(("       {0,-16} from {1}:{2}   since {3}" -f $who, (Get-SafeText $ra 45), $c.RemotePort, $since), 'Green'))
        }
    }
    $buf.Add(@($sep, 'DarkGray'))

    $failColor = 'Gray'
    if ($script:failCount -gt 0) { $failColor = 'Red' }
    $buf.Add(@(("   RECENT ACTIVITY   (failed logins: {0}, blocked IPs: {1})" -f $script:failCount, $script:blocked.Count), $failColor))
    if ($script:events.Count -eq 0) {
        $buf.Add(@('       (nothing yet)', 'DarkGray'))
    } else {
        # indexed loop on purpose: foreach over a pipeline that yields exactly one array
        # iterates the array's elements instead of the array itself.
        $n = [math]::Min(8, $script:events.Count)
        for ($i = 0; $i -lt $n; $i++) {
            $e = $script:events[$i]
            $buf.Add(@(("       " + $e[0]), $e[1]))
        }
    }

    # redraw only when something changed (no flicker)
    $hash = ($buf | ForEach-Object { $_[0] }) -join "`n"
    if ($hash -eq $script:lastHash) { return }
    $script:lastHash = $hash
    Clear-Host
    foreach ($l in $buf) { Write-Host $l[0] -ForegroundColor $l[1] }
}

# ======================================================================
#  Entry point
# ======================================================================

# ---- Desktop shortcut (no admin needed) ----
if ($CreateShortcut) {
    $bat = Join-Path $PSScriptRoot 'SSH-Toggle.bat'
    if (-not (Test-Path -LiteralPath $bat)) { Write-Host "SSH-Toggle.bat not found next to the script ($bat)." -ForegroundColor Red; exit 1 }
    $lnkPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'SSH Toggle.lnk'
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = $bat
    $lnk.WorkingDirectory = $PSScriptRoot
    $lnk.IconLocation = "$env:WINDIR\System32\shell32.dll,18"
    $lnk.Description = 'Turn SSH on while this window is open'
    $lnk.Save()
    Write-Host "Shortcut created: $lnkPath" -ForegroundColor Green
    exit 0
}

# ---- Validate input BEFORE elevating (errors show in the normal window) ----
$inputError = $null
if ($TargetUser -match '"' -or $TargetProfile -match '"' -or $AllowedRemote -match '"') { $inputError = 'Quotes are not allowed in parameters.' }
elseif ([string]::IsNullOrWhiteSpace($TargetUser)) { $inputError = 'TargetUser is empty.' }
elseif (-not (Test-RemoteSpec $AllowedRemote)) { $inputError = "AllowedRemote '$AllowedRemote' is not valid. Use LocalSubnet, an IP, a CIDR (192.168.1.0/24), a range, or a comma-separated list." }
elseif ((Test-RemoteSpecIsOpen $AllowedRemote) -and -not $AllowInternet) { $inputError = "AllowedRemote 'Any' opens SSH to every address. Add -AllowInternet if you really want that." }
if ($inputError) {
    Write-Host ''
    Write-Host "  $inputError" -ForegroundColor Red
    Wait-ForKey
    exit 1
}
$TargetProfile = $TargetProfile.TrimEnd('\')

# ---- Elevate (UAC). Always forward the ORIGINAL user, even if another admin approves. ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($k in $PSBoundParameters.Keys) {
        if ($k -eq 'TargetUser' -or $k -eq 'TargetProfile') { continue }
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) { if ($v.IsPresent) { $parts.Add("-$k") } }
        else { $parts.Add("-$k `"$v`"") }
    }
    $parts.Add("-TargetUser `"$TargetUser`"")
    $parts.Add("-TargetProfile `"$TargetProfile`"")
    # -NoProfile: an elevated run must never load a user profile script.
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" " + ($parts -join ' ')
    try { Start-Process -FilePath $WinPS -Verb RunAs -ArgumentList $argList }
    catch { Write-Host 'Administrator approval was cancelled. SSH was not turned on.' -ForegroundColor Yellow; Start-Sleep 3 }
    exit
}

# ---- One instance at a time ----
$created = $false
$mutex = New-Object System.Threading.Mutex($true, 'Global\SSHToggleRunning', [ref]$created)
if (-not $created) {
    Write-Host 'SSH Toggle is already running in another window. Close that one first.' -ForegroundColor Yellow
    Start-Sleep 4
    exit
}

# ---- Maintenance modes ----
if ($Revert -or $LockFolder) {
    $modeErr = $null
    try {
        if ($Revert) { Invoke-RevertMode }
        if ($LockFolder) { Invoke-LockFolder }
    } catch { $modeErr = $_ }
    if ($modeErr) { Write-Host ("  ERROR: {0}" -f $modeErr) -ForegroundColor Red }
    if ($TestSeconds -gt 0) { Start-Sleep 3 } else { Wait-ForKey }
    try { $mutex.ReleaseMutex() } catch { }
    exit
}

$Host.UI.RawUI.WindowTitle = 'SSH IS ON - press Q to turn it off'

# =====================================================================
$err = $null
try {
    try { [Console]::TreatControlCAsInput = $true } catch { }
    try { [Console]::CursorVisible = $false } catch { }

    Clear-Host
    Write-Host ''
    Write-Host '  Turning SSH on...' -ForegroundColor Cyan

    # OpenSSH Server installed?
    if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
        Write-Host '  OpenSSH Server is not installed. Installing it (needs internet)...' -ForegroundColor Yellow
        try { Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null } catch { }
        if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
            throw 'OpenSSH Server could not be installed. Install it manually (Settings > Apps > Optional features, or: winget install Microsoft.OpenSSH.Beta) and run this again.'
        }
    }
    $SshdExe = Get-SshdPath
    if (-not $SshdExe) { Write-Host '  ! sshd.exe path not found; the firewall rule will not be limited to the program.' -ForegroundColor Yellow }

    # Remember the original settings once, so -Revert can restore them.
    Save-OriginalState

    # Best effort: if the window is closed with the X button, PowerShell usually raises this
    # event before exiting. Not guaranteed if the process is killed.
    $null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -MessageData $CleanupText -Action {
        & ([scriptblock]::Create($Event.MessageData))
    }

    Write-Host '  - hardening sshd_config' -ForegroundColor Gray
    $hard = Set-SshdHardening $SshdExe
    $script:keyOnly = [bool]$hard.KeyOnly
    $script:restricted = [bool]$hard.UserRestricted
    foreach ($n in $hard.Notes) { $script:warnings.Add([string]$n) }

    Write-Host '  - firewall: scoped rule' -ForegroundColor Gray
    Set-NetFirewallRule -Name $BuiltinRule -Enabled False -ErrorAction SilentlyContinue   # it is open to every address
    Remove-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Name "$BlockPrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $fwArgs = @{
        Name = $RuleName; DisplayName = 'SSH Toggle (temporary)'; Direction = 'Inbound'; Action = 'Allow'
        Protocol = 'TCP'; LocalPort = $Port; RemoteAddress = @($AllowedRemote -split ',' | ForEach-Object { $_.Trim() }); Profile = 'Any'
    }
    if ($SshdExe) { $fwArgs['Program'] = $SshdExe }
    New-NetFirewallRule @fwArgs | Out-Null

    Write-Host '  - starting sshd' -ForegroundColor Gray
    Set-Service -Name sshd -StartupType Manual     # never starts by itself at boot
    Start-Service -Name sshd

    Write-Host ("  - waiting for sshd to listen on port {0}" -f $Port) -ForegroundColor Gray
    $deadline = (Get-Date).AddSeconds(15)
    $listening = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-PortOpen $Port) { $listening = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $listening) {
        $st = (Get-Service -Name sshd -ErrorAction SilentlyContinue).Status
        throw ("sshd (status: {0}) is not accepting connections on port {1} after 15 seconds. See Event Viewer > Applications and Services Logs > OpenSSH > Operational." -f $st, $Port)
    }

    $script:ips = @(Get-LocalIPs)

    # ---- warnings worth showing ----
    $fwp = @()
    try { $fwp = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop | Where-Object { $_.displayName -notmatch 'Windows' } | ForEach-Object { $_.displayName }) } catch { }
    if ($fwp.Count -gt 0) {
        $script:warnings.Add(("Third-party firewall: {0}. If the other device times out, allow TCP {1} there." -f ($fwp -join ', '), $Port))
    }
    if ($AllowedRemote -ieq 'LocalSubnet') {
        $pub = @()
        try { $pub = @(Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $_.NetworkCategory -eq 'Public' } | ForEach-Object { $_.Name }) } catch { }
        if ($pub.Count -gt 0) {
            $script:warnings.Add(("Network '{0}' is Public: anyone on it can reach the SSH port. On shared Wi-Fi use -AllowedRemote <your device IP>." -f (Get-SafeText ($pub -join ', ') 30)))
        }
    }
    $r1 = Get-UnsafeAclReason $PSScriptRoot
    if (-not $r1) { $r1 = Get-UnsafeAclReason $PSCommandPath }
    if ($r1) {
        $script:warnings.Add(("This script's folder can be modified by non-admin programs ({0}). The script runs as admin: run it once with -LockFolder." -f (Get-SafeText $r1 70)))
    }

    # Sessions that were already connected before we started: learn their user names from the log.
    try {
        foreach ($pe in @(Get-WinEvent -FilterHashtable @{ LogName = 'OpenSSH/Operational'; StartTime = (Get-Date).AddHours(-24) } -ErrorAction Stop)) {
            $pr = ConvertFrom-SshdMessage $pe.Message
            if ($pr -and $pr.Type -eq 'accept') { $script:sessions["$($pr.Ip):$($pr.Port)"] = (Get-SafeText $pr.User 32) }
        }
    } catch { }

    $tick = 0
    while ($true) {
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq [ConsoleKey]::Q) { break }
            if ($k.Key -eq [ConsoleKey]::C -and ($k.Modifiers -band [ConsoleModifiers]::Control)) { break }
        }
        if ($TestSeconds -gt 0 -and ((Get-Date) - $script:start).TotalSeconds -ge $TestSeconds) { break }
        if ($tick % 15 -eq 14) { $script:ips = @(Get-LocalIPs) }
        Update-Events
        Render
        $tick++
        Start-Sleep -Milliseconds 1000
    }
}
catch {
    $err = $_
}
finally {
    try { [Console]::CursorVisible = $true } catch { }
    Write-Host ''
    Write-Host '  Turning SSH off...' -ForegroundColor Cyan
    & ([scriptblock]::Create($CleanupText))

    $svc = (Get-Service -Name sshd -ErrorAction SilentlyContinue).Status
    $rule = [bool](Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue)
    $left = @(Get-Process -Name sshd, sshd-session -ErrorAction SilentlyContinue).Count
    $ruleText = 'removed'; if ($rule) { $ruleText = 'STILL PRESENT' }
    Write-Host ("  sshd: {0} | temporary firewall rule: {1} | sshd processes left: {2}" -f $svc, $ruleText, $left) -ForegroundColor Green
    if ($err) {
        Write-Host ''
        Write-Host ("  ERROR: {0}" -f $err) -ForegroundColor Red
        if ($TestSeconds -gt 0) { Start-Sleep 5 } else { Wait-ForKey 'Press any key to close...' }
    } else {
        Start-Sleep -Seconds 2
    }
    try { $mutex.ReleaseMutex() } catch { }
}
