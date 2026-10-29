# Raven relay kit, Windows: a dedicated relay for your friends (raven-node relay) as a per-user
# logon task. Guide: docs/RELAY_KIT.md; notes: WINDOWS_SERVICE.md ("Dedicated relay (logon task)").
#
#   powershell -ExecutionPolicy Bypass -File node/scripts/install/windows_relay.ps1 -PublicHost <public IP or DNS name>
#
# The relay holds NO Raven identity and touches no keystore: only its own libp2p key
# (relay_key.ed25519 in -RelayDir), and it relays only between the PeerIds you allow
# (raven-relay allow <PeerId>). It passes encrypted bytes. It learns both PeerIds and IPs of
# every circuit, its timing and byte counts; never a message, never a Raven ID.
# The task runs only while you are signed in, and a sleeping PC relays nothing (design Q9: no
# Windows service, no boot task). Task Scheduler keeps no log: `raven-relay status` shows the
# state and counts, and also the allow-list (friends' PeerIds and your labels) and the relay's
# own addresses.
#
# -RelayDir    key, allow-list, status (default %LOCALAPPDATA%\RavenRelay, the folder
#              INSTALL_Windows.md uses, so a relay you ran by hand keeps its PeerId)
# -BinDir      binaries, their .prev copies, kit.conf, raven-relay.cmd (default
#              %LOCALAPPDATA%\RavenRelayBin)
# -PublicHost  the address friends reach it at (cards name it)
# -Port 7423   TCP + QUIC port (7424/7425: a second Raven profile's; 7427: the friend relay's;
#              else 7428)
# -Tcp443      direct (also TCP 443 for networks that let only HTTPS out), 7443 (listen on 7443,
#              your router maps 443 to it) or off. http.sys / IIS may already hold 443.
# -NoAutonat   do not answer reachability checks for friends; -CountsEvery 300 (30-3600 s)
# -Prebuilt <dir>  take raven-node.exe and raven.exe (or ash.exe) from there instead of building
# -Lab         a debug build with the lab unlock (RAVEN_LAB_TEST_A=1); tests only
# -TaskName / -SkipScheduledTask / -NoStart: CI hooks. -Uninstall removes the task and the
# binaries (keeps -RelayDir: the key). -Rollback swaps back the previous binaries.
# Settings not passed come from kit.conf (written by the last run; parsed, never run).
# Update: re-run; the PeerId must stay the same (else the previous binaries come back).
# Exit codes: 0 ok; 1 failed; 2 bad settings; 3 this build holds p2p; 4 a port is busy;
# 5 the relay folder cannot be used. The firewall is never changed: the rules are printed.
# Keep this file ASCII-only: Windows PowerShell 5.1 reads a BOM-less file as ANSI.
param(
    [string]$RelayDir = $(Join-Path $env:LOCALAPPDATA "RavenRelay"),
    [string]$BinDir = $(Join-Path $env:LOCALAPPDATA "RavenRelayBin"),
    [string]$PublicHost = "",
    [ValidateRange(1, 65535)]
    [int]$Port = 7423,
    [ValidateSet("direct", "7443", "off")]
    [string]$Tcp443 = "direct",
    [switch]$NoAutonat,
    [ValidateRange(30, 3600)]
    [int]$CountsEvery = 300,
    [string]$Prebuilt = "",
    [switch]$Lab,
    [string]$TaskName = "RavenRelay",
    [switch]$SkipScheduledTask,
    [switch]$NoStart,
    [switch]$Uninstall,
    [switch]$Rollback
)

$ErrorActionPreference = "Stop"

function Fail-Settings([string]$Message) {
    Write-Host "relay kit: $Message"
    exit 2
}

foreach ($dir in @($RelayDir, $BinDir)) {
    if ($dir -match '["%\r\n]') { Fail-Settings "-RelayDir and -BinDir must not contain a double quote, % or a newline" }
}
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$BinDir = (Resolve-Path -LiteralPath $BinDir).Path
$kitConf = Join-Path $BinDir "kit.conf"

# kit.conf: plain KEY=VALUE lines, parsed (never run), the same keys as the Linux and macOS kits.
$known = @("RAVEN_RELAY_PORT", "RAVEN_RELAY_TCP443", "RAVEN_RELAY_HOST", "RAVEN_RELAY_AUTONAT",
    "RAVEN_RELAY_COUNTS_EVERY", "RAVEN_RELAY_LAB", "RAVEN_RELAY_DIR")
$conf = @{}
if (Test-Path -LiteralPath $kitConf) {
    $n = 0
    foreach ($line in (Get-Content -LiteralPath $kitConf)) {
        $n++
        if ($line -eq "" -or $line.StartsWith("#")) { continue }
        if ($line -notmatch '^(RAVEN_RELAY_[A-Z0-9_]*)=(.*)$') { Fail-Settings "$kitConf line ${n}: not a RAVEN_RELAY_KEY=value line" }
        $key = $Matches[1]
        $value = $Matches[2]
        if ($known -notcontains $key) { Fail-Settings "$kitConf line ${n}: unknown setting $key" }
        # The folder may hold any letter (a user name with an accent); the rest is plain.
        $plain = $value -match '^[A-Za-z0-9._:/@\[\]-]*$'
        $folder = ($key -eq "RAVEN_RELAY_DIR") -and ($value -notmatch '["%\x00-\x1f]')
        if (-not ($plain -or $folder)) { Fail-Settings "$kitConf line ${n}: bad value for $key" }
        if (-not $conf.ContainsKey($key)) { $conf[$key] = $value }
    }
}
# A parameter you pass wins over kit.conf.
if (-not $PSBoundParameters.ContainsKey("Port") -and $conf.ContainsKey("RAVEN_RELAY_PORT")) {
    $v = $conf["RAVEN_RELAY_PORT"]
    if (($v -notmatch '^\d{1,5}$') -or ([int]$v -lt 1) -or ([int]$v -gt 65535)) { Fail-Settings "kit.conf: bad RAVEN_RELAY_PORT" }
    $Port = [int]$v
}
if (-not $PSBoundParameters.ContainsKey("Tcp443") -and $conf.ContainsKey("RAVEN_RELAY_TCP443")) {
    if (@("direct", "7443", "off") -notcontains $conf["RAVEN_RELAY_TCP443"]) { Fail-Settings "kit.conf: bad RAVEN_RELAY_TCP443" }
    $Tcp443 = $conf["RAVEN_RELAY_TCP443"]
}
if (-not $PSBoundParameters.ContainsKey("PublicHost") -and $conf.ContainsKey("RAVEN_RELAY_HOST")) {
    $PublicHost = $conf["RAVEN_RELAY_HOST"]
}
if (-not $PSBoundParameters.ContainsKey("NoAutonat") -and $conf.ContainsKey("RAVEN_RELAY_AUTONAT")) {
    $NoAutonat = [switch]($conf["RAVEN_RELAY_AUTONAT"] -eq "0")
}
if (-not $PSBoundParameters.ContainsKey("CountsEvery") -and $conf.ContainsKey("RAVEN_RELAY_COUNTS_EVERY")) {
    $v = $conf["RAVEN_RELAY_COUNTS_EVERY"]
    if (($v -notmatch '^\d{2,4}$') -or ([int]$v -lt 30) -or ([int]$v -gt 3600)) { Fail-Settings "kit.conf: bad RAVEN_RELAY_COUNTS_EVERY" }
    $CountsEvery = [int]$v
}
if (-not $PSBoundParameters.ContainsKey("Lab") -and $conf.ContainsKey("RAVEN_RELAY_LAB")) {
    $Lab = [switch]($conf["RAVEN_RELAY_LAB"] -eq "1")
}
if (-not $PSBoundParameters.ContainsKey("RelayDir") -and $conf.ContainsKey("RAVEN_RELAY_DIR")) {
    $RelayDir = $conf["RAVEN_RELAY_DIR"]
}
if ($Port -lt 1 -or $Port -gt 65535) { Fail-Settings "-Port must be 1-65535" }
if (@("direct", "7443", "off") -notcontains $Tcp443) { Fail-Settings "-Tcp443 must be direct, 7443 or off" }
if ($CountsEvery -lt 30 -or $CountsEvery -gt 3600) { Fail-Settings "-CountsEvery must be 30-3600" }
if (($Tcp443 -eq "direct" -and $Port -eq 443) -or ($Tcp443 -eq "7443" -and $Port -eq 7443)) {
    Fail-Settings "-Port $Port is already the TCP 443 listener: pass -Tcp443 off"
}
if ($PublicHost -and ($PublicHost -notmatch '^\[?[0-9A-Fa-f:.]+\]?$|^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')) {
    Fail-Settings "-PublicHost must be the public IP or DNS name friends reach this relay at, e.g. 203.0.113.7 or relay.example.org"
}
if ($RelayDir -match '["%\r\n]') { Fail-Settings "-RelayDir must not contain a double quote, % or a newline" }
New-Item -ItemType Directory -Force -Path $RelayDir | Out-Null
# Task Scheduler runs with another working directory: register absolute paths only.
$RelayDir = (Resolve-Path -LiteralPath $RelayDir).Path

$exe = Join-Path $BinDir "raven-node.exe"
$cli = Join-Path $BinDir "raven.exe"
$statusPath = Join-Path $RelayDir "relay_status.json"

# The TCP ports it listens on (the first is also QUIC).
$tcpPorts = @("$Port")
if ($Tcp443 -eq "direct") { $tcpPorts += "443" }
if ($Tcp443 -eq "7443") { $tcpPorts += "7443" }

# The `raven-node relay` flags after --data-dir. Never the flag that serves anyone (a test and
# a CI tripwire check this file for it).
$relayArgs = @("--listen", "$Port")
if ($Tcp443 -eq "direct") { $relayArgs += @("--also-tcp", "443") }
if ($Tcp443 -eq "7443") { $relayArgs += @("--also-tcp", "7443:443") }
if ($PublicHost) { $relayArgs += @("--public-host", $PublicHost) }
if (-not $NoAutonat) { $relayArgs += "--autonat-server" }
$relayArgs += @("--counts-every", "$CountsEvery")

function Read-RelayStatus {
    if (-not (Test-Path -LiteralPath $statusPath)) { return $null }
    try {
        return (Get-Content -Raw -LiteralPath $statusPath | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Stop-Relay {
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null } catch { }
    # Path-filtered: another install's or another user's raven-node is left alone.
    $procs = @(Get-Process -Name "raven-node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
    foreach ($proc in $procs) {
        Write-Host "stopping the running relay (pid $($proc.Id)) so its binary can be replaced"
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $proc.Id -Timeout 15 -ErrorAction SilentlyContinue
    }
    return $procs.Count
}

function Test-TaskExists {
    return [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
}

function Swap-Prev {
    foreach ($name in @("raven-node.exe", "raven.exe")) {
        if (-not (Test-Path -LiteralPath (Join-Path $BinDir "$name.prev"))) { return $false }
    }
    foreach ($name in @("raven-node.exe", "raven.exe")) {
        $cur = Join-Path $BinDir $name
        $swap = Join-Path $BinDir ".$name.swap"
        Move-Item -LiteralPath $cur -Destination $swap -Force
        Move-Item -LiteralPath "$cur.prev" -Destination $cur -Force
        Move-Item -LiteralPath $swap -Destination "$cur.prev" -Force
    }
    return $true
}

# Wait up to 20 s for the started relay: its status file is written by a raven-node.exe from
# -BinDir, lists the listen ports and (on an update) the PeerId it had before.
function Wait-RelayUp([string]$WantPeer) {
    for ($i = 1; $i -le 20; $i++) {
        Start-Sleep -Seconds 1
        $status = Read-RelayStatus
        if ($null -eq $status) { continue }
        $pids = @(Get-Process -Name "raven-node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe } | ForEach-Object { $_.Id })
        if ($pids -notcontains [int]$status.pid) { continue }
        $listen = @($status.listen_addrs)
        $missing = @($tcpPorts | Where-Object { $p = $_; -not ($listen | Where-Object { $_ -match "^/ip[46]/[^/]+/tcp/$p$" }) })
        if ($missing.Count -gt 0) { continue }
        if ($WantPeer -and ([string]$status.peer_id -ne $WantPeer)) {
            Write-Host "relay kit: the relay's PeerId changed ($WantPeer -> $($status.peer_id)): its key was not kept"
            return $null
        }
        Write-Host "relay kit: relay up after ${i}s (pid $($status.pid))"
        return [string]$status.peer_id
    }
    Write-Host "relay kit: the relay did not report its ports within 20 s"
    return $null
}

if ($Uninstall) {
    $status = Read-RelayStatus
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Relay | Out-Null
    foreach ($name in @("raven-node.exe", "raven.exe", "raven-node.exe.prev", "raven.exe.prev", "raven.exe.old", "raven-relay.cmd", "kit.conf")) {
        Remove-Item -LiteralPath (Join-Path $BinDir $name) -Force -ErrorAction SilentlyContinue
    }
    Write-Host "relay kit: removed the task $TaskName and the binaries in $BinDir"
    $peerText = ""
    if ($null -ne $status) { $peerText = " of $($status.peer_id)" }
    Write-Host "relay kit: kept $RelayDir (key$peerText and allow-list): a re-install keeps the PeerId; delete the folder yourself to forget it"
    exit 0
}

if ($Rollback) {
    $status = Read-RelayStatus
    $oldPeer = ""
    if ($null -ne $status) { $oldPeer = [string]$status.peer_id }
    Stop-Relay | Out-Null
    if (-not (Swap-Prev)) { throw "no previous binaries to roll back to ($BinDir\*.prev)" }
    if ((Test-TaskExists) -and -not $NoStart) {
        Start-ScheduledTask -TaskName $TaskName
        if ($null -eq (Wait-RelayUp $oldPeer)) { throw "the rolled-back relay did not come up (-Rollback again swaps back)" }
    }
    Write-Host "relay kit: rolled back to the previous binaries"
    exit 0
}

# The binaries to install: -Prebuilt, else a build from this checkout.
if ($Prebuilt) {
    if (-not (Test-Path -LiteralPath $Prebuilt -PathType Container)) { Fail-Settings "-Prebuilt $Prebuilt is not a folder" }
    $srcDir = (Resolve-Path -LiteralPath $Prebuilt).Path
} else {
    $Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
    $cargoArgs = @("build", "--locked", "-p", "raven-node", "-p", "ash")
    $profileName = "debug"
    if (-not $Lab) {
        $cargoArgs += "--release"
        $profileName = "release"
    }
    Push-Location $Root
    # --locked: build exactly the audited Cargo.lock.
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo build failed" }
    Pop-Location
    $targetDir = $env:CARGO_TARGET_DIR
    if (-not $targetDir) { $targetDir = Join-Path $Root "target" }
    $srcDir = Join-Path $targetDir $profileName
}
$srcNode = Join-Path $srcDir "raven-node.exe"
$srcCli = Join-Path $srcDir "raven.exe"
if (-not (Test-Path -LiteralPath $srcCli)) { $srcCli = Join-Path $srcDir "ash.exe" }
if (-not (Test-Path -LiteralPath $srcNode)) { throw "no raven-node.exe in $srcDir" }
if (-not (Test-Path -LiteralPath $srcCli)) { throw "no raven.exe (or ash.exe) in $srcDir" }
$help = [string](& $srcNode relay --help | Out-String)
if (($help -notmatch '--also-tcp') -or ($help -notmatch '--public-host') -or ($help -notmatch '--check')) {
    throw "this raven-node is too old for the kit (no --also-tcp / --public-host / --check): update it or point -Prebuilt at a newer build"
}

# What runs now. A running relay holds its ports and its folder's lock.
$oldPeer = ""
$status = Read-RelayStatus
if ($null -ne $status) { $oldPeer = [string]$status.peer_id }
$wasRunning = (Stop-Relay) -gt 0

# The NEW binary checks the gate, the folder and every port before anything is replaced. It
# creates nothing. The lab unlock only under -Lab, and only for this call.
$savedLab = $env:RAVEN_LAB_TEST_A
if ($Lab) { $env:RAVEN_LAB_TEST_A = "1" } else { Remove-Item Env:\RAVEN_LAB_TEST_A -ErrorAction SilentlyContinue }
try {
    & $srcNode relay --check --data-dir $RelayDir @relayArgs
    $rc = $LASTEXITCODE
} finally {
    if ($null -eq $savedLab) { Remove-Item Env:\RAVEN_LAB_TEST_A -ErrorAction SilentlyContinue } else { $env:RAVEN_LAB_TEST_A = $savedLab }
}
if ($rc -ne 0) {
    switch ($rc) {
        3 { Write-Host "relay kit: this build holds p2p (P2P_PRODUCTION_ENABLED=false): the kit installs only a build with p2p on, or a lab build (-Lab, a debug build; not for real use)" }
        4 {
            Write-Host "relay kit: a listen port is busy (lines above; http.sys or IIS may hold 443). Pick another port (-Port 7428; 7424/7425 are a second Raven profile's, 7427 the friend relay's) or -Tcp443 off"
            Write-Host "relay kit: -Tcp443 7443 fits only when your router's public TCP 443 is free for the relay and maps it to 7443 here, never when it already goes to a web server"
        }
        5 { Write-Host "relay kit: the relay folder cannot be used (line above): it holds a Raven profile, or a relay already runs in it (stop that one first)" }
        default { Write-Host "relay kit: raven-node relay --check failed (exit $rc)" }
    }
    if ($wasRunning -and (Test-TaskExists)) {
        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host "relay kit: the relay that ran before was started again (unchanged)"
    }
    exit $rc
}

# Binaries, the old ones kept as .prev.
function Install-Binary([string]$Src, [string]$Dst) {
    if (Test-Path -LiteralPath $Dst) {
        Copy-Item -LiteralPath $Dst -Destination "$Dst.prev" -Force
    }
    try {
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    } catch {
        # raven.exe can be held open by a running CLI session: Windows refuses to overwrite a
        # running image but allows renaming it. Move the old copy aside and retry.
        if (-not (Test-Path -LiteralPath $Dst)) { throw }
        $old = "$Dst.old"
        Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $Dst -Destination $old -Force
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    }
}
$hadPrev = Test-Path -LiteralPath $exe
Install-Binary $srcNode $exe
Install-Binary $srcCli $cli

# raven-relay.cmd: `raven-relay status|card|allow|deny ...` for this relay folder.
$wrapper = Join-Path $BinDir "raven-relay.cmd"
# cmd.exe reads a .cmd in the OEM code page.
Set-Content -LiteralPath $wrapper -Encoding Oem -Value "@`"%~dp0raven.exe`" --data-dir `"$RelayDir`" relay %*"

$autonatValue = "1"
if ($NoAutonat) { $autonatValue = "0" }
$labValue = "0"
if ($Lab) { $labValue = "1" }
$confLines = @(
    "# Raven relay kit settings (docs/RELAY_KIT.md), written by windows_relay.ps1.",
    "# Plain KEY=VALUE lines, parsed and never run. A parameter you pass overrides a line.",
    "RAVEN_RELAY_PORT=$Port",
    "RAVEN_RELAY_TCP443=$Tcp443",
    "RAVEN_RELAY_HOST=$PublicHost",
    "RAVEN_RELAY_AUTONAT=$autonatValue",
    "RAVEN_RELAY_COUNTS_EVERY=$CountsEvery",
    "RAVEN_RELAY_LAB=$labValue",
    "RAVEN_RELAY_DIR=$RelayDir"
)
Set-Content -LiteralPath $kitConf -Encoding UTF8 -Value $confLines

# The task's command line: every word plain except the quoted folder.
$taskArgs = "relay --data-dir `"$RelayDir`" " + ($relayArgs -join " ")
if ($SkipScheduledTask) {
    Write-Host "SkipScheduledTask: binaries, raven-relay.cmd and kit.conf written; logon task not registered"
    Write-Host "relay command: `"$exe`" $taskArgs"
} else {
    # Per-user logon task, the same Task Scheduler settings as windows_service.ps1: no
    # execution time limit (PT0S; the 72h default would stop the relay after three days),
    # restart on failure, one instance.
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if ($Lab) {
        # The lab unlock for the relay only (a debug build; not for real use).
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/d /s /c `"set RAVEN_LAB_TEST_A=1&& `"$exe`" $taskArgs`""
    } else {
        $action = New-ScheduledTaskAction -Execute $exe -Argument $taskArgs
    }
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Raven relay for your friends (raven-node relay; holds no Raven identity)" | Out-Null
    Write-Host "installed task $TaskName"
    if ($NoStart) {
        Write-Host "NoStart: task registered, not started"
    } else {
        Start-ScheduledTask -TaskName $TaskName
        $peer = Wait-RelayUp $oldPeer
        if ($null -eq $peer) {
            Stop-Relay | Out-Null
            if ($hadPrev -and (Swap-Prev)) {
                Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                throw "the new relay did not come up: the previous binaries are back (-Rollback swaps again)"
            }
            throw "the relay did not come up (task $TaskName is registered; raven-relay status shows its last state)"
        }
        if ($oldPeer) {
            Write-Host "relay PeerId: $peer (kept: friends' via= lines still work)"
        } else {
            Write-Host "relay PeerId: $peer (new: give friends the card below)"
        }
    }
}

Write-Host "relay-dir=$RelayDir"
Write-Host "bin-dir=$BinDir (raven-relay.cmd, raven.exe, raven-node.exe)"
Write-Host "listening: TCP $($tcpPorts -join ',') and UDP (QUIC) $Port"
if (-not $PublicHost) {
    Write-Host "NOTE: no -PublicHost: cards name only what the relay sees itself; re-run with -PublicHost <public IP or DNS name>, or use 'raven-relay card --host <it>'"
}
Write-Host "Firewall (not changed by the kit): in an ELEVATED PowerShell, Private profile only, never Public:"
Write-Host "  New-NetFirewallRule -DisplayName `"Raven relay`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort $($tcpPorts -join ',') -Profile Private"
Write-Host "  New-NetFirewallRule -DisplayName `"Raven relay`" -Direction Inbound -Program `"$exe`" -Protocol UDP -LocalPort $Port -Profile Private"
Write-Host "Router: forward TCP+UDP $Port to this PC$(if ($Tcp443 -eq 'direct') { ', and TCP 443' } elseif ($Tcp443 -eq '7443') { ', and TCP 443 to its port 7443' })."
Write-Host "The task runs only while you are signed in; a sleeping PC relays nothing (Q9). Logs: none (Task Scheduler keeps no stderr); raven-relay status shows the state and counts."
Write-Host "Next (in $BinDir, or add it to PATH):"
Write-Host "  1. raven-relay card                     the via= lines, and the 'raven relay use ...' line for each friend"
Write-Host "  2. raven-relay allow <PeerId>           for EVERY friend who sends or is reached through the relay (their 'raven whoami --peer-id', taken from them directly)"
Write-Host "  3. raven-relay status                   allow-list (friends' PeerIds, your labels), the relay's addresses, state, counts"
Write-Host "     (remove PeerIds, labels and public IPs before you share its output)"
Write-Host "Update: re-run this script (kit.conf remembers the settings; the PeerId is kept). Rollback: -Rollback. Uninstall: -Uninstall."
if ($Lab) {
    Write-Host "LAB BUILD: a debug build with the lab unlock (RAVEN_LAB_TEST_A=1). Not for real use."
}
