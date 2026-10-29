# Install always-on raven-node for the current Windows user (no MSI / no system ash overwrite).
# -SkipScheduledTask: build + copy binaries only (CI / no persistent logon task). See WINDOWS_SERVICE.md.
# -LanListen: the default follows the build, identically on every OS installer: the task gets the
#   address `raven-node lan-default` prints, which is auto (every network of this PC, local sources
#   and contacts only) once the build's B12 gate (LAN_AUTO_LISTEN_PRODUCTION_ENABLED, the Phase 3
#   LAN amendment) is open, and 127.0.0.1:7420 (this PC only) until then; a profile that picked a
#   LAN port of its own (Phase 6b, a random port for new profiles) gets that port instead
#   (`raven-node lan-default --data-dir`: auto:PORT, 127.0.0.1:PORT; auto:PORT goes into the task as
#   a plain auto, which follows the profile's port at every start). Pass e.g.
#   -LanListen 192.168.1.20:7420, [::]:7420 or auto to choose; `raven lan off` closes LAN later.
#   For auto the installer prints two Private-profile firewall rules (TCP on its port, and UDP 7420
#   for the nearby search) to run elevated; it never changes the firewall itself.
# RAVEN_INSTALL_RENDER_ONLY=1 (environment) builds, copies, stops and registers nothing: it asks the
#   raven-node.exe already in -BinDir for the LAN default, prints lan-listen= and the task's
#   arguments (service-args=), and exits.
# -BleListen: where the local Bluetooth stand-in (mock BLE) listens (default RAVEN_BLE_LISTEN,
#   else 127.0.0.1:7421; 127.0.0.1:0 = any free port), e.g. for a test node beside another Raven.
# -InternetListen: Internet direct exposure is opt-in too (default: no listener; pass e.g.
#   -InternetListen 0.0.0.0:7422, a bare IP gets port 7422). Without it,
#   `raven node internet on --listen 0.0.0.0:7422` turns it on later (applied at the next
#   task start). The installer never changes the firewall: it prints the rule to run elevated.
# -P2pListen: libp2p (relay + hole punching, TCP and UDP 7423) is opt-in the same way (default:
#   no flag; pass e.g. -P2pListen 7423 = every interface, IPv4 + IPv6; IP:PORT = that address
#   only; off = off even if `raven node p2p on` saved it). -P2pRelays <multiaddr>[,<multiaddr>]
#   (at most 2, each ending in /p2p/<relay PeerId>) keeps a reservation on those relays;
#   -P2pRelay relays for your verified contacts (and the PeerIds in relay_allow.json) with this
#   profile's own relay key, never your PeerId: the friend relay on TCP and UDP 7427, the
#   consent `raven relay offer on` saves;
#   -Upnp 1|0 saves the router port-mapping choice (`raven node upnp on|off`). Without -Upnp,
#   an interactive install that turns -P2pListen on asks once (Enter = no); a non-interactive
#   one never asks (stays unset).
# -TaskName / -NoStart: CI hooks (register a uniquely named task without launching the daemon).
# Re-running is the upgrade path: the running daemon is stopped before its binaries are
# replaced and the task is re-registered with the current settings.
# The Tor onion carrier (switched on in release builds in 2026-10 after the three-machine field
#   test; not independently reviewed): the installer builds with the cargo feature `tor` and
#   installs raven-tor-helper.exe (Arti, the Tor client, in its own process) next to
#   raven-node.exe. raven-node starts it and keeps an onion service, so friends can reach this PC
#   from any network without a port forward; Tor relays are the only third party it talks to.
#   -NoTor builds without it and removes an installed one (raven status then says "Tor: not built
#   in this raven").
# Bluetooth nearby (Phase 5, docs/NEARBY.md) is in release builds on macOS only: Windows has no
#   release Bluetooth backend (its radio would use the adapter's fixed public address), so this
#   installer builds none and nearby stays lab-only here (NEARBY_PRODUCTION_ENABLED is false on
#   Windows). A debug lab build with feature nearby-radio has the WinRT backend: the logon task
#   runs raven-node in your user session, where that radio runs (session 0 is not supported).
# Keep this file ASCII-only: Windows PowerShell 5.1 reads a BOM-less file as ANSI, where the
# UTF-8 bytes of an em dash contain a smart double quote and break the string literal.
param(
    # Default = the profile raven.exe / ash.exe use without --data-dir (raven-core
    # resolve_raven_data_dir): RAVEN_DATA_DIR, ASH_DATA_DIR, a legacy ~\.raven-ash while
    # ~\.raven does not exist, else ~\.raven. The IPC pipe is per user, not per profile, so
    # a daemon serving any other directory would answer the CLI's pings for a profile it
    # does not serve.
    [string]$DataDir = $(& {
        if ($env:RAVEN_DATA_DIR) { return $env:RAVEN_DATA_DIR }
        if ($env:ASH_DATA_DIR) { return $env:ASH_DATA_DIR }
        $homeDir = $env:HOME
        if (-not $homeDir) { $homeDir = $env:USERPROFILE }
        if (-not $homeDir) { $homeDir = "$($env:HOMEDRIVE)$($env:HOMEPATH)" }
        $current = Join-Path $homeDir ".raven"
        $legacy = Join-Path $homeDir ".raven-ash"
        if ((Test-Path -LiteralPath $legacy -PathType Container) -and -not (Test-Path -LiteralPath $current)) { return $legacy }
        return $current
    }),
    [string]$BinDir = $(Join-Path $env:LOCALAPPDATA "RavenNode"),
    [string]$LanListen = "",
    [string]$BleListen = $(if ($env:RAVEN_BLE_LISTEN) { $env:RAVEN_BLE_LISTEN } else { "127.0.0.1:7421" }),
    [string]$InternetListen = "",
    [string]$P2pListen = "",
    # -P2pRelays a,b (an array) and -P2pRelays "a,b" (one comma separated string) both work.
    [string[]]$P2pRelays = @(),
    [switch]$P2pRelay,
    [string]$Upnp = "",
    [string]$TaskName = "RavenNodeBridge",
    [switch]$SkipScheduledTask,
    [switch]$NoStart,
    # Build without the Tor onion carrier's helper (raven-tor-helper.exe) and remove an installed one.
    [switch]$NoTor
)

$ErrorActionPreference = "Stop"
$renderOnly = $false
if ($env:RAVEN_INSTALL_RENDER_ONLY -eq "1") {
    $renderOnly = $true
} elseif ($env:RAVEN_INSTALL_RENDER_ONLY -and ($env:RAVEN_INSTALL_RENDER_ONLY -ne "0")) {
    throw "RAVEN_INSTALL_RENDER_ONLY must be 1 (print the task's arguments, install nothing) or 0"
}
# auto / auto:PORT / IP:PORT / [IPv6]:PORT / [IPv6%zone]:PORT characters only (it lands on the
# task's command line); raven-node validates the rest. Empty = the build's default, asked after the
# binaries are installed; a given -LanListen is checked now, so a typo stops the install before the
# build and before the running daemon is stopped. Case-sensitive: ASCII letters and digits only.
$lanListenPattern = '^(auto(:[0-9]{1,5})?|[\[\]0-9A-Za-z.:%]+)$'
$lanListenHelp = "-LanListen must look like auto, 192.168.1.20:7420 or [::]:7420"
if ($LanListen -and ($LanListen -cnotmatch $lanListenPattern)) {
    throw $lanListenHelp
}
# IP:PORT / [IPv6]:PORT characters only (it lands on the task's command line); raven-node
# validates the rest.
if ($BleListen -notmatch '^[\[\]0-9A-Za-z.:]+$') {
    throw "-BleListen must look like 127.0.0.1:7421 or 127.0.0.1:0"
}
# IP[:port] / [IPv6][:port] characters only (it lands on the task's command line);
# raven-node validates the rest.
if ($InternetListen -and ($InternetListen -notmatch '^[\[\]0-9A-Za-z.:]+$')) {
    throw "-InternetListen must look like 0.0.0.0:7422 or [::]:7422"
}
# libp2p settings: empty = no flag (node_policy.json decides, as today). PORT / IP:PORT /
# [IPv6]:PORT / on / off characters only; raven-node validates the rest.
if ($P2pListen -and ($P2pListen -notmatch '^[\[\]0-9A-Za-z.:]+$')) {
    throw "-P2pListen must look like 7423, 0.0.0.0:7423, [::]:7423 or off"
}
# "relay" (no listening port) is retired: a node without a listener can never hole-punch,
# so it becomes 7423 (every interface), like `raven node p2p on --listen relay`; the
# firewall rule and the UPnP question then follow for it.
if ($P2pListen -eq "relay") {
    $P2pListen = "7423"
    Write-Host "note: -P2pListen relay is retired: it opened no port, so hole punching could never work. Using 7423 (TCP and UDP, every interface) instead."
}
$p2pListenOn = [bool]$P2pListen -and ($P2pListen -ne "off")
# The libp2p port of -P2pListen: "[v6]:port", "v4:port", a bare port or "on" (the default
# port); empty when off.
$p2pPort = ""
if ($p2pListenOn) {
    $p2pPort = "7423"
    if (($P2pListen -match '^\[[^\]]*\]:(\d+)$') -or ($P2pListen -match '^[^:\[\]]+:(\d+)$')) {
        $p2pPort = $Matches[1]
    } elseif ($P2pListen -match '^\d+$') {
        $p2pPort = $P2pListen
    }
}
$p2pRelayList = @()
foreach ($item in $P2pRelays) {
    foreach ($entry in ([string]$item -split ',')) {
        $entry = $entry.Trim()
        if (-not $entry) { continue }
        if (($entry -notmatch '^/[0-9A-Za-z./:_-]+$') -or ($entry -notlike '*/p2p/?*')) {
            throw "-P2pRelays entries must look like /ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>"
        }
        $p2pRelayList += $entry
    }
}
if ($p2pRelayList.Count -gt 2) {
    throw "-P2pRelays takes at most 2 relays"
}
if ($Upnp -and ($Upnp -notmatch '^[01]$')) {
    throw "-Upnp must be 1 (map the p2p port on the router) or 0"
}
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

if ($renderOnly) {
    # Render-only creates nothing: the folders are shown as given, made absolute.
    $DataDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DataDir)
    $BinDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BinDir)
} else {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    # Task Scheduler runs with another working directory: register absolute paths only.
    $DataDir = (Resolve-Path -LiteralPath $DataDir).Path
    $BinDir = (Resolve-Path -LiteralPath $BinDir).Path
}

# UPnP (owner decision Q8, "ask once at setup"): -Upnp decides. Without it, an
# interactive install (console input not redirected) that opens a p2p port asks the same
# one-time question as `raven node p2p on`, unless node_policy.json already holds an answer
# ("upnp": true|false). Enter = no. A host that cannot prompt leaves it unset. Asked before
# the build so nobody waits for cargo to answer it; saved after install below.
$upnpMode = ""
if ($Upnp -eq "1") {
    $upnpMode = "on"
} elseif ($Upnp -eq "0") {
    $upnpMode = "off"
} elseif ($p2pPort -and -not $renderOnly -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
    $policyPath = Join-Path $DataDir "node_policy.json"
    $upnpAnswered = $false
    if (Test-Path -LiteralPath $policyPath) {
        $policyText = [string](Get-Content -Raw -LiteralPath $policyPath -ErrorAction SilentlyContinue)
        $upnpAnswered = $policyText -match '"upnp"\s*:\s*(true|false)'
    }
    if (-not $upnpAnswered) {
        $asked = $true
        $answer = $null
        try {
            $answer = Read-Host "Open TCP/UDP $p2pPort on your router automatically (UPnP) so friends can reach this node? [y/N]"
        } catch {
            $asked = $false
        }
        if ($asked) {
            if ([string]$answer -match '^\s*(y|yes)\s*$') { $upnpMode = "on" } else { $upnpMode = "off" }
        }
    }
}

$exe = Join-Path $BinDir "raven-node.exe"
$torExe = Join-Path $BinDir "raven-tor-helper.exe"
$running = @()
# Render-only builds, stops and copies nothing: it asks the raven-node.exe already in -BinDir.
if (-not $renderOnly) {
    Push-Location $Root
    # --locked: build exactly the audited Cargo.lock. `tor` adds raven-tor-helper.exe
    # (raven-node itself never links Arti).
    if ($NoTor) {
        cargo build --locked -p raven-node -p ash --release
    } else {
        cargo build --locked -p raven-node -p ash --release --features raven-node/tor
    }
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo build failed" }
    Pop-Location

    # Windows cannot overwrite a running image. Stop the daemon only now (after the build
    # succeeded, so a failed build leaves the old daemon up): the task's own instance, then any
    # hand-started copy of THIS exe (path-filtered so other installs/users are left alone).
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
    $running = @(Get-Process -Name "raven-node" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
    foreach ($proc in $running) {
        Write-Host "stopping running raven-node (pid $($proc.Id)) so its binary can be replaced"
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $proc.Id -Timeout 15 -ErrorAction SilentlyContinue
    }
    # Its Tor helper (a child process Windows does not stop with it), likewise path-filtered.
    foreach ($proc in @(Get-Process -Name "raven-tor-helper" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $torExe })) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $proc.Id -Timeout 15 -ErrorAction SilentlyContinue
    }
}

function Install-Binary([string]$Src, [string]$Dst) {
    try {
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    } catch {
        # ash.exe / raven.exe can be held open by a running CLI session: Windows refuses to
        # overwrite a running image but allows renaming it. Move the old copy aside and retry.
        if (-not (Test-Path -LiteralPath $Dst)) { throw }
        $old = "$Dst.old"
        Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $Dst -Destination $old -Force
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    }
}

if (-not $renderOnly) {
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { "$Root\target" }
    Install-Binary "$target\release\raven-node.exe" $exe
    Install-Binary "$target\release\ash.exe" (Join-Path $BinDir "raven.exe")
    # Optional product alias - never touches system ash
    Install-Binary "$target\release\ash.exe" (Join-Path $BinDir "ash.exe")
    # The Tor helper sits next to raven-node.exe, where raven-node looks for it.
    if ($NoTor) {
        if (Test-Path -LiteralPath $torExe) {
            Remove-Item -LiteralPath $torExe -Force
            Write-Host "removed $torExe (-NoTor)"
        }
    } else {
        Install-Binary "$target\release\raven-tor-helper.exe" $torExe
    }
}

# The LAN address follows the build (hold B12): the installed raven-node.exe prints auto once
# LAN_AUTO_LISTEN_PRODUCTION_ENABLED is on, else 127.0.0.1:7420, each on the port this profile
# picked where it picked one (`lan-default --data-dir`, Phase 6b; a profile the task creates at its
# first start picks it then, and a plain auto follows it). One without `--data-dir` (an older
# build) is asked again without it; one that fails, is missing or prints anything else (an older
# build without `lan-default`) keeps 127.0.0.1:7420. -LanListen wins.
$lanDefault = "127.0.0.1:7420"
$savedPreference = $ErrorActionPreference
try {
    # Continue, not Stop: Windows PowerShell 5.1 turns a redirected stderr line of a native
    # command (an older build's usage error) into a terminating error under Stop.
    $ErrorActionPreference = "Continue"
    if (Test-Path -LiteralPath $exe -PathType Leaf) {
        $global:LASTEXITCODE = 0
        $printed = @(& $exe lan-default --data-dir $DataDir 2>$null)
        if ($LASTEXITCODE -ne 0) {
            $global:LASTEXITCODE = 0
            $printed = @(& $exe lan-default 2>$null)
        }
        if (($LASTEXITCODE -eq 0) -and ($printed.Count -eq 1) -and ([string]$printed[0] -cmatch $lanListenPattern)) {
            $lanDefault = [string]$printed[0]
        }
    }
} catch {
    $lanDefault = "127.0.0.1:7420"
} finally {
    $ErrorActionPreference = $savedPreference
}
$lanListenGiven = [bool]$LanListen
if (-not $LanListen) { $LanListen = $lanDefault }
if ($LanListen -cnotmatch $lanListenPattern) { throw $lanListenHelp }
# auto or auto:PORT, in any case (raven-node reads it so); the TCP port of the address (auto:PORT,
# IP:PORT, [IPv6]:PORT; 7420 for a bare auto and for port 0) for the lines printed below.
$lanAuto = $LanListen -match '^auto(:[0-9]+)?$'
$lanDefaultAuto = $lanDefault -match '^auto(:[0-9]+)?$'
$lanPort = "7420"
if ($LanListen -match ':([1-9][0-9]{0,4})$') { $lanPort = $Matches[1] }
# The build's auto:PORT goes into the task as a plain auto: raven-node then listens on the port this
# profile picked at every start, so `raven lan port random` moves the task too (Phase 6 review
# traffic-5). A -LanListen that names a port keeps it.
if ((-not $lanListenGiven) -and $lanAuto) { $LanListen = "auto" }
# The nearby search (LAN beacon) always uses UDP 7420 (raven-core lan_beacon BEACON_PORT), whatever
# the TCP port of auto:PORT.
$beaconUdpPort = "7420"

# What the install says about LAN (render-only prints it too).
function Write-LanLines {
    if ($lanAuto) {
        if ($lanDefaultAuto) {
            Write-Host "LAN: every network of this PC, contacts only (TCP $lanPort; nearby search on UDP $beaconUdpPort)"
            Write-Host "  Contacts on a VPN (100.64.0.0/10, e.g. Tailscale) or at a public address are refused;"
            Write-Host "  for them re-run with -LanListen 0.0.0.0:$lanPort."
        } else {
            Write-Host "LAN: this build holds auto (LAN_AUTO_LISTEN_PRODUCTION_ENABLED=false), so it listens on 0.0.0.0:$lanPort from any source (contacts only)"
        }
        Write-Host "To let contacts on your network reach it, run in an ELEVATED PowerShell yourself:"
        Write-Host "  New-NetFirewallRule -DisplayName `"Raven LAN`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort $lanPort -Profile Private"
        Write-Host "  New-NetFirewallRule -DisplayName `"Raven LAN search`" -Direction Inbound -Program `"$exe`" -Protocol UDP -LocalPort $beaconUdpPort -Profile Private"
        Write-Host "Private only, never Public; on a network you do not trust: raven lan off"
    } elseif ($LanListen -like "127.*" -or $LanListen -like "localhost:*") {
        Write-Host "LAN peers cannot reach this node (loopback only). Re-run with -LanListen <LAN-IP>:$lanPort and allow TCP $lanPort in Windows Firewall to accept LAN peers."
        if ($lanDefaultAuto) {
            Write-Host "  (re-run with -LanListen auto, which your build allows)"
        }
    }
}

# Do not use $args - automatic/read-only in pwsh 7.
$serviceArgs = "service --data-dir `"$DataDir`" --lan-listen $LanListen --ble-listen $BleListen --timeout-secs 0"
if ($InternetListen) {
    $serviceArgs = "$serviceArgs --internet-listen $InternetListen"
}
# libp2p flags: only the ones asked for (none = the task's arguments stay as before).
if ($P2pListen) {
    $serviceArgs = "$serviceArgs --p2p-listen $P2pListen"
}
foreach ($relayAddr in $p2pRelayList) {
    $serviceArgs = "$serviceArgs --p2p-relay $relayAddr"
}
if ($P2pRelay) {
    $serviceArgs = "$serviceArgs --relay"
}

if ($renderOnly) {
    Write-Host "lan-listen=$LanListen"
    Write-Host "service-args=$serviceArgs"
    Write-LanLines
    Write-Host "RAVEN_INSTALL_RENDER_ONLY=1: nothing was built, copied, stopped or registered"
    exit 0
}

$ravenExe = Join-Path $BinDir "raven.exe"
# The same p2p settings go into node_policy.json too, so `raven whoami --card` and
# `raven status` agree with the task even while it is not running (its arguments above still
# decide while it runs). Input comes from a pipe: it never asks.
if ($P2pListen) {
    if ($p2pListenOn) {
        $p2pSaveArgs = @("node", "p2p", "on", "--listen", $P2pListen)
        foreach ($relayAddr in $p2pRelayList) { $p2pSaveArgs += @("--relay", $relayAddr) }
    } else {
        $p2pSaveArgs = @("node", "p2p", "off")
    }
    $null | & $ravenExe --data-dir $DataDir @p2pSaveArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARN: could not save the p2p settings in node_policy.json (the task still uses its arguments); run '$ravenExe --data-dir `"$DataDir`" $($p2pSaveArgs -join ' ')'"
    }
}

# Saved in node_policy.json before the task (re)starts below, which applies it.
$upnpSaved = ""
if ($upnpMode) {
    & $ravenExe --data-dir $DataDir node upnp $upnpMode
    if ($LASTEXITCODE -eq 0) {
        $upnpSaved = $upnpMode
    } else {
        Write-Host "WARN: could not save the UPnP choice; run '$ravenExe --data-dir `"$DataDir`" node upnp $upnpMode' and restart the task"
    }
}

if ($SkipScheduledTask) {
    Write-Host "SkipScheduledTask: binaries copied; logon task not registered"
    if ($running.Count -gt 0) {
        Write-Host "NOTE: the raven-node that was running was stopped and NOT restarted (-SkipScheduledTask)."
    }
} else {
    # Register a per-user logon task (survives reboot; no admin service required for V1 software path).
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $exe -Argument $serviceArgs
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # ExecutionTimeLimit 0 (PT0S) = no limit: the default is 72h, after which Task Scheduler
    # force-stops the always-on daemon and nothing relaunches it until the next logon.
    # Restart-on-failure covers crashes; IgnoreNew keeps a single daemon per task.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "RAVEN raven-node bridge (serverless)" | Out-Null
    # `raven lock` may have disabled the task ("keep Raven stopped"). Installing is an explicit
    # start: the task is enabled again whatever state it was left in.
    Enable-ScheduledTask -TaskName $TaskName | Out-Null
    if ($NoStart) {
        Write-Host "NoStart: task registered, not started"
    } else {
        Start-ScheduledTask -TaskName $TaskName
    }
    Write-Host "installed task $TaskName"
}

Write-Host "data-dir=$DataDir"
Write-Host "CLI: raven.exe / ash.exe find this profile by default (RAVEN_DATA_DIR, else ~\.raven); for any other -DataDir pass --data-dir `"$DataDir`" to every command"
Write-Host "lan-listen=$LanListen"
Write-LanLines
if ($InternetListen) {
    $inetPort = "7422"
    # "[v6]:port" or "v4:port"; a bare IP (IPv6 included) means the default port.
    if (($InternetListen -match '^\[[^\]]*\]:(\d+)$') -or ($InternetListen -match '^[^:\[\]]+:(\d+)$')) {
        $inetPort = $Matches[1]
    }
    Write-Host "internet-listen=$InternetListen (only your contacts get an answer; anyone can see that the port is open)"
    Write-Host "To let contacts reach it, run in an ELEVATED PowerShell yourself (Private profile only, never Public):"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven node`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort $inetPort -Profile Private"
    Write-Host "and forward TCP $inetPort on your router if this PC is behind NAT. Outbound needs no rule."
    Write-Host "Check: raven.exe status (internet row)."
} else {
    Write-Host "internet-listen=off (opt-in: re-run with -InternetListen 0.0.0.0:7422, or run 'raven node internet on' and restart the task)"
}
if ($p2pListenOn) {
    Write-Host "p2p-listen=$P2pListen (libp2p TCP+UDP $p2pPort; only your contacts get a Raven link; anyone can see that the port is open)"
    Write-Host "To let contacts reach it, run in an ELEVATED PowerShell yourself (Private profile only, never Public):"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven node p2p`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort $p2pPort -Profile Private"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven node p2p`" -Direction Inbound -Program `"$exe`" -Protocol UDP -LocalPort $p2pPort -Profile Private"
    Write-Host "and forward TCP+UDP $p2pPort on your router if this PC is behind NAT (or -Upnp 1); without that a relay (-P2pRelays) still lets contacts reach you. Outbound needs no rule."
    Write-Host "Check: raven.exe status (p2p row)."
} elseif ($P2pListen) {
    Write-Host "p2p-listen=off (-P2pListen $P2pListen overrides 'raven node p2p on')"
} else {
    Write-Host "p2p-listen=off (opt-in: re-run with -P2pListen 7423, or run 'raven node p2p on' and restart the task)"
}
if ($p2pRelayList.Count -gt 0) {
    Write-Host "p2p-relays=$($p2pRelayList -join ',') (a reservation is kept on each; a relay sees both PeerIds and IPs of every circuit, never your messages)"
}
if ($P2pRelay) {
    Write-Host "relay=on for your verified contacts (and the PeerIds in $(Join-Path $DataDir 'relay_allow.json')), with this profile's own"
    Write-Host "  relay key (never your PeerId) on TCP and UDP 7427; 'raven relay offer off' stops it, 'raven relay status' shows it."
    Write-Host "  A saved 'raven relay offer off' wins over -P2pRelay ('raven relay offer on' to relay again); 'raven node hide-ip on' stops it too."
    Write-Host "To let contacts reach it, run in an ELEVATED PowerShell yourself (Private profile only, never Public):"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven friend relay`" -Direction Inbound -Program `"$exe`" -Protocol TCP -LocalPort 7427 -Profile Private"
    Write-Host "  New-NetFirewallRule -DisplayName `"Raven friend relay`" -Direction Inbound -Program `"$exe`" -Protocol UDP -LocalPort 7427 -Profile Private"
    Write-Host "and forward TCP+UDP 7427 on your router if this PC is behind NAT."
    Write-Host "  The logon task runs only while you are logged in, so this PC is a poor always-on relay."
}
if (($p2pRelayList.Count -gt 0) -and -not $p2pListenOn) {
    Write-Host "NOTE: -P2pRelays take effect only while p2p listen is on (-P2pListen 7423 or 'raven node p2p on')."
}
if ($P2pRelay -and -not $p2pListenOn) {
    Write-Host "NOTE: contacts are offered your relay once this PC is confirmed reachable (p2p listen on: -P2pListen 7423)"
    Write-Host "  or once you name its address: raven relay offer on --external /ip4/<public IP>/tcp/7427"
}
if ($upnpSaved -eq "on") {
    $upnpPortText = if ($p2pPort) { $p2pPort } else { "of the p2p port, when one is open" }
    Write-Host "upnp=on (raven-node asks the router to map TCP/UDP $upnpPortText; it logs only the mapped port and success or failure)"
} elseif ($upnpSaved -eq "off") {
    Write-Host "upnp=off ('raven node upnp on' changes it; applied when the task restarts)"
}
if ($NoTor) {
    Write-Host "tor=not installed (-NoTor); raven.exe status says `"Tor: not built in this raven`"."
} else {
    Write-Host "tor=$torExe, next to raven-node.exe. raven-node starts it and keeps an onion service, so friends"
    Write-Host "  can reach this PC from any network without a port forward; Tor relays are the only third party it talks to."
    Write-Host "  The first start can take a few minutes. Check: raven.exe status (Tor row)."
}
Write-Host "bluetooth-nearby=not in release builds on Windows (macOS only so far)"
Write-Host "bin-dir=$BinDir (raven.exe / ash.exe)"
$userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Host "Named-pipe IPC: \\.\pipe\raven-node-$userSid (per-user pipe, current-user DACL; ash refuses a pipe served by another user) - see WINDOWS_SERVICE.md"
