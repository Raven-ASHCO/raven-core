<#
.SYNOPSIS
Owner-run real rows R8w, R8p and R8m on Windows (Phase 4,
protocol/RAVEN_WSS_TRANSPORT_V1.md, RWS1): Raven on a laptop whose network
lets little out. The Windows twin of node/scripts/r8_only_443.sh.

.DESCRIPTION
For the length of the row, Windows Firewall blocks every outbound connection
(DefaultOutboundAction Block on every profile) except the row's own:
  R8w  TCP 443 and DNS (UDP/TCP 53); the relay runs on a VPS with
       `raven-node relay --wss 443` and this laptop names it by its `/tls/ws`
       address.
  R8p  only TCP to the HTTPS proxy (-Proxy HOST:PORT), DNS blocked too. The
       proxy is set in Settings > Network & internet > Proxy (manual setup):
       raven-node must find it itself, so RAVEN_P2P_PROXY is cleared here.
       This proves system detection.
  R8m  (optional) R8w (or, with -Proxy, R8p) through a TLS-intercepting
       proxy, the relay on a real domain certificate.
The rules carry the group "raven_r8". A finally block always puts every
profile's DefaultOutboundAction back as it was and removes the group's rules.
Run it on the laptop itself, never over Remote Desktop (refused).

Before the row a preflight must show the filter working: TCP 443 to the
relay host open (R8p: the proxy open and the relay host's 443 closed) and TCP
7423 to it closed.

The row: raven-node of the test profile (-DataDir, never %USERPROFILE%\.raven;
its relay set to the relay's `/tls/ws` address and the other machine pinned
with a relay-only card) is restarted under the filter with the lab switches
RAVEN_LAB_TEST_A=1 RAVEN_LAB_WSS=1 (R8p: RAVEN_LAB_WSS_PROXY=1 too); -Count
messages go to -Tag with `--carrier p2p` (verbose: each path= label is kept);
then the script waits up to -WaitSeconds for -Count messages from the other
machine, which runs `wan_two_network_test.sh three send <its tag for this
laptop> <count>` meanwhile. It writes
node\proof_artifacts\R8<w|p|m>-windows-<UTC date>.txt: counts, path labels,
the relay transport (`raven status`) and receipt times only, no address,
name, key or message text.

Pass bar: Count/Count delivered each way, every message to -Tag `relayed`,
each message from it exactly once, the relay transport WSS (R8w) or WSS
through the HTTPS proxy (R8p).

.EXAMPLE
powershell -ExecutionPolicy Bypass -File node\scripts\r8_only_443.ps1 -IUnderstand -Mode w -RelayHost relay.example.org -Tag bob -DataDir C:\raven-wan-test\laptop
#>
[CmdletBinding()]
param(
    [switch]$IUnderstand,
    [ValidateSet('w', 'p', 'm')][string]$Mode = '',
    [string]$RelayHost = '',
    [string]$Tag = '',
    [string]$DataDir = '',
    [string]$Proxy = '',
    [ValidateRange(1, 99)][int]$Count = 10,
    [int]$WaitSeconds = 900,
    [string]$Bin = '',
    [string]$NodeArgs = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
if (-not $Bin) {
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Root 'target' }
    $Bin = Join-Path $target 'debug'
}
$Ash = Join-Path $Bin 'ash.exe'
$Node = Join-Path $Bin 'raven-node.exe'
$Group = 'raven_r8'

function Fail([string]$Text, [int]$Code = 2) {
    Write-Host "r8_only_443: $Text"
    exit $Code
}

if (-not $Mode) { Fail 'give -Mode w, p or m' }
if (-not $RelayHost) { Fail "give -RelayHost (the relay's IP or DNS name)" }
if (-not $Tag) { Fail 'give -Tag (the other machine, pinned with a relay-only card)' }
$Filter = if ($Mode -eq 'p' -or ($Mode -eq 'm' -and $Proxy)) { 'p' } else { 'w' }
if ($Filter -eq 'p' -and -not $Proxy) { Fail '-Mode p needs -Proxy HOST:PORT (the proxy the system names)' }
if (-not $DataDir) { Fail 'give -DataDir (the test profile; never your real one)' }
$DataDir = (Resolve-Path $DataDir).Path
$real = Join-Path $env:USERPROFILE '.raven'
if ($DataDir.TrimEnd('\').StartsWith($real, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "refusing the real profile $DataDir"
}
if (-not (Test-Path (Join-Path $DataDir 'contacts.json'))) { Fail "$DataDir holds no profile" }
if (-not (Test-Path $Ash) -or -not (Test-Path $Node)) { Fail "no debug ash.exe/raven-node.exe in $Bin (build them, or give -Bin)" }
if ($env:SESSIONNAME -like 'RDP-*') { Fail 'refusing to block outbound traffic over Remote Desktop' }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail 'needs an elevated PowerShell (Run as administrator)' }
if (-not $IUnderstand) {
    Fail ("this blocks almost all outbound traffic of THIS computer for the length of the row " +
        "(filter ${Filter}), then puts Windows Firewall back. Add -IUnderstand to go on.")
}
if (Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue) {
    Fail "rules of the group $Group exist (an earlier run not restored?): Remove-NetFirewallRule -Group $Group"
}

function Resolve-First([string]$HostName) {
    $ip = $null
    if ([Net.IPAddress]::TryParse($HostName, [ref]$ip)) { return $ip.ToString() }
    return ([Net.Dns]::GetHostAddresses($HostName) | Select-Object -First 1).ToString()
}
function Test-Tcp([string]$HostName, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        return ($task.Wait(5000) -and $client.Connected)
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

$proxyIp = ''
$proxyPort = 0
if ($Proxy) {
    $proxyPort = [int]($Proxy.Split(':')[-1])
    $proxyIp = Resolve-First ($Proxy.Substring(0, $Proxy.LastIndexOf(':')))
}
# Resolved before the filter: DNS may be blocked afterwards.
$relayIp = Resolve-First $RelayHost

$saved = Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction
$result = 'FAIL'
$artifactLines = @()
try {
    # ---- the filter ---------------------------------------------------------
    if ($Filter -eq 'w') {
        New-NetFirewallRule -DisplayName 'raven_r8 TCP 443' -Group $Group -Direction Outbound `
            -Protocol TCP -RemotePort 443 -Action Allow | Out-Null
        New-NetFirewallRule -DisplayName 'raven_r8 DNS UDP' -Group $Group -Direction Outbound `
            -Protocol UDP -RemotePort 53 -Action Allow | Out-Null
        New-NetFirewallRule -DisplayName 'raven_r8 DNS TCP' -Group $Group -Direction Outbound `
            -Protocol TCP -RemotePort 53 -Action Allow | Out-Null
    } else {
        New-NetFirewallRule -DisplayName 'raven_r8 proxy' -Group $Group -Direction Outbound `
            -Protocol TCP -RemoteAddress $proxyIp -RemotePort $proxyPort -Action Allow | Out-Null
    }
    Set-NetFirewallProfile -All -DefaultOutboundAction Block
    Write-Host "r8_only_443: filter $Filter applied (Windows Firewall, group $Group)"

    # ---- preflight ----------------------------------------------------------
    if ($Filter -eq 'w') {
        if (-not (Test-Tcp $relayIp 443)) { Fail "preflight: the relay host's TCP 443 does not open under the filter" 1 }
        $preflight = '443 open, 7423 blocked'
    } else {
        if (-not (Test-Tcp $proxyIp $proxyPort)) { Fail 'preflight: the proxy does not open under the filter' 1 }
        if (Test-Tcp $relayIp 443) { Fail "preflight: the relay host's TCP 443 opens directly: the filter does not hold" 1 }
        $preflight = 'proxy open, direct 443 blocked, 7423 blocked'
    }
    if (Test-Tcp $relayIp 7423) { Fail 'preflight: TCP 7423 to the relay host opens: the filter does not hold' 1 }
    Write-Host "r8_only_443: preflight: $preflight"

    # ---- raven-node restarted under the filter --------------------------------
    $env:RAVEN_LAB_TEST_A = '1'
    $env:RAVEN_LAB_WSS = '1'
    if ($Filter -eq 'p') { $env:RAVEN_LAB_WSS_PROXY = '1' }
    foreach ($k in 'RAVEN_P2P_PROXY', 'HTTPS_PROXY', 'ALL_PROXY') { Remove-Item "Env:$k" -ErrorAction SilentlyContinue }
    foreach ($k in 'RAVEN_IDENTITY_BACKEND', 'RAVEN_SESSION_BACKEND', 'RAVEN_PREKEY_BACKEND') { Set-Item "Env:$k" 'locked-file' }
    $env:RAVEN_ALLOW_EPHEMERAL_DATA_DIR = '1'
    $env:NO_COLOR = '1'
    $pidFile = Join-Path $DataDir 'node.pid'
    if (Test-Path $pidFile) {
        Stop-Process -Id ([int](Get-Content $pidFile)) -ErrorAction SilentlyContinue
    }
    if (-not $NodeArgs -and (Test-Path (Join-Path $DataDir 'service.flags'))) {
        $NodeArgs = (Get-Content (Join-Path $DataDir 'service.flags') -Raw).Trim()
    }
    $log = Join-Path $DataDir 'node.log'
    $err = Join-Path $DataDir 'node.err.log'
    $nodeArgv = @('service', '--data-dir', $DataDir, '--lan-listen', '127.0.0.1:0', '--ble-listen', '127.0.0.1:0') +
        @($NodeArgs -split '\s+' | Where-Object { $_ })
    $proc = Start-Process -FilePath $Node -ArgumentList $nodeArgv -RedirectStandardOutput $log `
        -RedirectStandardError $err -WindowStyle Hidden -PassThru
    Set-Content -Path $pidFile -Value $proc.Id
    $deadline = (Get-Date).AddSeconds(180)
    while (-not (Select-String -Path $err -SimpleMatch 'raven-node p2p: reservation accepted' -Quiet -ErrorAction SilentlyContinue)) {
        if ($proc.HasExited -or (Get-Date) -gt $deadline) { Fail 'raven-node holds no reservation on the relay within 180 s' 1 }
        Start-Sleep -Seconds 1
    }
    $status = (& $Ash --data-dir $DataDir status 2>&1 | Out-String)
    $row = ($status -split "`n" | Where-Object { $_ -match '^\s*p2p\s' } | Select-Object -First 1)
    $transport = if ($row -match 'relay over WSS through the HTTPS proxy') { 'wss-proxy' }
        elseif ($row -match 'relay over WSS') { 'wss' } else { 'tcp-or-quic' }

    # ---- A -> B ---------------------------------------------------------------
    $pattern = 'three-[A-Za-z0-9_.-]+-[0-9]+-[0-9]{6}'
    $before = @([regex]::Matches((& $Ash --data-dir $DataDir inbox 2>$null | Out-String), $pattern) |
        ForEach-Object { $_.Value } | Sort-Object -Unique)
    $t0 = Get-Date
    $paths = @{}
    $delivered = 0
    $secs = @()
    $name = Split-Path -Leaf $DataDir
    for ($i = 1; $i -le $Count; $i++) {
        $text = "three-$name-$Tag-$i-$((Get-Date).ToUniversalTime().ToString('HHmmss'))"
        $start = Get-Date
        $env:RAVEN_VERBOSE = '1'
        $out = ($text | & $Ash --data-dir $DataDir send --contact "@$Tag" --carrier p2p 2>&1 | Out-String)
        Remove-Item Env:RAVEN_VERBOSE
        $took = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        if ($out -match 'status delivered' -and $out -match 'confirmed receipt') {
            $delivered++
            $secs += $took
            $path = if ($out -match ' path=([a-z_]+)') { $Matches[1] } else { 'none' }
            $paths[$path] = 1 + [int]$paths[$path]
        }
        Write-Host "  $i/$Count  $(if ($out -match 'status delivered') { 'delivered' } else { 'not delivered' })"
    }

    # ---- B -> A ---------------------------------------------------------------
    Write-Host "r8_only_443: now run on the other machine: wan_two_network_test.sh three send <its tag for this laptop> $Count (waiting up to $WaitSeconds s)"
    $received = 0
    $dupes = 0
    $lastAfter = '-'
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        $all = @([regex]::Matches((& $Ash --data-dir $DataDir inbox 2>$null | Out-String), $pattern) |
            ForEach-Object { $_.Value })
        $new = @($all | Where-Object { $before -notcontains $_ })
        $received = @($new | Sort-Object -Unique).Count
        $dupes = $new.Count - $received
        if ($received -ge $Count) {
            $lastAfter = [math]::Round(((Get-Date) - $t0).TotalSeconds)
            break
        }
        Start-Sleep -Seconds 5
    }

    # ---- the artifact: counts only -----------------------------------------------
    $want = if ($Filter -eq 'w') { 'wss' } else { 'wss-proxy' }
    $pathText = (($paths.Keys | Sort-Object | ForEach-Object { "$_=$($paths[$_])" }) -join ',')
    if (-not $pathText) { $pathText = 'none' }
    $sorted = @($secs | Sort-Object)
    $median = if ($sorted.Count) { $sorted[[int][math]::Floor($sorted.Count / 2)] } else { '-' }
    $max = if ($sorted.Count) { $sorted[-1] } else { '-' }
    if ($delivered -eq $Count -and $pathText -eq "relayed=$Count" -and $received -ge $Count -and
        $dupes -eq 0 -and $transport -eq $want) {
        $result = 'PASS'
    }
    $artifactLines = @(
        "row R8$Mode",
        'os windows',
        "utc $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
        "filter $(if ($Filter -eq 'w') { 'only TCP 443 and DNS out' } else { 'only the HTTPS proxy out (DNS blocked)' })",
        "preflight $preflight",
        "relay_transport $transport (pass bar: $want)",
        "a_to_b sent $Count delivered $delivered paths $pathText median_s $median max_s $max",
        "b_to_a received $received of $Count duplicates $dupes last_after_s $lastAfter",
        "result $result"
    )
} finally {
    foreach ($p in $saved) {
        Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.DefaultOutboundAction
    }
    Remove-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue
    Write-Host 'r8_only_443: Windows Firewall restored'
}

$dir = Join-Path $Root 'proof_artifacts'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$artifact = Join-Path $dir "R8$Mode-windows-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd')).txt"
Set-Content -Path $artifact -Value $artifactLines
$artifactLines | ForEach-Object { Write-Host $_ }
Write-Host "r8_only_443: wrote $artifact (counts only)"
if ($result -ne 'PASS') { exit 1 }
