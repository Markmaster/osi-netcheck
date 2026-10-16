<#
osi.ps1 - step-by-step network check for Windows: is it my DNS (Control D) or the internet?
Same logic as osi.awk (Blink Shell and macOS). Windows PowerShell 5.1 and PowerShell 7.

Run:
  powershell -ExecutionPolicy Bypass -File "$HOME\osi.ps1"
  powershell -ExecutionPolicy Bypass -File "$HOME\osi.ps1" -Gateway ROUTER_IP

The gateway is found automatically (Get-NetRoute). The script changes nothing on the system:
only ping, TCP connects, DNS queries and one HTTPS request.
#>
param(
    [string]$Gateway = '',
    [switch]$NoRun   # for tests: load the functions only, do not run the check
)

$script:VerifyIp = '147.185.34.1'
$script:Ipv4 = '^\d{1,3}(\.\d{1,3}){3}$'

# ---------- Probes: all network access happens here ----------

function Test-Ping([string]$Ip) {
    # A reply means "TTL=" in the ping.exe output (the same in localized Windows).
    $out = & ping.exe -n 2 -w 2000 $Ip 2>&1 | Out-String
    return @{ Ok = ($out -match 'TTL=') }
}

function Test-Tcp([string]$Ip, [int]$Port, [int]$TimeoutMs = 3000) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.ConnectAsync($Ip, $Port)
        if ($t.Wait($TimeoutMs)) { return $c.Connected }
        return $false
    } catch {
        return $false
    } finally {
        $c.Close()
    }
}

function Test-Https([string]$Url) {
    # $null = curl.exe not found (happens on old Windows 10 builds).
    # --ssl-no-revoke: without it Schannel checks certificate revocation through the system DNS,
    # and with broken DNS HTTPS fails falsely (looks like a captive portal).
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) { return $null }
    & $curl.Source -sS -m 5 --ssl-no-revoke -o NUL $Url 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Resolve-A([string]$Name, [string]$Server = '') {
    # IPv4 addresses from the answer. Without -Server: the Windows DNS client (with NRPT, like apps).
    try {
        $p = @{ Name = $Name; Type = 'A'; ErrorAction = 'Stop'; QuickTimeout = $true }
        if ($Server) { $p.Server = $Server; $p.DnsOnly = $true }
        $r = Resolve-DnsName @p
        return @($r | Where-Object { $_.IPAddress -match $script:Ipv4 } | ForEach-Object { $_.IPAddress })
    } catch {
        return @()
    }
}

function Get-DefaultRoute {
    try {
        return Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
    } catch {
        return $null
    }
}

function Get-DefaultGateway {
    $r = Get-DefaultRoute
    if ($r -and $r.NextHop -match $script:Ipv4 -and $r.NextHop -ne '0.0.0.0') { return $r.NextHop }
    return ''
}

function Get-NetworkDns {
    # First DNS server of the adapter that holds the default route.
    $r = Get-DefaultRoute
    if (-not $r) { return '' }
    try {
        $s = (Get-DnsClientServerAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses |
            Select-Object -First 1
        if ($s) { return [string]$s }
    } catch {}
    return ''
}

# ---------- Output ----------

function Say([string]$Status, [string]$Step, [string]$Text) {
    $color = 'Gray'
    if ($Status -eq 'OK') { $color = 'Green' } elseif ($Status -eq 'FAIL') { $color = 'Red' }
    Write-Host ('[{0,4}] {1} {2}' -f $Status, $Step, $Text) -ForegroundColor $color
}

function Note([string]$Text) { Write-Host ('  * ' + $Text) }

function Pick([bool]$Cond, [string]$A, [string]$B) { if ($Cond) { return $A } return $B }

# ---------- Check ----------

function Invoke-Osi([string]$Gateway = '') {
    Write-Host '== OSI check: Control D or the internet =='

    # 1 Gateway
    if (-not $Gateway) { $Gateway = Get-DefaultGateway }
    $gwOk = -1
    if (-not $Gateway) {
        Say '--' '1 ' 'Gateway: not found. Pass it manually: -Gateway IP'
    } elseif ($Gateway -notmatch $script:Ipv4) {
        Say '??' '1 ' "Gateway: `"$Gateway`" is not an IPv4 address, skipped"
    } else {
        $gwOk = [int](Test-Ping $Gateway).Ok
        Say (Pick ($gwOk -eq 1) 'OK' 'FAIL') '1 ' ("Gateway $Gateway" + (Pick ($gwOk -eq 1) ': replies' ': no reply'))
    }

    # 2 Ping by IP, no DNS involved
    $p1 = Test-Ping '1.1.1.1'
    $p2 = Test-Ping '8.8.8.8'
    $pingOk = ($p1.Ok -or $p2.Ok)
    if ($pingOk) { Say 'OK' '2 ' 'Ping 1.1.1.1 / 8.8.8.8' }
    else { Say 'FAIL' '2 ' 'Ping 1.1.1.1 / 8.8.8.8: no reply' }

    # 3 TCP 443 by IP
    $tcpOk = [bool](Test-Tcp '1.1.1.1' 443)
    Say (Pick $tcpOk 'OK' 'FAIL') '3 ' 'TCP 443 to 1.1.1.1'

    # 3b HTTPS by IP
    $h = Test-Https 'https://1.1.1.1'
    if ($null -eq $h) {
        Say '??' '3b' 'HTTPS to 1.1.1.1: no curl.exe, using the TCP 443 result'
        $httpsOk = $tcpOk
    } else {
        $httpsOk = [bool]$h
        Say (Pick $httpsOk 'OK' 'FAIL') '3b' 'HTTPS to 1.1.1.1'
    }

    # 4 DNS bypassing Control D
    $dnsExt = (@(Resolve-A 'example.com' '1.1.1.1').Count -gt 0)
    Say (Pick $dnsExt 'OK' 'FAIL') '4 ' 'DNS via 1.1.1.1 (UDP 53, bypassing Control D)'

    # 5 Control D directly over UDP 53
    # Only Control D answers verify.controld.com with 147.185.34.1: any other answer = the network intercepts DNS.
    $cdIps = @(Resolve-A 'verify.controld.com' '76.76.2.0')
    $cdDns = ($cdIps -contains $script:VerifyIp)
    $hijack = $false
    if ($cdDns) {
        Say 'OK' '5 ' 'Control D directly 76.76.2.0 (UDP 53)'
    } elseif ($cdIps.Count -gt 0 -or @(Resolve-A 'example.com' '76.76.2.0').Count -gt 0) {
        $hijack = $true
        Say '??' '5 ' 'Control D directly 76.76.2.0: answered, but not by Control D (network intercepts DNS)'
    } else {
        Say 'FAIL' '5 ' 'Control D directly 76.76.2.0 (UDP 53)'
    }

    # 5b Control D DoH endpoint over TCP 443
    $cdDoh = [bool](Test-Tcp '76.76.2.22' 443)
    Say (Pick $cdDoh 'OK' 'FAIL') '5b' 'Control D DoH 76.76.2.22 (TCP 443)'

    # 6 System DNS (the Windows DNS client, like apps use)
    $sysIps = @(Resolve-A 'example.com')
    $sysDns = ($sysIps.Count -gt 0)
    Say (Pick $sysDns 'OK' 'FAIL') '6 ' ('System DNS: example.com' + (Pick $sysDns (' -> ' + $sysIps[0]) ' does not resolve'))

    # 6b Adapter DNS directly
    $nd = Get-NetworkDns
    $netDns = $true
    if (-not $nd) {
        Say '??' '6b' 'Adapter DNS: not found'
    } else {
        $netDns = (@(Resolve-A 'example.com' $nd).Count -gt 0)
        Say (Pick $netDns 'OK' 'FAIL') '6b' "Adapter DNS $nd directly"
    }

    # 7 Verify via the system DNS
    $vIps = @(Resolve-A 'verify.controld.com')
    $verifySys = 0
    if ($vIps -contains $script:VerifyIp) {
        $verifySys = 1
        Say 'OK' '7 ' "Verify (system): $($script:VerifyIp) = Control D"
    } elseif ($vIps.Count -gt 0) {
        Say 'FAIL' '7 ' "Verify (system): $($vIps[0]), not Control D"
    } else {
        Say 'FAIL' '7 ' 'Verify (system): does not resolve'
    }

    # 7b Verify via the adapter DNS
    if ($nd) {
        $vn = @(Resolve-A 'verify.controld.com' $nd)
        if ($vn -contains $script:VerifyIp) { Say 'OK' '7b' 'Verify (adapter): Control D' }
        # Resolvers other than Control D return an empty answer for this name: that is "not Control D".
        # Dead DNS = 6b got no answer either.
        elseif ($vn.Count -eq 0 -and -not $netDns) { Say 'FAIL' '7b' 'Verify (adapter): adapter DNS did not answer' }
        else { Say '--' '7b' 'Verify (adapter): not Control D (normal unless your router uses Control D)' }
    }

    # ---------- Verdict ----------
    $inet = ($pingOk -or $tcpOk -or $httpsOk -or $cdDoh -or $cdDns -or $dnsExt)
    $web = $false
    Write-Host ''
    Write-Host '== VERDICT =='
    if (-not $inet) {
        Write-Host 'NO INTERNET: nothing outside answers (no ping, no TCP 443, no DNS).'
        Write-Host 'Control D is not the cause.'
        if ($gwOk -eq 0) { Write-Host 'The router does not reply: Wi-Fi, cable or router problem.' }
        elseif ($gwOk -eq 1) { Write-Host 'The router replies, nothing beyond it: ISP or router settings.' }
        else { Write-Host 'Check Wi-Fi, cable or router, or switch to another network.' }
    } elseif (-not $tcpOk -and -not $httpsOk -and -not $cdDoh) {
        Write-Host 'Something outside answers, but TCP 443 is blocked everywhere: the network blocks HTTPS (firewall).'
        Write-Host 'Control D is not the cause.'
    } elseif ($tcpOk -and -not $httpsOk) {
        Write-Host 'TCP 443 connects but HTTPS fails: looks like a Wi-Fi login page'
        Write-Host '(captive portal) or TLS interception. Open a browser.'
    } elseif (-not $sysDns) {
        $web = $true
        if ($cdDoh) {
            Write-Host 'Internet works, Control D is reachable on 443, but the system DNS does not work.'
            Write-Host 'Your setup is the cause: ctrld, adapter DNS settings or the router.'
            Write-Host 'Check: stop ctrld (or set the adapter DNS back to automatic) and run again.'
        } elseif ($cdDns -or $dnsExt) {
            Write-Host 'Internet works, but TCP 443 to Control D (DoH) is blocked:'
            Write-Host 'the network blocks Control D. Use another network or plain DNS.'
            if ($cdDns) { Write-Host 'If Control D runs on your router (UDP 53), check the router too.' }
        } elseif ($nd -and $netDns -and $nd -notmatch '^127\.') {
            Write-Host 'Internet works, but the network blocks Control D and all outside DNS:'
            Write-Host 'only its own DNS answers (6b). ctrld cannot work here:'
            Write-Host 'stop ctrld (or set the adapter DNS back to automatic) on this network, or use another network.'
        } else {
            Write-Host 'The network blocks both outside DNS and Control D. System DNS does not work.'
            Write-Host 'Control D is not the cause: try another network.'
        }
    } elseif ($verifySys -eq 0) {
        $web = $true
        Write-Host 'Internet and DNS work, but the system DNS most likely does NOT go through Control D.'
        Write-Host 'Usual causes: VPN, manual adapter DNS, ctrld not running or disabled.'
    } else {
        $web = $true
        Write-Host 'ALL OK: internet works, DNS goes through Control D.'
    }

    if ($web -and -not $tcpOk -and -not $httpsOk) { Note '1.1.1.1 is blocked on this network, but the internet works (Control D answers on 443).' }
    if ($web -and -not $pingOk) { Note 'This network blocks ping, but the internet works. Not a fault.' }
    if ($web -and $gwOk -eq 0) { Note 'The router did not answer ping, but the internet works: the router just ignores ping.' }
    if ($web -and -not $dnsExt -and $sysDns) { Note 'This network blocks outside DNS (UDP 53), but the system DNS works.' }
    if ($web -and $hijack) { Note 'This network intercepts plain DNS (5): Control D on a router cannot work from here (DoH is checked separately in 5b).' }
    if ($web -and -not $cdDns -and -not $hijack -and $cdDoh -and $sysDns) { Note 'Control D is unreachable on UDP 53 but reachable on 443: normal for DoH.' }
    if ($web -and $nd -and -not $netDns -and $sysDns) { Note "The adapter DNS ($nd) does not answer, but the system DNS works." }
    Write-Host 'Final check in a browser: https://controld.com/status'
    if ($web -and $sysDns -and $verifySys -eq 1) { Note 'If this says OK but the status page says "Not using": the browser may use its own Secure DNS (DoH) or another path (VPN, proxy extension). Check its Secure DNS setting first.' }
}

if (-not $NoRun) { Invoke-Osi -Gateway $Gateway }
