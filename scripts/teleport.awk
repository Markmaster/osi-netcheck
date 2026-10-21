# teleport.awk - UniFi Teleport on a UniFi Travel Router (UTR): is it the uplink or the router?
# Client side, layer by layer, from a device behind the UTR. Runs in the Blink Shell local
# shell (iPhone/iPad) and in macOS Terminal. Read-only: ping, TCP connects, small UDP probes,
# DNS queries, HTTPS requests. Prints one Markdown table per run and saves it to a log file.
#
# Blink:  awk -v home=HOME_WAN_IP -v label=office-wifi -f ~/iCloud/scripts/teleport.awk   (snip tp/run)
# macOS:  awk -v home=HOME_WAN_IP -v label=office-wifi -f ~/tp/teleport.awk
# Watch:  awk -v watch=15 -v label=office-wifi -f ...   (logs link and uplink changes for 15 minutes;
#         the snip tp/watch passes -v mode=watch -v minutes=N, 10 minutes if left empty)
#
# Variables (-v name=value), all optional:
#   home     home WAN IP (the CGM public IP): target of the L4 probes and the egress check
#   label    name of this run, e.g. office-wifi or lte-hotspot; goes into the log file name
#   tp       Teleport toggle in the UTR during this run, on or off (recorded only)
#   tport    Teleport WireGuard port on the CGM (teleport-cgm.sh info); gets the WireGuard-shaped probe
#   homelan  an address on the home LAN that answers TCP 443, e.g. the CGM LAN IP; reachable = tunnel up
#   ports    UDP ports to probe at home, default "51820 443 3478"
#   gw       UTR LAN gateway and DNS, default 10.10.10.1
#   hosts    TLS and DNS targets, default below. The UTR's Teleport client talks to cloudaccess.svc.ubnt.com
#            (firmware strings, 6.6.115-6.6.122); the ui.com hosts are context.
#   dir      folder with stun-req.bin and wg-probe.bin (Blink: ~/iCloud/scripts, macOS: ~/tp)
#
# Blink's local shell has no sh, so the logic is awk, as in osi.awk. Each probe runs through
# system() with its output in a temp file, which awk then parses.

BEGIN {
    VERIFY_IP = "147.185.34.1"
    home = val(home); tport = val(tport); homelan = val(homelan); label = val(label)
    tp = val(tp); ports = val(ports); hosts = val(hosts); gw = val(gw); dir = val(dir); watch = val(watch)
    mode = val(mode); minutes = val(minutes)
    if (watch == "" && mode == "watch") watch = (minutes ~ /^[0-9]+$/) ? minutes : 10
    if (watch != "" && watch !~ /^[0-9]+$/) { print "watch=\"" watch "\" is not a number of minutes"; exit 2 }
    if (gw == "") gw = "10.10.10.1"
    if (ports == "") ports = "51820 443 3478"
    if (hosts == "") hosts = "cloudaccess.svc.ubnt.com unifi.ui.com sso.ui.com api.ui.com account.ui.com"
    if (label == "") label = "run"
    gsub(/[^A-Za-z0-9._-]/, "-", label)
    if (tp == "") tp = "not recorded"
    if (home != "" && !is_ip(home)) { print "home=\"" home "\" is not an IPv4 address"; exit 2 }
    if (homelan != "" && !is_ip(homelan)) { print "homelan=\"" homelan "\" is not an IPv4 address"; exit 2 }
    if (tport != "" && tport !~ /^[0-9]+$/) { print "tport=\"" tport "\" is not a port number"; exit 2 }
    LANP = gw; sub(/[0-9]+$/, "", LANP)

    if (!preflight()) {
        print "STOP: cannot save command output to a temp file ($HOME, $TMPDIR, current folder)."
        exit 1
    }
    PLAT = platform()
    if (dir == "") dir = ENVIRON["HOME"] (PLAT == "blink" ? "/iCloud/scripts" : "/tp")
    open_log()

    if (watch != "") { watch_loop(watch + 0); finish(); exit 0 }

    header("client check")
    link_checks()
    l3_checks()
    l4_checks()
    l5_checks()
    l7_checks()
    tp_checks()
    facts()
    finish()
}

# ---------- L1/L2: link to the UTR ----------

function link_checks(    i, s, ch, ipaddr, ifc, g) {
    row("L1", "UTR uplink SSID/band/RSSI", "MANUAL", "UniFi app > UTR > uplink: write down RSSI, band, channel and any reconnect")
    if (PLAT == "macos") {
        run("system_profiler SPAirPortDataType")
        s = ""; ch = ""
        for (i = 1; i <= NL; i++) {
            if (LINES[i] ~ /Current Network Information:/) s = "cur"
            if (s == "cur" && ch == "" && LINES[i] ~ /Channel:/) { ch = LINES[i]; sub(/^.*Channel: */, "", ch) }
            if (s == "cur" && LINES[i] ~ /Signal \/ Noise:/) { s = LINES[i]; sub(/^.*Noise: */, "", s); break }
        }
        if (s != "" && s != "cur") row("L2", "Mac Wi-Fi to UTR", "INFO", "signal/noise " s ", channel " ch " (the Mac's link, not the UTR uplink)")
        else row("L2", "Mac Wi-Fi to UTR", "??", "no Wi-Fi data from system_profiler (Ethernet?)")

        run("route -n get default")
        g = ""; ifc = ""
        for (i = 1; i <= NL; i++) {
            if (LINES[i] ~ /gateway:/) { g = LINES[i]; sub(/^.*gateway: */, "", g) }
            if (LINES[i] ~ /interface:/) { ifc = LINES[i]; sub(/^.*interface: */, "", ifc) }
        }
        if (g == gw) row("L2", "default route", "OK", "via " gw " on " ifc)
        else if (g != "") row("L2", "default route", "WARN", "via " g " on " ifc ", not the UTR " gw ": VPN or another network")
        else if (ifc != "") row("L2", "default route", "WARN", "on " ifc " without a gateway: VPN?")
        else row("L2", "default route", "FAIL", "none: no network")
        if (ifc == "") ifc = "en0"
    } else if (PLAT == "blink") {
        row("L2", "iPhone Wi-Fi to UTR", "SKIP", "iOS does not give apps the RSSI")
        ifc = "en0"
    } else {
        row("L2", "client link", "SKIP", "not macOS or Blink")
        return
    }

    ipaddr = if_ip(ifc)
    CLIENT_IP = ipaddr
    if (ipaddr == "") row("L2", "client IP", "FAIL", "no IPv4 on " ifc)
    else if (index(ipaddr, LANP) == 1) row("L2", "client IP", "OK", ifc " " ipaddr " (behind the UTR)")
    else row("L2", "client IP", "WARN", ifc " " ipaddr ": not in " LANP "0/24, this device is not behind the UTR")

    if (PLAT == "blink") {
        ipaddr = if_ip("pdp_ip0")
        if (ipaddr != "") row("L2", "cellular data", "WARN", "on (" ipaddr "): iOS can send probes over LTE. For UTR runs turn off Cellular Data")
        else row("L2", "cellular data", "OK", "no IPv4 on pdp_ip0")
    }
}

# ---------- L3: addressing and path ----------

function l3_checks(    ok, f, n, t, i) {
    ok = (run("ping -c 2 -W 2000 " gw) == 0)
    row("L3", "ping UTR " gw, ok ? "OK" : "INFO", ok ? "replies" : "no reply (the UTR may ignore ping; DNS below decides)")

    PUBIP = public_ip()
    if (PUBIP != "") row("L3", "public IP", "OK", PUBIP " (" PUBSRC ")")
    else row("L3", "public IP", "FAIL", "1.1.1.1 trace and api.ipify.org both failed")

    if (home == "") row("L3", "egress vs home WAN", "SKIP", "pass -v home=HOME_WAN_IP")
    else if (PUBIP == home) row("L3", "egress vs home WAN", "INFO", "egress = home WAN: client traffic goes through Teleport")
    else if (PUBIP != "") row("L3", "egress vs home WAN", "INFO", "egress " PUBIP " is not home " home ": client traffic leaves via the uplink")

    # The UTR's own internet check is ICMP only (firmware 6.6.115-6.6.122, unifi_mwan and mcad):
    # one of 1.1.1.1, 8.8.8.8, www.microsoft.com must answer ping, or the app shows "No Internet".
    # Since 6.6.117 teleport-client then waits for WAN and never connects; WireGuard waits too.
    ICMP_OK = 0; f = 0
    n = split("1.1.1.1 8.8.8.8 www.microsoft.com", t, " ")
    for (i = 1; i <= n; i++) {
        if (run("ping -c 2 -W 2000 " t[i]) == 0) ICMP_OK++
        else if (has("prohibited")) f = 1
    }
    if (ICMP_OK) row("L3", "ping 1.1.1.1, 8.8.8.8, www.microsoft.com", "OK", ICMP_OK "/" n " reply: the UTR's internet check can pass on this uplink")
    else row("L3", "ping 1.1.1.1, 8.8.8.8, www.microsoft.com", "FAIL", (f ? "prohibited by filter" : "no reply") ": the UTR shows No Internet; firmware 6.6.117+ then likely does not start Teleport or WireGuard (H7; OpenVPN is not gated)")

    if (PLAT == "macos") {
        if (home != "") trace(home, "home")
        trace("1.1.1.1", "1.1.1.1")
    } else row("L3", "traceroute", "SKIP", "Blink has no traceroute: run it on the Mac")
}

# traceroute -n, one probe per hop: hops that answered, last answering hop, target reached or not.
function trace(target, name,    i, f, n, ans, hops, last) {
    run("traceroute -n -q 1 -w 2 -m 16 " target)
    ans = 0; hops = 0; last = ""
    for (i = 1; i <= NL; i++) {
        if (LINES[i] !~ /^ *[0-9]+  */) continue
        n = split(LINES[i], f, " ")
        hops++
        if (n >= 2 && f[2] != "*") { ans++; last = f[2] }
    }
    if (hops == 0) row("L3", "traceroute " name, "??", "no hop lines (" (NL > 0 ? LINES[1] : "no output") ")")
    else row("L3", "traceroute " name, last == target ? "OK" : "INFO", ans "/" hops " hops answered, last " (last == "" ? "none" : last) (last == target ? ", reached" : ", not reached (ICMP/UDP filtered?)"))
}

# ---------- L4: TCP and UDP ----------

function l4_checks(    n, p, i, probe, seen, t0, wport) {
    tcp_row("1.1.1.1", 443, "")
    tcp_row("1.1.1.1", 80, "")
    if (home != "") { tcp_row(home, 443, "home"); tcp_row(home, 80, "home") }

    STUN_OK = 0; STUN_TRIED = 0
    stun("stun.cloudflare.com", 3478)
    stun("stun.l.google.com", 19302)

    if (home == "") { row("L4", "UDP to home", "SKIP", "pass -v home=HOME_WAN_IP"); return }
    if (PUBIP == home) row("L4", "UDP to home", "WARN", "egress is already home: these probes go through the tunnel, not the uplink. Uplink test = Teleport off")
    n = split(ports, probe, " ")
    if (tport != "") {
        seen = 0
        for (i = 1; i <= n; i++) if (probe[i] == tport) seen = 1
        if (!seen) probe[++n] = tport
    }
    UDP_T0 = now()
    for (i = 1; i <= n; i++) {
        p = probe[i]
        if (p !~ /^[0-9]+$/) continue
        if (run("nc -uz " home " " p) == 0) row("L4", "UDP home:" p, "SENT", "4 x 1 byte; did it arrive? see the CGM capture")
        else row("L4", "UDP home:" p, "FAIL", "nc could not send: " first_line())
    }
    wport = (tport != "") ? tport : "51820"
    if (!readable(dir "/wg-probe.bin")) row("L4", "WG-shaped home:" wport, "SKIP", "wg-probe.bin not found in " dir)
    else if (run("nc -u -w 1 " home " " wport " < " dir "/wg-probe.bin") == 0) row("L4", "WG-shaped home:" wport, "SENT", "148 bytes shaped like a WireGuard handshake; see the CGM capture")
    else row("L4", "WG-shaped home:" wport, "FAIL", "nc could not send: " first_line())
    UDP_T1 = now()
}

# TCP connect with a 3 s timeout. For home: refused = an RST came back, so the path works both ways.
function tcp_row(host, port, name,    rc) {
    rc = run("nc -zv -G 3 " host " " port)
    if (rc == 0) row("L4", "TCP " (name != "" ? name : host) ":" port, "OK", "connected")
    else if (has("refused")) row("L4", "TCP " (name != "" ? name : host) ":" port, name != "" ? "OK" : "FAIL", "refused: the RST came back" (name != "" ? ", path works both ways" : ""))
    else if (has("timed out")) row("L4", "TCP " (name != "" ? name : host) ":" port, name != "" ? "INFO" : "FAIL", "timed out" (name != "" ? ": dropped on the way or by the CGM firewall; see the CGM capture" : ""))
    else row("L4", "TCP " (name != "" ? name : host) ":" port, "FAIL", first_line())
}

# STUN binding request (20 bytes). Any answer = UDP goes out and comes back on this uplink.
function stun(host, port,    rc, i, err) {
    if (!readable(dir "/stun-req.bin")) { row("L4", "UDP STUN " host ":" port, "SKIP", "stun-req.bin not found in " dir); return }
    STUN_TRIED++
    rc = run("nc -u -w 2 " host " " port " < " dir "/stun-req.bin")
    err = ""
    # The reply is binary: index() only, Blink's awk aborts when a regex meets invalid UTF-8.
    for (i = 1; i <= NL; i++) if (index(LINES[i], "nc: ") == 1 || index(LINES[i], "netcat: ") == 1) err = LINES[i]
    if (err != "") row("L4", "UDP STUN " host ":" port, "FAIL", err)
    else if (NL > 0) { row("L4", "UDP STUN " host ":" port, "OK", "answer received: UDP out and back works"); STUN_OK++ }
    else row("L4", "UDP STUN " host ":" port, "FAIL", "no answer in 2 s")
}

# ---------- L5/L6: TLS ----------

function l5_checks(    n, h, i) {
    TLS_OK = 0; TLS_CERT = 0; TLS_N = 0
    tls("1.1.1.1")
    n = split(hosts, h, " ")
    for (i = 1; i <= n; i++) tls(h[i])
}

# HTTPS GET with timings and the certificate chain.
# macOS curl (LibreSSL/OpenSSL) prints "issuer: ...", Blink curl (Secure Transport) prints
# one "Server certificate: <subject>" line per certificate, leaf first.
function tls(host,    rc, i, f, t, code, issuer, chain, nchain, s, d, p) {
    rc = run("curl -sS -v -o /dev/null -m 10 -w \"\\nTIMES %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{http_code} %{remote_ip}\\n\" https://" host "/")
    t = ""; issuer = ""; nchain = 0
    # curl -v includes the server's headers, which can hold any bytes: find lines with
    # substr()/index() and run regexes only on the certificate lines picked out.
    for (i = 1; i <= NL; i++) {
        if (substr(LINES[i], 1, 6) == "TIMES ") t = LINES[i]
        else if (substr(LINES[i], 1, 1) == "*" && index(LINES[i], " issuer: ")) { issuer = LINES[i]; sub(/^.* issuer: */, "", issuer) }
        else if ((p = index(LINES[i], "Server certificate: ")) && length(LINES[i]) > p + 19) chain[++nchain] = substr(LINES[i], p + 20)
    }
    if (issuer == "" && nchain >= 2) issuer = chain[2]
    if (issuer ~ /CN ?= ?/) { sub(/^.*CN ?= ?/, "", issuer); sub(/[,;\/].*$/, "", issuer) }
    TLS_N++
    if (rc == 0 && t != "") {
        split(t, f, " ")
        d = "HTTP " f[6] ", dns " ms(f[2]) " tcp " ms(f[3] - f[2]) " tls " ms(f[4] - f[3]) " ttfb " ms(f[5]) " ms, " f[7]
        if (issuer != "") d = d ", issuer " issuer
        row("L5", "TLS " host, "OK", d)
        TLS_OK++
    } else if (rc == 60) {
        row("L5", "TLS " host, "CERT", "certificate not trusted (curl 60): TLS interception or portal" (issuer != "" ? ", issuer " issuer : ""))
        TLS_CERT++
    } else row("L5", "TLS " host, "FAIL", curl_err(rc))
}

function curl_err(rc) {
    if (rc == 6) return "name does not resolve (curl 6)"
    if (rc == 7) return "TCP connect failed (curl 7)"
    if (rc == 28) return "timed out (curl 28)"
    if (rc == 35) return "TLS handshake failed (curl 35)"
    if (rc == 51) return "certificate name mismatch (curl 51)"
    return "curl exit " rc ": " first_line()
}

# ---------- L7: DNS and captive portal ----------

function l7_checks(    n, h, i, a, ok, ip) {
    a = dig_first("dig @" gw " example.com +short +time=2 +tries=1")
    DNS_GW = (a != "")
    row("L7", "DNS @" gw " example.com", a != "" ? "OK" : "FAIL", a != "" ? a : "no answer: UTR DNS or its upstream")

    n = split(hosts, h, " ")
    for (i = 1; i <= n; i++) {
        a = dig_first("dig @" gw " " h[i] " +short +time=2 +tries=1")
        if (a == "0.0.0.0") row("L7", "DNS @" gw " " h[i], "FAIL", "0.0.0.0: blocked by a filter upstream")
        else row("L7", "DNS @" gw " " h[i], a != "" ? "OK" : "FAIL", a != "" ? a : "no answer")
    }

    # Which resolver does the UTR forward to? These names answer with the address of the
    # resolver that asked the authoritative server, not with a fixed record.
    a = dig_first("dig @" gw " whoami.akamai.net +short +time=2 +tries=1")
    row("L7", "UTR DNS upstream (Akamai)", a != "" ? "INFO" : "??", a != "" ? "resolver egress " a : "no answer")
    run("dig @" gw " o-o.myaddr.l.google.com TXT +short +time=2 +tries=1")
    a = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^"/) { ip = LINES[i]; gsub(/"/, "", ip); a = a (a == "" ? "" : "; ") ip }
    row("L7", "UTR DNS upstream (Google)", a != "" ? "INFO" : "??", a != "" ? a : "no answer")
    a = dig_first("dig @" gw " verify.controld.com +short +time=2 +tries=1")
    row("L7", "UTR DNS = Control D?", "INFO", a == VERIFY_IP ? "yes (" a ")" : "no" (a != "" ? " (" a ")" : ""))

    # System resolver of this device (ping by name; on iOS it follows a DNS profile, dig does not).
    run("ping -c 1 -W 1000 verify.controld.com")
    ip = ping_ip()
    if (ip == VERIFY_IP) row("L7", "device DNS = Control D?", "INFO", "yes: this device's apps resolve via Control D, not via the UTR")
    else row("L7", "device DNS = Control D?", "INFO", "no" (ip != "" ? " (" ip ")" : ""))

    # Captive portal probes. curl keeps no cookies, like a private window.
    PORTAL = 0
    captive("Apple", "http://captive.apple.com/hotspot-detect.html", "200", "Success")
    captive("Google", "http://connectivitycheck.gstatic.com/generate_204", "204", "")
    captive("Firefox", "http://detectportal.firefox.com/success.txt", "200", "success")
    row("L7", "captive probe UI", "MANUAL", "UI's probe URL is not documented: not tested")
}

function captive(name, url, want, body,    rc, i, code, redir, got) {
    rc = run("curl -sS -m 8 -w \"\\nHTTPCODE %{http_code} %{redirect_url}\\n\" " url)
    code = ""; redir = ""; got = (body == "")
    for (i = 1; i <= NL; i++) {
        # Page bodies can be any bytes: substr()/index() only, no regex on them.
        if (substr(LINES[i], 1, 9) == "HTTPCODE ") { code = substr(LINES[i], 10); redir = substr(code, 5); code = substr(code, 1, 3) }
        else if (body != "" && index(LINES[i], body) > 0) got = 1
    }
    if (rc != 0 || code == "") { row("L7", "captive probe " name, "FAIL", curl_err(rc)); PORTAL++ }
    else if (code == want && got) row("L7", "captive probe " name, "OK", "HTTP " code ", expected answer")
    else { row("L7", "captive probe " name, "PORTAL", "HTTP " code (redir != "" ? " -> " redir : "") ", not the expected answer"); PORTAL++ }
}

# ---------- Teleport, as far as a client can see it ----------

function tp_checks(    rc) {
    if (homelan == "") row("TP", "home LAN reachable", "SKIP", "pass -v homelan=CGM_LAN_IP")
    else {
        rc = run("nc -zv -G 3 " homelan " 443")
        if (rc == 0) row("TP", "home LAN " homelan ":443", "OK", "reachable: the tunnel is up and routes the home LAN")
        else row("TP", "home LAN " homelan ":443", "FAIL", "not reachable: tunnel down, or it does not route the home LAN")
    }
    row("TP", "UTR Teleport status", "MANUAL", "UniFi app: status text and time")
    row("TP", "CGM side", "MANUAL", "teleport-cgm.sh capture and watch during this run")
}

# ---------- facts only, no verdict ----------

function facts() {
    out("")
    out("Observed in this run (" label ", Teleport " tp "):")
    if (PUBIP != "") out("- public IP " PUBIP (home != "" ? (PUBIP == home ? " = home WAN" : ", not home WAN") : ""))
    out("- ICMP to the UTR's check targets: " ICMP_OK "/3 reply" (ICMP_OK ? "" : ": UTR No Internet, Teleport on 6.6.117+ waits for WAN (see docs/teleport.md H7)"))
    if (STUN_TRIED) out("- UDP out and back to STUN: " STUN_OK "/" STUN_TRIED " answered")
    out("- TLS: " TLS_OK "/" TLS_N " OK" (TLS_CERT ? ", " TLS_CERT " with an untrusted certificate" : ", no untrusted certificate seen"))
    out("- captive probes: " (PORTAL ? PORTAL " not as expected" : "all as expected"))
    out("- UTR DNS: " (DNS_GW ? "answers" : "does not answer"))
    if (home != "" && UDP_T0 != "" && PUBIP == home) out("- UDP probes to " home " went through the tunnel (egress = home): not an uplink test")
    else if (home != "" && UDP_T0 != "") out("- UDP probes to " home " sent " UDP_T0 "-" UDP_T1 " UTC" (PUBIP != "" ? " from " PUBIP : "") ": match them in the CGM capture")
    out("Not decided by this script: whether UDP to home arrives (CGM capture) and the control run.")
}

# ---------- watch mode: timestamps of link and uplink changes ----------

function watch_loop(mins,    tend, cyc, recv, g, n, c, ip, pg, pn, pc, pip, beat, st) {
    if (PLAT == "blink") NOTE = "Keep Blink in front with the screen on (or run `geo track` first): iOS suspends apps in the background."
    header("watch " mins " min")
    tend = epoch() + mins * 60
    cyc = 0; pg = ""; pn = ""; pc = ""; pip = ""; beat = 0
    while (1) {
        cyc++
        run("ping -c 5 -i 1 -W 1000 " gw)
        recv = ping_received()
        g = (recv > 0) ? "up" : "down"
        n = (run("nc -z -G 2 1.1.1.1 443") == 0) ? "up" : "down"
        c = if_ip(PLAT == "macos" ? default_if() : "en0")
        if (cyc == 1 || cyc % 6 == 0) ip = public_ip()
        st = (cyc == 1) ? "START " : ""
        if (g != pg) row("L2", "UTR " gw " ping", st (g == "up" ? "UP" : "DOWN"), recv "/5 replies")
        if (n != pn) row("L4", "TCP 1.1.1.1:443", st (n == "up" ? "UP" : "DOWN"), "internet")
        if (c != pc) row("L2", "client IP", st (c == "" ? "DOWN" : "UP"), c == "" ? "no IPv4" : c)
        if (ip != pip) row("L3", "public IP", st (ip == "" ? "DOWN" : "CHANGE"), ip == "" ? "no answer" : ip)
        pg = g; pn = n; pc = c; pip = ip
        if (++beat >= 12) { row("--", "alive", "INFO", "gw " g ", internet " n ", public " (ip == "" ? "?" : ip)); beat = 0 }
        if (epoch() >= tend) break
    }
}

function default_if(    i, s) {
    run("route -n get default")
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /interface:/) { s = LINES[i]; sub(/^.*interface: */, "", s); return s }
    return "en0"
}

function ping_received(    i, s) {
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /packets received/) { s = LINES[i]; sub(/^[^,]*, */, "", s); sub(/ .*$/, "", s); return s + 0 }
    return 0
}

# ---------- helpers ----------

# Snip parameters left unfilled arrive as "${name}": treat them as not given.
function val(x) { return (x ~ /\$\{/) ? "" : x }

function is_ip(x) { return (x ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) }

function ms(x) { return int(x * 1000 + 0.5) }

function platform(    m) {
    run("uname -m")
    m = (NL > 0) ? LINES[1] : ""
    if (m ~ /^(iPhone|iPad|iPod)/ || ENVIRON["HOME"] ~ /\/mobile\/Containers\//) return "blink"
    run("uname -s")
    if (NL > 0 && LINES[1] == "Darwin") return "macos"
    return "other"
}

function now() { run("date -u +%H:%M:%S"); return (NL > 0) ? LINES[1] : "??:??:??" }

function epoch() { run("date -u +%s"); return (NL > 0) ? LINES[1] + 0 : 0 }

# IPv4 of an interface from ifconfig, empty if none.
function if_ip(ifc,    i, f) {
    if (run("ifconfig " ifc) != 0) return ""
    for (i = 1; i <= NL; i++) {
        if (LINES[i] ~ /^[ \t]*inet [0-9]/) { split(LINES[i], f, " "); return f[2] }
    }
    return ""
}

function public_ip(    i, s) {
    PUBSRC = "1.1.1.1 trace"
    if (run("curl -sS -m 8 https://1.1.1.1/cdn-cgi/trace") == 0) {
        for (i = 1; i <= NL; i++) if (substr(LINES[i], 1, 3) == "ip=") return substr(LINES[i], 4)
    }
    PUBSRC = "api.ipify.org"
    if (run("curl -sS -m 8 https://api.ipify.org") == 0 && NL > 0 && length(LINES[1]) <= 39 && is_ip(LINES[1])) return LINES[1]
    return ""
}

function readable(f,    r, x) {
    r = (getline x < f)
    close(f)
    return (r >= 0)
}

# First IPv4 in "dig +short" output, empty if none.
function dig_first(cmd,    i) {
    if (run(cmd) != 0) return ""
    for (i = 1; i <= NL; i++) if (is_ip(LINES[i])) return LINES[i]
    return ""
}

# IP from the line "PING name (IP): ...", otherwise empty.
function ping_ip(    i, s) {
    for (i = 1; i <= NL; i++) {
        if (LINES[i] ~ /^PING .*\(/) { s = LINES[i]; sub(/^[^(]*\(/, "", s); sub(/\).*$/, "", s); return s }
    }
    return ""
}

function first_line() { return (NL > 0) ? LINES[1] : "no output" }

function header(what,    d) {
    run("date -u +%Y-%m-%dT%H:%M:%SZ")
    d = (NL > 0) ? LINES[1] : "?"
    out("== UTR Teleport check, " what " ==")
    out("run: " label "  teleport: " tp "  platform: " PLAT "  started: " d)
    out("home WAN: " (home != "" ? home : "-") "  teleport port: " (tport != "" ? tport : "-") "  home LAN probe: " (homelan != "" ? homelan : "-") "  UTR: " gw)
    if (NOTE != "") out(NOTE)
    out("")
    out("| time UTC | layer | test | result | detail |")
    out("|---|---|---|---|---|")
}

function row(layer, test, result, detail) {
    out("| " now() " | " layer " | " test " | " result " | " detail " |")
}

function out(s) {
    print s
    if (LOG != "") print s >> LOG
}

# Log next to the scripts in iCloud (Blink) or in ~/tp (macOS) if writable, else next to the temp file.
function open_log(    d, stamp, f) {
    run("date -u +%Y%m%d-%H%M%S")
    stamp = (NL > 0) ? LINES[1] : "now"
    d = (PLAT == "blink") ? ENVIRON["HOME"] "/iCloud" : dir
    f = d "/tp-" label "-" stamp ".txt"
    if (system("echo > " f " 2>/dev/null") == 0) { LOG = f; printf "" > LOG; close(LOG); return }
    f = OUTDIR "/tp-" label "-" stamp ".txt"
    if (system("echo > " f " 2>/dev/null") == 0) { LOG = f; printf "" > LOG; close(LOG); return }
    LOG = ""
}

# Blink: ~/iCloud is the Blink folder in iCloud Drive, so show it the way the Files app does.
function pretty(f,    h) {
    h = ENVIRON["HOME"] "/iCloud/"
    if (PLAT == "blink" && index(f, h) == 1) return "Files > iCloud Drive > Blink > " substr(f, length(h) + 1)
    return f
}

function finish() {
    if (LOG != "") { close(LOG); print ""; print "Saved (same as above): " pretty(LOG) }
    system("rm -f " OUT)
}

# Find a folder where "> file 2>&1" redirection really works. OUT = path to the temp file.
function preflight(    dirs, n, i, line) {
    n = split(ENVIRON["HOME"] " " ENVIRON["TMPDIR"] " .", dirs, " ")
    for (i = 1; i <= n; i++) {
        OUT = dirs[i] "/.tp-out.txt"
        OUTDIR = dirs[i]
        if (system("echo tp-ok > " OUT " 2>&1") != 0) continue
        line = ""
        getline line < OUT
        close(OUT)
        if (line == "tp-ok") return 1
    }
    return 0
}

# Run a command, keep its output (stdout+stderr) in LINES[1..NL]. Return the exit code.
function run(cmd,    rc, line, r) {
    rc = system(cmd " > " OUT " 2>&1")
    # Killed by a signal (Ctrl-C): stop instead of reporting the check as failed.
    if (rc >= 256 || rc != int(rc)) {
        print ""
        print "Interrupted (Ctrl-C)."
        if (LOG != "") close(LOG)
        system("rm -f " OUT)
        exit 130
    }
    split("", LINES)
    NL = 0
    while ((r = (getline line < OUT)) > 0) LINES[++NL] = line
    close(OUT)
    return rc
}

# Does any output line match the regular expression?
function has(re,    i) {
    for (i = 1; i <= NL; i++) if (LINES[i] ~ re) return 1
    return 0
}
