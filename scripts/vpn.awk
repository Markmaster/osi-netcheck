# vpn.awk - can a VPN connect over the current connection (Wi-Fi or LTE)?
# Runs in the Blink Shell local shell (iPhone/iPad) and in macOS Terminal. Read-only, needs no server.
#
# Blink:  awk -f ~/iCloud/scripts/vpn.awk                                   (snip vpn/run)
#         awk -v server=HOME_IP -v tcp=PORT -f ~/iCloud/scripts/vpn.awk     (snip vpn/run-server)
# macOS:  awk -f ~/vpn/vpn.awk   (vpn.awk, stun-req.bin and ntp-req.bin from scripts/ in one folder)
#
# What a VPN needs from the network, tested without a server of your own: internet and no
# Wi-Fi login page, UDP out and back (STUN 3478 and 19302, NTP 123, DNS 53 to 1.1.1.1), HTTPS
# to the UniFi cloud without interception (Teleport). IPv6 is shown for context.
# Optional -v server=IP -v tcp=PORT: TCP connect to your own server (OpenVPN over TCP).
# UDP to your own server's port cannot be confirmed from the phone: WireGuard does not answer
# unknown packets. The VPN app is the final word; this script says what the network allows.
#
# Blink's local shell has no sh, so the logic is awk, as in osi.awk: each probe runs through
# system() with its output in a temp file, which awk then parses. Replies from the network
# (UDP answers, web pages) are only compared with index() and ==: Blink's awk aborts when a
# regex meets a byte that is not valid UTF-8.

BEGIN {
    server = val(server); tcp = val(tcp); dir = val(dir)
    if (tcp != "" && tcp !~ /^[0-9]+$/) { print "tcp=\"" tcp "\" is not a port number"; exit 2 }
    if (tcp != "" && server == "") { print "tcp=" tcp " needs -v server=IP_or_name"; exit 2 }
    if (server != "" && tcp == "") tcp = "443"

    if (!preflight()) {
        print "STOP: cannot save command output to a temp file ($HOME, $TMPDIR, current folder)."
        exit 1
    }
    PLAT = platform()
    if (dir == "") dir = find_dir()
    link()
    open_log()
    header()

    row("L2", "connection", LINK_OK ? "OK" : "FAIL", LINK_TXT)
    if (TUN != "") row("L2", "VPN already on?", "WARN", TUN ": a VPN looks connected, the rows below then describe the VPN. Turn it off and run again")
    internet()
    udp()
    ipv6()
    cloud()
    if (server != "") server_tcp()
    verdict()
    finish()
}

# ---------- link: Wi-Fi or LTE ----------

function link(    w, c, g, ifc, i, cur, f, wdev) {
    LINK_OK = 1; HAS4 = 1; V6ONLY = 0; TUN = ""
    if (PLAT == "blink") {
        w = if_ip("en0"); c = if_ip("pdp_ip0")
        if (w ~ /^169\.254\./) w = ""
        if (w == "" && if_has6("en0")) w = "IPv6 only"
        if (c == "" && if_has6("pdp_ip0")) c = "IPv6 only"
        if (w != "" && c != "") { KIND = "wifi"; LINK_TXT = "Wi-Fi " w ", cellular also up (" c "): iOS can move traffic to LTE if Wi-Fi is weak" }
        else if (w != "") { KIND = "wifi"; LINK_TXT = "Wi-Fi " w }
        else if (c != "") { KIND = "lte"; LINK_TXT = "LTE/cellular " c }
        else { KIND = "none"; LINK_TXT = "no IP on Wi-Fi (en0) or cellular (pdp_ip0)"; LINK_OK = 0 }
        if ((KIND == "wifi" && w == "IPv6 only") || (KIND == "lte" && c == "IPv6 only")) { V6ONLY = 1; HAS4 = 0 }
        if ((KIND == "wifi" && w ~ /^192\.0\.0\./) || (KIND == "lte" && c ~ /^192\.0\.0\./)) { V6ONLY = 1; LINK_TXT = LINK_TXT " (IPv6-only network, IPv4 via CLAT/NAT64)" }
        # A connected iOS VPN shows up as a utun/ipsec/ppp interface with an IPv4 address.
        # 192.0.0.x is skipped: iOS puts such addresses on utun0 by itself (seen on an iPhone with
        # no VPN on, public IP still the carrier's), like the 192.0.0.2 CLAT address on pdp_ip0.
        run("ifconfig")
        cur = ""
        for (i = 1; i <= NL; i++) {
            if (LINES[i] ~ /^[a-z]+[0-9]+:/) { cur = LINES[i]; sub(/:.*$/, "", cur) }
            else if (cur ~ /^(utun|ipsec|ppp)/ && LINES[i] ~ /^[ \t]*inet [0-9]/) { split(LINES[i], f, " "); if (f[2] !~ /^192\.0\.0\./) { TUN = cur " " f[2]; break } }
        }
        return
    }
    if (PLAT == "macos") {
        # The route to 1.1.1.1 follows VPN split routes (0.0.0.0/1 + 128.0.0.0/1); "get default" does not.
        run("route -n get 1.1.1.1")
        g = ""; ifc = ""
        for (i = 1; i <= NL; i++) {
            if (LINES[i] ~ /gateway:/) { g = LINES[i]; sub(/^.*gateway: */, "", g) }
            if (LINES[i] ~ /interface:/) { ifc = LINES[i]; sub(/^.*interface: */, "", ifc) }
        }
        if (ifc == "") { KIND = "none"; LINK_TXT = "no IPv4 route to the internet"; LINK_OK = 0; HAS4 = 0; return }
        if (ifc ~ /^(utun|ppp|ipsec)/) { KIND = "vpn"; TUN = ifc; LINK_TXT = "traffic goes via " ifc " (a VPN)"; return }
        run("networksetup -listallhardwareports")
        wdev = ""
        for (i = 1; i < NL; i++) if (index(LINES[i], "Hardware Port: Wi-Fi") == 1 || index(LINES[i], "Hardware Port: AirPort") == 1) { wdev = LINES[i + 1]; sub(/^Device: */, "", wdev) }
        KIND = (ifc == wdev) ? "wifi" : "wired"
        if (g ~ /^172\.20\.10\./) KIND = "hotspot"
        LINK_TXT = (KIND == "hotspot" ? "iPhone hotspot (LTE), " : (KIND == "wifi" ? "Wi-Fi, " : "not Wi-Fi, ")) ifc " " if_ip(ifc) (g != "" ? ", gateway " g : "")
        return
    }
    KIND = "other"; LINK_TXT = "not macOS or Blink: link type not detected"
}

# ---------- internet and login page ----------

function internet(    rc) {
    TCP443 = (run("nc -z -G 3 1.1.1.1 443") == 0)
    row("L4", "TCP 443 to 1.1.1.1", TCP443 ? "OK" : "FAIL", TCP443 ? "connected" : "no connection")

    rc = run("curl -sS -m 6 https://1.1.1.1/cdn-cgi/trace")
    HTTPS = (rc == 0)
    PUB4 = HTTPS ? trace_ip() : ""
    CERT1 = (rc == 60)
    row("L5", "HTTPS to 1.1.1.1", HTTPS ? "OK" : "FAIL", HTTPS ? "public IPv4 " (PUB4 != "" ? PUB4 : "?") : curl_err(rc))

    PORTAL = 0
    rc = run("curl -sS -m 6 -w \"\\nHTTPCODE %{http_code}\\n\" http://captive.apple.com/hotspot-detect.html")
    if (rc == 0 && line_is("HTTPCODE 200") && contains("Success")) row("L7", "Wi-Fi login page", "OK", "none (Apple probe answers Success)")
    else if (rc == 0) { PORTAL = 1; row("L7", "Wi-Fi login page", "PORTAL", "Apple probe answered something else: log in via Safari first") }
    else row("L7", "Wi-Fi login page", "FAIL", "Apple probe: " curl_err(rc))
}

# ---------- UDP out and back ----------

function udp(    a, i, s) {
    FAM = HAS4 ? "-4" : "-6"
    FAMTXT = HAS4 ? "IPv4" : "IPv6"
    UDPSKIP = ""
    U3478 = udp_probe("stun.cloudflare.com", 3478, "stun-req.bin", "STUN")
    U19302 = udp_probe("stun.l.google.com", 19302, "stun-req.bin", "STUN")
    U123 = udp_probe("time.apple.com", 123, "ntp-req.bin", "NTP")

    # UDP 53: only Cloudflare answers id.server (CHAOS TXT) with its site code ("sea07" on an
    # iPhone 2026-10-20, "SJC" in older docs: 3 letters, optional digits, any case), so
    # a network that answers DNS itself (hijack) is not counted as "UDP 53 reaches the internet".
    run("dig @1.1.1.1 CH TXT id.server +short +time=2 +tries=1")
    s = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^"[A-Za-z][A-Za-z][A-Za-z][0-9]*"$/) s = LINES[i]
    U53 = (s != "")
    if (U53) row("L4", "UDP 53 DNS to 1.1.1.1", "OK", "Cloudflare answered (" s ")")
    else {
        a = dig_first("dig @1.1.1.1 example.com +short +time=2 +tries=1")
        if (a == "") row("L4", "UDP 53 DNS to 1.1.1.1", "FAIL", "no answer")
        else {
            # Only Control D answers verify.controld.com with 147.185.34.1 (as in osi.awk). An iOS DNS
            # profile does not catch "dig @1.1.1.1" (iPhone 2026-10-20, Control D profile on): a router does.
            run("dig @1.1.1.1 verify.controld.com +short +time=2 +tries=1")
            if (line_is("147.185.34.1")) row("L4", "UDP 53 DNS to 1.1.1.1", "HIJACK", "answered by Control D, not Cloudflare: the router or an app on this device redirects DNS to Control D")
            else row("L4", "UDP 53 DNS to 1.1.1.1", "HIJACK", "answered, but not by Cloudflare: the network or a VPN-mode DNS app answers DNS itself (a DNS profile does not)")
        }
    }
}

# Send a small request file over UDP, wait 2 s. Any answer = UDP goes out and comes back on this port.
# Returns 1 answered, 0 no answer, -1 not tested (UDPSKIP says why: file or dns).
function udp_probe(host, port, file, what,    i, err, t) {
    t = "UDP " port " " what " (" FAMTXT ")"
    if (!readable(dir "/" file)) { row("L4", t, "SKIP", file " not found in " dir); UDPSKIP = "file"; return -1 }
    run("nc " FAM " -u -w 2 " host " " port " < " dir "/" file)
    err = ""
    for (i = 1; i <= NL; i++) if (index(LINES[i], "nc: ") == 1 || index(LINES[i], "netcat: ") == 1) err = LINES[i]
    if (err != "" && (index(err, "getaddrinfo") || index(err, "nodename") || index(err, "not known"))) {
        row("L4", t, "SKIP", host " does not resolve: DNS problem, UDP not tested"); if (UDPSKIP == "") UDPSKIP = "dns"; return -1
    }
    if (err != "") { row("L4", t, "FAIL", err); return 0 }
    if (NL > 0) { row("L4", t, "OK", host " answered"); return 1 }
    row("L4", t, "FAIL", host ": no answer in 2 s")
    return 0
}

# ---------- IPv6 ----------

function ipv6(    rc) {
    rc = run("curl -6 -sS -m 6 https://one.one.one.one/cdn-cgi/trace")
    PUB6 = (rc == 0) ? trace_ip() : ""
    if (PUB6 != "") row("L3", "IPv6 to the internet", "OK", PUB6)
    else row("L3", "IPv6 to the internet", "NONE", (rc == 6 || rc == 7) ? "no IPv6 on this connection" : curl_err(rc))
}

# ---------- UniFi cloud (Teleport brokering) ----------

function cloud(    n, h, i, rc) {
    UI_N = 0; UI_OK = 0; UI_CERT = 0
    n = split("unifi.ui.com api.ui.com", h, " ")
    for (i = 1; i <= n; i++) {
        UI_N++
        rc = run("curl -sS -o /dev/null -m 8 -w \"HTTP %{http_code}, %{remote_ip}\\n\" https://" h[i] "/")
        if (rc == 0) { UI_OK++; row("L5", "HTTPS " h[i], "OK", first_line()) }
        else if (rc == 60) { UI_CERT++; row("L5", "HTTPS " h[i], "CERT", "certificate not trusted: the network intercepts TLS") }
        else row("L5", "HTTPS " h[i], "FAIL", curl_err(rc))
    }
}

# ---------- optional: TCP to your own server ----------

function server_tcp(    rc) {
    rc = run("nc -zv -G 3 " server " " tcp)
    if (rc == 0) SRV = "open"
    else if (contains("refused")) SRV = "refused"
    else if (contains("timed out")) SRV = "timeout"
    else SRV = "error"
    row("L4", "TCP " server ":" tcp, SRV == "open" ? "OK" : "FAIL", SRV == "open" ? "connected" : (SRV == "refused" ? "refused: an RST came back (server or a firewall), nothing accepts on this port" : (SRV == "timeout" ? "timed out: blocked on the way or by the server firewall" : first_line())))
}

# ---------- verdict: an inference from the rows above ----------

function verdict(    inet, stun, tested, nudp, v, tcpok) {
    inet = (TCP443 || HTTPS || UI_OK > 0 || PUB6 != "" || U3478 == 1 || U19302 == 1 || U53 || U123 == 1)
    stun = (U3478 == 1 || U19302 == 1)
    tested = (U3478 >= 0 || U19302 >= 0)
    nudp = (U53 || U123 == 1) ? "UDP to STUN ports 3478/19302 gets no answer, only DNS/NTP do" : "no UDP answer on 3478, 19302, 123 or 53"
    tcpok = (TCP443 || UI_OK > 0)

    out("")
    out("== VPN on this connection (" KIND "): inferred from the rows above ==")
    if (PORTAL) { out("NO VPN until you log in: a Wi-Fi login page is in the way. Open Safari, log in, run again."); return }
    if (!inet) { out("NO VPN can work: nothing outside answers. Check Wi-Fi/LTE first (osi/run)."); return }

    # Teleport: WireGuard (UDP), brokered through the UniFi cloud (HTTPS), works behind NAT.
    if (!tested) v = untested()
    else if (!stun) v = "NO (likely): " nudp ". WireGuard is UDP-only; a TCP fallback for Teleport is not documented"
    else if (UI_CERT) v = "NO (likely): the network intercepts TLS to the UniFi cloud"
    else if (UI_OK < UI_N) v = "UNLIKELY: UniFi cloud not reachable over HTTPS"
    else v = "LIKELY: UDP out and back works (tested on STUN ports), UniFi cloud reachable"
    if (V6ONLY) v = v ". This connection is IPv6-only (IPv4 via NAT64): if Teleport fails, enable IPv6 on the home gateway WAN"
    out("- Teleport: " v)

    # WireGuard, OpenVPN UDP and UniFi Identity (it is WireGuard 51820 or OpenVPN 10118 to the console's public IP).
    if (!tested) v = untested()
    else if (!stun) v = "NO (likely): " nudp "; your server's port was not tested"
    else v = "POSSIBLE: UDP works on STUN ports 3478/19302 (often opened for video calls); your server's port (e.g. 51820) is not testable from here"
    out("- WireGuard, OpenVPN UDP, UniFi Identity (UDP): " v)

    if (UI_CERT) v = "UNLIKELY: TLS on 443 is intercepted here; a proxy like that usually breaks a non-HTTPS stream"
    else if (server != "" && SRV == "open") v = "LIKELY: TCP to " server ":" tcp " connects"
    else if (server != "" && SRV == "refused") v = "NO on port " tcp ": connection refused (nothing listens there, or a firewall rejects)"
    else if (server != "") v = "NO from here: TCP to " server ":" tcp " " (SRV == "timeout" ? "times out" : "fails")
    else if (tcpok) v = "LIKELY if the server listens on TCP 443 (other ports: run vpn/run-server)"
    else v = "NO: TCP 443 to 1.1.1.1 and to the UniFi cloud both fail"
    out("- OpenVPN TCP, UniFi Identity (OpenVPN TCP): " v)

    if (!tested) v = untested()
    else if (!stun) v = "NO (likely): " nudp "; UDP 500/4500 were not tested"
    else v = "UNKNOWN: needs UDP 500 and 4500, not testable without the server"
    out("- L2TP/IPsec: " v)

    if (CERT1 && !UI_CERT) out("Note: HTTPS to 1.1.1.1 has an untrusted certificate while the UniFi cloud is fine: 1.1.1.1 is intercepted or local on this network.")
    if (KIND == "wifi" && index(LINK_TXT, "cellular also up")) out("Note: cellular is also up. To test Wi-Fi alone, turn off Cellular Data and run again.")
    if (TUN != "") out("Note: a VPN looks connected (" TUN "): these results describe the VPN, not the network.")
    out("Own servers and UniFi Identity need a public IP at home, not CGNAT 100.64.0.0/10 (UniFi docs).")
    out("Teleport does not, but may need IPv6 on the home gateway WAN (UniFi docs).")
    out("Final check: open the VPN app on this connection. If it fails while the rows are OK, the cause is not this network.")
}

function untested() {
    if (UDPSKIP == "file") return "UNKNOWN: stun-req.bin and ntp-req.bin not found in " dir ", copy them next to vpn.awk"
    return "UNKNOWN: STUN names do not resolve, UDP not tested. Fix DNS first (osi/run)"
}

# ---------- helpers ----------

# Snip parameters left unfilled arrive as "${name}": treat them as not given.
function val(x) { return (x ~ /\$\{/) ? "" : x }

function platform(    m) {
    run("uname -m")
    m = (NL > 0) ? LINES[1] : ""
    if (m ~ /^(iPhone|iPad|iPod)/ || ENVIRON["HOME"] ~ /\/mobile\/Containers\//) return "blink"
    run("uname -s")
    if (NL > 0 && LINES[1] == "Darwin") return "macos"
    return "other"
}

# Folder with the request files: Blink iCloud scripts, ~/vpn, ~/tp, $HOME or the current folder.
function find_dir(    d, n, i) {
    n = split(ENVIRON["HOME"] "/iCloud/scripts " ENVIRON["HOME"] "/vpn " ENVIRON["HOME"] "/tp " ENVIRON["HOME"] " .", d, " ")
    for (i = 1; i <= n; i++) if (readable(d[i] "/stun-req.bin")) return d[i]
    return (PLAT == "blink") ? ENVIRON["HOME"] "/iCloud/scripts" : "."
}

function now() { run("date -u +%H:%M:%S"); return (NL > 0) ? LINES[1] : "??:??:??" }

# IPv4 of an interface from ifconfig, empty if none.
function if_ip(ifc,    i, f) {
    if (run("ifconfig " ifc) != 0) return ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[ \t]*inet [0-9]/) { split(LINES[i], f, " "); return f[2] }
    return ""
}

# Does the interface have a global IPv6 address (not link-local fe80::)?
function if_has6(ifc,    i) {
    if (run("ifconfig " ifc) != 0) return 0
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[ \t]*inet6 [0-9a-fA-F]/ && LINES[i] !~ /inet6 fe80/) return 1
    return 0
}

# "ip=..." line of a Cloudflare trace. Byte-safe: no regex on the reply.
function trace_ip(    i) {
    for (i = 1; i <= NL; i++) if (substr(LINES[i], 1, 3) == "ip=") return substr(LINES[i], 4)
    return ""
}

# Byte-safe tests on command output (index and ==, no regex).
function contains(s,    i) {
    for (i = 1; i <= NL; i++) if (index(LINES[i], s) > 0) return 1
    return 0
}

function line_is(s,    i) {
    for (i = 1; i <= NL; i++) if (LINES[i] == s) return 1
    return 0
}

function readable(f,    r, x) {
    r = (getline x < f)
    close(f)
    return (r >= 0)
}

# First IPv4 in "dig +short" output, empty if none.
function dig_first(cmd,    i) {
    if (run(cmd) != 0) return ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return LINES[i]
    return ""
}

function curl_err(rc) {
    if (rc == 6) return "name does not resolve (curl 6)"
    if (rc == 7) return "connect failed (curl 7)"
    if (rc == 28) return "timed out (curl 28)"
    if (rc == 35) return "TLS handshake failed (curl 35)"
    if (rc == 60) return "certificate not trusted (curl 60): TLS interception or login page"
    return "curl exit " rc
}

function first_line() { return (NL > 0) ? LINES[1] : "no output" }

function header(    d) {
    run("date -u +%Y-%m-%dT%H:%M:%SZ")
    d = (NL > 0) ? LINES[1] : "?"
    out("== VPN check: can a VPN connect over this connection? ==")
    out("connection: " KIND "  platform: " PLAT "  started: " d (server != "" ? "  server: " server ":" tcp : ""))
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

# Log in iCloud (Blink) or next to the request files (macOS), else next to the temp file.
# Like preflight: a failed "> file" in Blink still returns 0, so the file is read back.
function open_log(    stamp) {
    run("date -u +%Y%m%d-%H%M%S")
    stamp = (NL > 0) ? LINES[1] : "now"
    LOG = ""
    if (try_log(((PLAT == "blink") ? ENVIRON["HOME"] "/iCloud" : dir) "/vpn-" KIND "-" stamp ".txt")) return
    try_log(OUTDIR "/vpn-" KIND "-" stamp ".txt")
}

function try_log(f,    line) {
    if (system("echo vpn-log > " f " 2>&1") != 0) return 0
    line = ""
    getline line < f
    close(f)
    if (line != "vpn-log") return 0
    LOG = f
    printf "" > LOG
    close(LOG)
    return 1
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
        OUT = dirs[i] "/.vpn-out.txt"
        OUTDIR = dirs[i]
        if (system("echo vpn-ok > " OUT " 2>&1") != 0) continue
        line = ""
        getline line < OUT
        close(OUT)
        if (line == "vpn-ok") return 1
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
