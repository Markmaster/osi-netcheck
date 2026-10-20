# vpn.awk - can a VPN connect over the current connection (Wi-Fi or LTE)?
# Runs in the Blink Shell local shell (iPhone/iPad) and in macOS Terminal. Read-only, needs no server.
#
# Blink:  awk -f ~/iCloud/scripts/vpn.awk                                   (snip vpn/run)
#         awk -v server=HOME_IP -v tcp=PORT -f ~/iCloud/scripts/vpn.awk     (snip vpn/run-server)
# macOS:  awk -f ~/vpn/vpn.awk   (vpn.awk, stun-req.bin and ntp-req.bin from scripts/ in one folder)
#
# What a VPN needs from the network, tested without a server of your own:
#   internet and no Wi-Fi login page, UDP out and back (STUN 3478 and 19302, DNS 53, NTP 123),
#   HTTPS to the UniFi cloud without interception (Teleport, UniFi Identity), IPv6.
# Optional -v server=IP -v tcp=PORT: TCP connect to your own server (OpenVPN over TCP).
# UDP to your own server's port cannot be confirmed from the phone: WireGuard does not answer
# unknown packets. The VPN app is the final word; this script says what the network allows.
#
# Blink's local shell has no sh, so the logic is awk, as in osi.awk: each probe runs through
# system() with its output in a temp file, which awk then parses.

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
    internet()
    udp()
    ipv6()
    cloud()
    if (server != "") server_tcp()
    verdict()
    finish()
}

# ---------- link: Wi-Fi or LTE ----------

function link(    w, c, g, ifc, i) {
    LINK_OK = 1
    if (PLAT == "blink") {
        w = if_ip("en0"); c = if_ip("pdp_ip0")
        if (w == "" && if_has6("en0")) w = "IPv6 only"
        if (c == "" && if_has6("pdp_ip0")) c = "IPv6 only"
        if (w != "" && c != "") { KIND = "wifi"; LINK_TXT = "Wi-Fi " w ", cellular also up (" c "): iOS can move traffic to LTE if Wi-Fi is weak" }
        else if (w != "") { KIND = "wifi"; LINK_TXT = "Wi-Fi " w }
        else if (c != "") { KIND = "lte"; LINK_TXT = "LTE/cellular " c }
        else { KIND = "none"; LINK_TXT = "no IP on Wi-Fi (en0) or cellular (pdp_ip0)"; LINK_OK = 0 }
        return
    }
    if (PLAT == "macos") {
        run("route -n get default")
        g = ""; ifc = ""
        for (i = 1; i <= NL; i++) {
            if (LINES[i] ~ /gateway:/) { g = LINES[i]; sub(/^.*gateway: */, "", g) }
            if (LINES[i] ~ /interface:/) { ifc = LINES[i]; sub(/^.*interface: */, "", ifc) }
        }
        if (ifc == "") { KIND = "none"; LINK_TXT = "no default route"; LINK_OK = 0; return }
        if (ifc ~ /^(utun|ppp|ipsec)/) { KIND = "vpn"; LINK_TXT = "default route via " ifc ": a VPN is already on, turn it off for this test"; return }
        run("system_profiler SPAirPortDataType")
        KIND = has("Current Network Information:") ? "wifi" : "wired"
        if (g ~ /^172\.20\.10\./) KIND = "hotspot"
        LINK_TXT = (KIND == "hotspot" ? "iPhone hotspot (LTE), " : (KIND == "wifi" ? "Wi-Fi, " : "")) ifc " " if_ip(ifc) ", gateway " g
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
    PUB4 = ""
    if (HTTPS) PUB4 = trace_ip()
    if (rc == 60) CERT++
    row("L5", "HTTPS to 1.1.1.1", HTTPS ? "OK" : "FAIL", HTTPS ? "public IPv4 " (PUB4 != "" ? PUB4 : "?") : curl_err(rc))

    PORTAL = 0
    rc = run("curl -sS -m 6 -w \"\\nHTTPCODE %{http_code}\\n\" http://captive.apple.com/hotspot-detect.html")
    if (rc == 0 && has("^HTTPCODE 200$") && has("Success")) row("L7", "Wi-Fi login page", "OK", "none (Apple probe answers Success)")
    else if (rc == 0) { PORTAL = 1; row("L7", "Wi-Fi login page", "PORTAL", "Apple probe answered something else: log in via Safari first") }
    else row("L7", "Wi-Fi login page", "FAIL", "Apple probe: " curl_err(rc))
}

# ---------- UDP out and back ----------

function udp() {
    U3478 = udp_probe("stun.cloudflare.com", 3478, "stun-req.bin", "STUN")
    U19302 = udp_probe("stun.l.google.com", 19302, "stun-req.bin", "STUN")
    U123 = udp_probe("time.apple.com", 123, "ntp-req.bin", "NTP")
    U53 = (dig_first("dig @1.1.1.1 example.com +short +time=2 +tries=1") != "")
    row("L4", "UDP 53 DNS to 1.1.1.1", U53 ? "OK" : "FAIL", U53 ? "answer received" : "no answer")
}

# Send a small request file over UDP, wait 2 s. Any answer = UDP goes out and comes back on this port.
# Returns 1 answered, 0 no answer, -1 not tested (request file missing or the name does not resolve).
function udp_probe(host, port, file, what,    i, err) {
    if (!readable(dir "/" file)) { row("L4", "UDP " port " " what, "SKIP", file " not found in " dir); return -1 }
    run("nc -u -w 2 " host " " port " < " dir "/" file)
    err = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^(nc|netcat): /) err = LINES[i]
    if (err ~ /getaddrinfo|nodename|not known|resolve/) { row("L4", "UDP " port " " what, "SKIP", host " does not resolve: DNS problem, UDP not tested"); return -1 }
    if (err != "") { row("L4", "UDP " port " " what, "FAIL", err); return 0 }
    if (NL > 0) { row("L4", "UDP " port " " what, "OK", host " answered"); return 1 }
    row("L4", "UDP " port " " what, "FAIL", host ": no answer in 2 s")
    return 0
}

# ---------- IPv6 ----------

function ipv6(    rc) {
    rc = run("curl -6 -sS -m 6 https://one.one.one.one/cdn-cgi/trace")
    PUB6 = (rc == 0) ? trace_ip() : ""
    row("L3", "IPv6 to the internet", PUB6 != "" ? "OK" : "NONE", PUB6 != "" ? PUB6 : "no IPv6 path (" curl_err(rc) ")")
}

# ---------- UniFi cloud (Teleport, UniFi Identity) ----------

function cloud(    n, h, i, rc) {
    UI_N = 0; UI_OK = 0
    n = split("unifi.ui.com api.ui.com", h, " ")
    for (i = 1; i <= n; i++) {
        UI_N++
        rc = run("curl -sS -o /dev/null -m 8 -w \"HTTP %{http_code}, %{remote_ip}\\n\" https://" h[i] "/")
        if (rc == 0) { UI_OK++; row("L5", "HTTPS " h[i], "OK", first_line()) }
        else if (rc == 60) { CERT++; row("L5", "HTTPS " h[i], "CERT", "certificate not trusted: the network intercepts TLS") }
        else row("L5", "HTTPS " h[i], "FAIL", curl_err(rc))
    }
}

# ---------- optional: TCP to your own server ----------

function server_tcp(    rc) {
    rc = run("nc -zv -G 3 " server " " tcp)
    if (rc == 0) SRV = "open"
    else if (has("refused")) SRV = "refused"
    else if (has("timed out")) SRV = "timeout"
    else SRV = "error"
    row("L4", "TCP " server ":" tcp, SRV == "open" ? "OK" : "FAIL", SRV == "open" ? "connected" : (SRV == "refused" ? "refused: an RST came back (server or a firewall), nothing accepts on this port" : (SRV == "timeout" ? "timed out: blocked on the way or by the server firewall" : first_line())))
}

# ---------- verdict: an inference from the rows above ----------

function verdict(    inet, anyport, tested, wk, v, nudp) {
    inet = (TCP443 || HTTPS || U3478 == 1 || U19302 == 1 || U53 || U123 == 1)
    anyport = (U3478 == 1 || U19302 == 1)
    tested = (U3478 >= 0 || U19302 >= 0)
    wk = (U53 || U123 == 1)
    nudp = "UDP " (wk ? "only to DNS/NTP ports" : "blocked")

    out("")
    out("== VPN on this connection (" KIND "): inferred from the rows above ==")
    if (!inet) { out("NO VPN can work: nothing outside answers. Check Wi-Fi/LTE first (osi/run)."); return }
    if (PORTAL) { out("NO VPN until you log in: a Wi-Fi login page is in the way. Open Safari, log in, run again."); return }

    # Teleport and UniFi Identity: WireGuard (UDP) brokered through the UniFi cloud (HTTPS).
    if (!tested) v = "UNKNOWN: STUN names do not resolve, UDP not tested. Fix DNS first (osi/run)"
    else if (!anyport) v = "NO (likely): " nudp ". WireGuard is UDP-only; a TCP fallback for Teleport is not documented"
    else if (CERT) v = "NO (likely): the network intercepts TLS, the UniFi cloud login fails"
    else if (UI_OK < UI_N) v = "UNLIKELY: UniFi cloud not reachable over HTTPS"
    else v = "LIKELY: UDP out and back works, UniFi cloud reachable"
    out("- Teleport / UniFi Identity: " v)

    if (!tested) v = "UNKNOWN: UDP not tested (DNS)"
    else if (!anyport) v = "NO: " nudp
    else v = "LIKELY: UDP to non-standard ports works. Your server's port itself is not testable from here"
    out("- WireGuard, OpenVPN over UDP: " v)

    if (server != "" && SRV == "open") v = "LIKELY: TCP to " server ":" tcp " connects"
    else if (server != "" && SRV == "refused") v = "NO on port " tcp ": connection refused (nothing listens there, or a firewall rejects)"
    else if (server != "") v = "NO from here: TCP to " server ":" tcp " " (SRV == "timeout" ? "times out" : "fails")
    else if (TCP443) v = "LIKELY if the server listens on TCP 443 (other ports: run vpn/run-server)"
    else v = "NO: outbound TCP 443 is blocked"
    out("- OpenVPN over TCP: " v)

    if (!tested) v = "UNKNOWN: UDP not tested (DNS)"
    else if (!anyport) v = "NO: " nudp
    else v = "UNKNOWN: needs UDP 500 and 4500, not testable without the server"
    out("- L2TP/IPsec: " v)

    if (KIND == "wifi" && LINK_TXT ~ /cellular also up/) out("Note: cellular is also up. To test Wi-Fi alone, turn off Cellular Data and run again.")
    if (KIND == "vpn") out("Note: a VPN is already on: these results describe the VPN, not the network.")
    out("Own WireGuard/OpenVPN/L2TP servers also need a public IP at home (UniFi docs); Teleport does not.")
    out("Final check: open the VPN app on this connection. If it fails while the rows are OK, the cause is not this network.")
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

function trace_ip(    i, s) {
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^ip=/) { s = LINES[i]; sub(/^ip=/, "", s); return s }
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
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return LINES[i]
    return ""
}

function curl_err(rc) {
    if (rc == 6) return "name does not resolve (curl 6)"
    if (rc == 7) return "connect failed (curl 7)"
    if (rc == 28) return "timed out (curl 28)"
    if (rc == 35) return "TLS handshake failed (curl 35)"
    if (rc == 60) return "certificate not trusted (curl 60): TLS interception or login page"
    return "curl exit " rc ": " first_line()
}

function first_line() { return (NL > 0) ? LINES[1] : "no output" }

function header(    d) {
    run("date -u +%Y-%m-%dT%H:%M:%SZ")
    d = (NL > 0) ? LINES[1] : "?"
    out("== VPN check: can a VPN connect over this connection? ==")
    out("connection: " KIND "  platform: " PLAT "  started: " d (server != "" ? "  server: " server ":" tcp : ""))
    if (LOG != "") out("log: " LOG)
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
function open_log(    d, stamp, f) {
    run("date -u +%Y%m%d-%H%M%S")
    stamp = (NL > 0) ? LINES[1] : "now"
    d = (PLAT == "blink") ? ENVIRON["HOME"] "/iCloud" : dir
    f = d "/vpn-" KIND "-" stamp ".txt"
    if (system("echo > " f " 2>/dev/null") == 0) { LOG = f; printf "" > LOG; close(LOG); return }
    f = OUTDIR "/vpn-" KIND "-" stamp ".txt"
    if (system("echo > " f " 2>/dev/null") == 0) { LOG = f; printf "" > LOG; close(LOG); return }
    LOG = ""
}

function finish() {
    if (LOG != "") { close(LOG); print ""; print "Saved: " LOG }
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

# Does any output line match the regular expression?
function has(re,    i) {
    for (i = 1; i <= NL; i++) if (LINES[i] ~ re) return 1
    return 0
}
