# vpn.awk - can a VPN connect over the current connection (Wi-Fi or LTE)?
# Runs in the Blink Shell local shell (iPhone/iPad) and in macOS Terminal. Read-only, needs no server.
#
# Blink:  awk -f ~/iCloud/scripts/vpn.awk                                   (snip vpn/run)
#         awk -v server=HOME_IP -v tcp=PORT -f ~/iCloud/scripts/vpn.awk     (snip vpn/run-server)
# macOS:  awk -f ~/vpn/vpn.awk   (vpn.awk, stun-req.bin and ntp-req.bin from scripts/ in one folder)
#
# What a VPN needs from the network, tested without a server of your own: internet and no
# login page, UDP out and back (STUN 3478 and 19302, NTP 123, DNS 53 to 1.1.1.1), HTTPS
# to the UniFi cloud without interception (Teleport). IPv6 is shown for context.
# Optional -v server=IP -v tcp=PORT: TCP connect to your own server (OpenVPN over TCP).
# Optional -v home_ip=IP: your home WAN IPv4. If the run exits there, a router-level Teleport/VPN
# carries the traffic (row "traffic exits at home WAN"), and home-resolver answers are INFO, not HIJACK.
# Optional -v ladder=1 (macOS only): DF ping ladder, sizes up to the Wi-Fi MTU, to look for a path MTU hole.
# UDP to your own server's port cannot be confirmed from the phone: WireGuard does not answer
# unknown packets. The VPN app is the final word; this script says what the network allows.
#
# Blink's local shell has no sh, so the logic is awk, as in osi.awk: each probe runs through
# system() with its output in a temp file, which awk then parses. Replies from the network
# (UDP answers, web pages) are only compared with index() and ==: Blink's awk aborts when a
# regex meets a byte that is not valid UTF-8.
#
# Names are resolved once each (resolve(): dig, 3 s cap) and handed to curl/nc/ping as addresses, so
# a broken system resolver costs 3 s per name, not 30 s per row. Every row clobbers LINES/NL (row()
# runs date): read command output before calling row(), not after.

BEGIN {
    server = val(server); tcp = val(tcp); dir = val(dir); home_ip = val(home_ip); ladder = val(ladder)
    if (ladder == "0") ladder = ""
    if (home_ip != "" && home_ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print "home_ip=\"" home_ip "\" is not an IPv4 address"; exit 2 }
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

    # A link that ifconfig/route did not recognise is judged after the probes (link_late).
    if (LINK_OK) row("L2", "connection", "OK", LINK_TXT)
    dns()
    internet()
    if (!LINK_OK) link_late()
    home_egress()
    vpn_on()
    udp()
    ipv6()
    icmp()
    cloud()
    if (ladder != "") df_ladder()
    if (server != "") server_tcp()
    verdict()
    finish()
}

# ---------- link: Wi-Fi or LTE ----------

function link(    w, c, g, ifc, i, cur, f, wdev) {
    LINK_OK = 1; HAS4 = 1; V6ONLY = 0; TUN = ""; TUNSKIP = ""; TSNET = ""; LINKDEV = ""; GW = ""; MACIF = ""
    if (PLAT == "blink") {
        w = if_ip("en0"); c = if_ip("pdp_ip0")
        if (w ~ /^169\.254\./) w = ""
        if (w == "" && if_has6("en0")) w = "IPv6 only"
        if (c == "" && if_has6("pdp_ip0")) c = "IPv6 only"
        CELLUP = (w != "" && c != "")
        if (w != "" && c != "") { KIND = "wifi"; LINK_TXT = "Wi-Fi " w ", cellular also up (" c "): iOS can move traffic to LTE if Wi-Fi is weak" }
        else if (w != "") { KIND = "wifi"; LINK_TXT = "Wi-Fi " w }
        else if (c != "") { KIND = "lte"; LINK_TXT = "LTE/cellular " c }
        else { KIND = "none"; LINK_TXT = "no IP on Wi-Fi (en0) or cellular (pdp_ip0)"; LINK_OK = 0 }
        LINKDEV = (KIND == "wifi") ? "en0" : (KIND == "lte" ? "pdp_ip0" : "")
        if ((KIND == "wifi" && w == "IPv6 only") || (KIND == "lte" && c == "IPv6 only")) { V6ONLY = 1; HAS4 = 0 }
        if ((KIND == "wifi" && w ~ /^192\.0\.0\./) || (KIND == "lte" && c ~ /^192\.0\.0\./)) { V6ONLY = 1; LINK_TXT = LINK_TXT " (IPv6-only network, IPv4 via CLAT/NAT64)" }
        # A connected iOS VPN can show up as a utun/ipsec/ppp interface with an IPv4 address.
        # 192.0.0.x is skipped: iOS puts such addresses on utun0 by itself (seen on an iPhone with
        # no VPN on, public IP still the carrier's), like the 192.0.0.2 CLAT address on pdp_ip0.
        # 100.64.0.0/10 on a utun is Tailscale-like (CGNAT range): kept apart in TSNET, it does not make
        # the rows "describe a VPN" by itself. On 2026-10-20 a full-tunnel VPN went unseen here, so
        # vpn_on() also compares egress IPs.
        run("ifconfig")
        cur = ""
        for (i = 1; i <= NL; i++) {
            if (LINES[i] ~ /^[A-Za-z][A-Za-z0-9_]*:/) { cur = LINES[i]; sub(/:.*$/, "", cur) }
            else if (cur ~ /^(utun|ipsec|ppp)/ && LINES[i] ~ /^[ \t]*inet [0-9]/) {
                split(LINES[i], f, " ")
                if (f[2] ~ /^192\.0\.0\./) TUNSKIP = TUNSKIP (TUNSKIP != "" ? ", " : "") cur " " f[2]
                else if (is_cgnat(f[2])) TSNET = TSNET (TSNET != "" ? ", " : "") cur " " f[2]
                else TUN = TUN (TUN != "" ? ", " : "") cur " " f[2]
            }
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
        GW = g; MACIF = ifc
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

# ---------- DNS: three ways to resolve one name, each capped at 3 s ----------

# Row 1 is the system resolver (what apps use: getaddrinfo, via curl). Rows 2 and 3 are raw UDP 53
# with dig: the gateway (macOS) or the configured server (Blink has no route command), and 1.1.1.1.
# Where the break is: system fails and raw works means the system resolver path, not the network.
function dns(    rc, t, i, ms, srv, ok2, ok3, nm) {
    DNS_NAME = "example.com"
    # Port 1 refuses at once after the lookup; time_namelookup stays 0 if the lookup itself failed.
    rc = run("curl -sS -m 3 -o /dev/null -w \"%{time_namelookup}\\n\" http://" DNS_NAME ":1/")
    t = 0
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[0-9]+\.[0-9]+$/) t = LINES[i] + 0
    DNS_SYS = (t > 0)
    if (DNS_SYS) row("L7", "DNS system resolver", "OK", DNS_NAME " resolves in " int(t * 1000 + 0.5) " ms")
    else if (rc == 6) row("L7", "DNS system resolver", "FAIL", DNS_NAME " fails at once (curl 6): the system resolver answers no")
    else row("L7", "DNS system resolver", "FAIL", DNS_NAME ": no answer in 3 s (cap; a dead resolver took 30 s per name on 2026-10-21)")

    ok2 = 0
    srv = GW
    if (PLAT == "macos" && srv == "") row("L7", "DNS dig @gateway", "SKIP", "no gateway known (no route to the internet)")
    else {
        dig_q(srv, DNS_NAME, "")
        nm = (srv != "") ? "dig @" srv " (gateway)" : "dig, configured server" (DIG_SRV != "" ? " " DIG_SRV : "")
        ok2 = (DIG_IP != "")
        if (ok2) row("L7", "DNS " nm, "OK", DNS_NAME " -> " DIG_IP (DIG_MS != "" ? " in " DIG_MS " ms" : ""))
        else if (DIG_RC == 0) row("L7", "DNS " nm, "FAIL", "answered, but no address for " DNS_NAME)
        else row("L7", "DNS " nm, "FAIL", "no answer in 3 s")
    }

    dig_q("1.1.1.1", DNS_NAME, "")
    ok3 = (DIG_IP != "")
    if (ok3) row("L7", "DNS dig @1.1.1.1", "OK", DNS_NAME " -> " DIG_IP (DIG_MS != "" ? " in " DIG_MS " ms" : ""))
    else if (DIG_RC == 0) row("L7", "DNS dig @1.1.1.1", "FAIL", "answered, but no address for " DNS_NAME)
    else row("L7", "DNS dig @1.1.1.1", "FAIL", "no answer in 3 s")

    DNS_RAW = (ok2 || ok3)
    if (!DNS_SYS && DNS_RAW) row("L7", "DNS reading", "WARN", "system lookups fail while raw UDP 53 answers: the break is in the system resolver path (profile, app, encrypted DNS, upstream). This script cannot tell which; the rows below use dig answers instead")
    else if (!DNS_SYS && !DNS_RAW) row("L7", "DNS reading", "FAIL", "no name resolves by any path here")
}

# One dig query, 3 s cap, one try. srv "" = configured server. Sets DIG_IP, DIG_MS, DIG_SRV, DIG_RC.
# type "" = A, "AAAA" = IPv6. dig prints text, so a regex is safe here.
function dig_q(srv, name, type,    i, n, f, w, a) {
    DIG_IP = ""; DIG_MS = ""; DIG_SRV = ""
    DIG_RC = run("dig " (srv != "" ? "@" srv " " : "") name (type != "" ? " " type : "") " +noall +answer +stats +time=3 +tries=1")
    for (i = 1; i <= NL; i++) {
        w = LINES[i]
        if (index(w, ";; Query time: ") == 1) { DIG_MS = substr(w, length(";; Query time: ") + 1); sub(/ .*$/, "", DIG_MS) }
        else if (index(w, ";; SERVER: ") == 1) { DIG_SRV = substr(w, length(";; SERVER: ") + 1); sub(/#.*$/, "", DIG_SRV) }
        else if (substr(w, 1, 1) != ";" && DIG_IP == "") {
            n = split(w, f, /[ \t]+/)
            a = f[n]
            if (n >= 5 && (type == "AAAA" ? (a ~ /^[0-9a-fA-F:]+$/ && index(a, ":") > 0) : a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) DIG_IP = a
        }
    }
    return DIG_IP
}

# Resolve a host once: the configured server first, then 1.1.1.1 once the configured one timed out
# (and for every later name: DNSDEAD). Cached; callers pass the address to curl --resolve, nc, ping.
# An answer without an address (no AAAA, say) is final: it is not asked again elsewhere.
function resolve(host, type,    k, ip, ms) {
    k = host " " type
    if (k in RES) return RES[k]
    ip = ""; ms = ""
    if (!DNSDEAD) {
        dig_q("", host, type)
        ip = DIG_IP; ms = DIG_MS
        if (ip == "" && DIG_RC != 0) DNSDEAD = 1
    }
    if (ip == "" && DNSDEAD) { dig_q("1.1.1.1", host, type); ip = DIG_IP; ms = DIG_MS }
    RES[k] = ip; RESMS[k] = ms
    return ip
}

# ---------- internet and login page ----------

function internet(    rc, ip) {
    TCP443 = (run("nc -z -G 3 1.1.1.1 443") == 0)
    row("L4", "TCP 443 to 1.1.1.1", TCP443 ? "OK" : "FAIL", TCP443 ? "connected" : "no connection")

    https_probe("1.1.1.1", "/cdn-cgi/trace", 1, TCP443 ? 3 : 1)
    HTTPS = P_OK
    PUB4 = HTTPS ? P_IP : ""
    CERT1 = (P_STAGE == "cert")
    row("L5", "HTTPS to 1.1.1.1 (control)", probe_word(), (HTTPS ? "public IPv4 " (PUB4 != "" ? PUB4 : "?") "; " : "") P_DETAIL)

    PORTAL = 0
    ip = resolve("captive.apple.com", "")
    if (ip == "") { row("L7", "login page (Apple probe)", "FAIL", "captive.apple.com does not resolve (dig, 3 s cap): login page not tested"); return }
    rc = run("curl -sS -m 6 --resolve captive.apple.com:80:" ip " -w \"\\nHTTPCODE %{http_code}\\n\" http://captive.apple.com/hotspot-detect.html")
    if (rc == 0 && line_is("HTTPCODE 200") && contains("Success")) row("L7", "login page (Apple probe)", "OK", "none (Apple probe answers Success)")
    else if (rc == 0) { PORTAL = 1; row("L7", "login page (Apple probe)", "PORTAL", "Apple probe answered something else: log in via Safari first") }
    else row("L7", "login page (Apple probe)", "FAIL", "Apple probe: " curl_err(rc))
}

# HTTPS GET with stage times (curl -w), up to `tries` attempts, stopping at the first success. The
# name comes from resolve() and goes in with --resolve, so curl does no DNS of its own. Stage of a
# failed attempt: dns (no address), tcp (no connect), cert, tls (connected, handshake not finished:
# with curl 28 a hang, the MTU/MSS pattern), http (TLS done, no answer). `keep` = keep the body in
# LINES (Cloudflare trace). Sets P_OK, P_STAGE, P_RC, P_DETAIL, P_IP.
function https_probe(host, path, keep, tries,    isip, ip, a, rc, i, f, have, tc, ta, tt, code, st, hist, prev, rest) {
    isip = (host ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
    P_OK = 0; P_STAGE = ""; P_RC = 0; P_DETAIL = ""; P_IP = ""
    ip = isip ? host : resolve(host, "")
    if (ip == "") { P_STAGE = "dns"; P_DETAIL = host " does not resolve (dig, 3 s cap): TCP and TLS not tested"; return 0 }
    hist = ""
    for (a = 1; a <= tries; a++) {
        rc = run("curl -sS -m 6 " (keep ? "" : "-o /dev/null ") (isip ? "" : "--resolve " host ":443:" ip " ") "-w \"\\nSTAGES %{time_connect} %{time_appconnect} %{time_total} %{http_code}\\n\" https://" host path)
        have = 0; tc = 0; ta = 0; tt = 0; code = ""
        for (i = 1; i <= NL; i++) if (index(LINES[i], "STAGES ") == 1) { split(LINES[i], f, " "); have = 1; tc = f[2] + 0; ta = f[3] + 0; tt = f[4] + 0; code = f[5] }
        if (keep && rc == 0) P_IP = trace_ip()
        if (rc == 0) st = "ok"
        else if (!have) st = "curl"
        else if (rc == 60) st = "cert"
        else if (tc == 0) st = "tcp"
        else if (ta == 0) st = "tls"
        else st = "http"
        prev = hist; hist = hist (hist != "" ? ", " : "") st
        P_RC = rc; P_STAGE = st
        if (st == "ok" || st == "cert") break
    }
    if (st == "ok") {
        P_OK = 1
        P_DETAIL = "HTTP " code ", dns " (isip ? "-" : (RESMS[host " "] != "" ? RESMS[host " "] " ms" : "?")) ", tcp " fmt(tc) ", tls " fmt(ta - tc) ", total " fmt(tt) (a > 1 ? " (attempt " a " of " tries "; earlier: " prev ")" : "")
        return 1
    }
    if (a > tries) a = tries
    rest = (tries > 1 ? " in " a " tries (" hist ")" : "")
    if (st == "tcp") P_DETAIL = "no TCP connect" rest ": " curl_err(rc)
    else if (st == "tls" && rc == 28) P_DETAIL = "TCP connect ok (" fmt(tc) "), then TLS hangs" rest ": MTU/MSS suspect, not 'unreachable'"
    else if (st == "tls") P_DETAIL = "TCP connect ok (" fmt(tc) "), TLS fails" rest ": " curl_err(rc)
    else if (st == "cert") P_DETAIL = "certificate not trusted: the network intercepts TLS (or a login page answers)"
    else if (st == "http") P_DETAIL = "TCP and TLS ok (" fmt(ta) "), no HTTP answer" rest ": " curl_err(rc)
    else P_DETAIL = "curl could not run the request: " curl_err(rc)
    return 0
}

function probe_word() {
    if (P_OK) return "OK"
    if (P_STAGE == "cert") return "CERT"
    if (P_STAGE == "tls" && P_RC == 28) return "HANG"
    return "FAIL"
}

function fmt(x) { return sprintf("%.2f s", x) }

# Late verdict on the L2 row: ifconfig/route found no link, but did the probes get through?
function link_late() {
    if (TCP443 || HTTPS) row("L2", "connection", "WARN", LINK_TXT ", yet the internet answers" (PUB4 != "" ? " (public IPv4 " PUB4 ")" : "") ": link detection missed it, trust the rows below")
    else row("L2", "connection", "FAIL", LINK_TXT)
}

# -v home_ip=IP: does this run exit at the home WAN? Then Teleport (or another VPN) carries it, even
# when it runs on the router and this device sees no tunnel.
function home_egress() {
    HOME_EGRESS = 0
    if (home_ip == "") return
    if (PUB4 == "") row("L3", "traffic exits at home WAN", "SKIP", "no public IPv4 measured")
    else if (PUB4 == home_ip) { HOME_EGRESS = 1; row("L3", "traffic exits at home WAN", "YES", "public IPv4 " PUB4 " = home_ip: Teleport carrying traffic") }
    else row("L3", "traffic exits at home WAN", "NO", "public IPv4 " PUB4 " is not " home_ip ": no tunnel to home on this path")
}

# Is a VPN carrying the traffic? Blink: tunnel addresses from link(), and the egress IPv4 of the
# default path vs a request bound to the link itself (en0 or pdp_ip0). A different /16 means a VPN
# diverts traffic, or, on Wi-Fi with cellular up, that iOS sends it over LTE (checked via pdp_ip0).
# Binding works only if the VPN lets apps use the link (not with enforced routes). If the bound
# request itself fails, the default path is not that link: said out loud, not skipped.
function vpn_on(    ip, ipc, lte, nm, other) {
    lte = ""; BOUND = 0
    if (PLAT == "blink" && LINKDEV != "" && PUB4 != "") {
        ip = egress(LINKDEV)
        if (ip == "") {
            if (EGRC == 2 || EGRC == 45) row("L2", "path", "INFO", "curl cannot bind to " LINKDEV " (curl " EGRC "): egress comparison skipped, VPN detection rests on the interface scan")
            else {
                nm = (LINKDEV == "en0") ? "Wi-Fi" : "Cellular"
                other = (LINKDEV == "en0") ? "LTE/VPN" : "Wi-Fi/VPN"
                row("L2", "path", "WARN", nm " itself has no internet, this run uses another path (" other "): a request bound to " LINKDEV " failed: " curl_err(EGRC))
            }
        }
        else {
            BOUND = 1
            if (!same16(ip, PUB4)) {
                ipc = (LINKDEV == "en0" && CELLUP) ? egress("pdp_ip0") : ""
                if (ipc != "" && same16(ipc, PUB4)) lte = "traffic leaves over LTE (" PUB4 "), not Wi-Fi (" ip ")"
                else TUN = (TUN != "" ? TUN ", " : "") "traffic exits at " PUB4 ", " LINKDEV " itself at " ip (TSNET != "" ? " (" TSNET " is up: an exit node?)" : "")
            }
        }
    }
    if (TUN != "") row("L2", "VPN already on?", "WARN", TUN ": a VPN looks connected, the rows below then describe the VPN. Turn it off and run again")
    else if (HOME_EGRESS) row("L2", "VPN already on?", "INFO", "no tunnel seen on this device" (BOUND ? " (" LINKDEV " itself exits at the same place)" : "") "; the exit is the home WAN, so a router-level Teleport/VPN carries the traffic and the rows describe that path")
    else if (PLAT == "blink") row("L2", "VPN already on?", "OK", "none seen" (TUNSKIP != "" ? " (" TUNSKIP " skipped: iOS sets 192.0.0.x itself)" : "") (TSNET != "" ? " (" TSNET " is 100.64.0.0/10, Tailscale-like" (BOUND ? ": egress matches " LINKDEV ", so the rows describe the network)" : ": egress not compared)") : ""))
    if (lte != "") row("L2", "path", "WARN", lte ": this run tests LTE. Turn off Cellular Data to test Wi-Fi")
}

# Public IPv4 of a request bound to one interface, empty if that fails (curl exit code in EGRC).
function egress(dev) {
    EGRC = run("curl -sS -m 6 --interface " dev " https://1.1.1.1/cdn-cgi/trace")
    return (EGRC == 0) ? trace_ip() : ""
}

function is_cgnat(x,    a) {
    split(x, a, ".")
    return (a[1] == 100 && a[2] >= 64 && a[2] <= 127)
}

function same16(x, y,    a, b) {
    split(x, a, "."); split(y, b, ".")
    return (a[1] == b[1] && a[2] == b[2])
}

# ---------- UDP out and back ----------

function udp(    a, i, s, t) {
    FAM = HAS4 ? "-4" : "-6"
    FAMTXT = HAS4 ? "IPv4" : "IPv6"
    UDPSKIP = ""
    U3478 = udp_probe("stun.cloudflare.com", 3478, "stun-req.bin", "STUN")
    U19302 = udp_probe("stun.l.google.com", 19302, "stun-req.bin", "STUN")
    U123 = udp_probe("time.apple.com", 123, "ntp-req.bin", "NTP")

    # UDP 53, transport only: does a DNS answer come back over UDP at all. Only Cloudflare answers
    # id.server (CHAOS TXT) with its site code ("sea07" on an iPhone 2026-10-20, "SJC" in older docs:
    # 3 letters, optional digits, any case), so a network that answers DNS itself is not counted as
    # "UDP 53 reaches the internet". Who answers is INFO when the run exits at home_ip (the home
    # resolver behind Teleport), HIJACK otherwise.
    run("dig @1.1.1.1 CH TXT id.server +short +time=3 +tries=1")
    s = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^"[A-Za-z][A-Za-z][A-Za-z][0-9]*"$/) s = LINES[i]
    U53 = (s != "")
    t = "UDP 53 DNS to 1.1.1.1 (transport only)"
    if (U53) row("L4", t, "OK", "Cloudflare answered (" s ")")
    else {
        a = dig_first("dig @1.1.1.1 example.com +short +time=3 +tries=1")
        if (a == "") row("L4", t, "FAIL", "no answer")
        else {
            # Only Control D answers verify.controld.com with 147.185.34.1 (as in osi.awk). An iOS DNS
            # profile does not catch "dig @1.1.1.1" (iPhone 2026-10-20, Control D profile on): a router does.
            run("dig @1.1.1.1 verify.controld.com +short +time=3 +tries=1")
            if (line_is("147.185.34.1")) {
                if (HOME_EGRESS) row("L4", t, "INFO", "answered by Control D, not Cloudflare; the run exits at the home WAN, so this is the home resolver (ctrld on the gateway) behind Teleport")
                else row("L4", t, "HIJACK", "answered by Control D, not Cloudflare: the router or an app on this device redirects DNS to Control D")
            }
            else if (HOME_EGRESS) row("L4", t, "INFO", "answered, but not by Cloudflare; the run exits at the home WAN, so the home network answers DNS")
            else row("L4", t, "HIJACK", "answered, but not by Cloudflare: the network or a VPN-mode DNS app answers DNS itself (a DNS profile does not)")
        }
    }
}

# Send a small request file over UDP, wait 2 s. Any answer = UDP goes out and comes back on this port.
# Returns 1 answered, 0 no answer, -1 not tested (UDPSKIP says why: file or dns).
function udp_probe(host, port, file, what,    i, err, t, ip) {
    t = "UDP " port " " what " (" FAMTXT ")"
    if (!readable(dir "/" file)) { row("L4", t, "SKIP", file " not found in " dir); UDPSKIP = "file"; return -1 }
    ip = resolve(host, HAS4 ? "" : "AAAA")
    if (ip == "") { row("L4", t, "SKIP", host " does not resolve (dig, 3 s cap): DNS problem, UDP not tested"); if (UDPSKIP == "") UDPSKIP = "dns"; return -1 }
    run("nc " FAM " -u -w 2 " ip " " port " < " dir "/" file)
    err = ""
    for (i = 1; i <= NL; i++) if (index(LINES[i], "nc: ") == 1 || index(LINES[i], "netcat: ") == 1) err = LINES[i]
    if (err != "") { row("L4", t, "FAIL", err); return 0 }
    if (NL > 0) { row("L4", t, "OK", host " answered"); return 1 }
    row("L4", t, "FAIL", host ": no answer in 2 s")
    return 0
}

# ---------- IPv6 ----------

function ipv6(    rc, ip) {
    ip = resolve("one.one.one.one", "AAAA")
    if (ip == "") { PUB6 = ""; V6DROP = 0; row("L3", "IPv6 to the internet", "NONE", "no IPv6 address for one.one.one.one (dig AAAA, 3 s cap)"); return }
    rc = run("curl -6 -sS -m 6 --resolve \"one.one.one.one:443:[" ip "]\" https://one.one.one.one/cdn-cgi/trace")
    PUB6 = (rc == 0) ? trace_ip() : ""
    V6DROP = (PUB6 == "" && rc == 28 && LINKDEV != "" && if_has6(LINKDEV))
    if (PUB6 != "") row("L3", "IPv6 to the internet", "OK", PUB6)
    else if (V6DROP) row("L3", "IPv6 to the internet", "FAIL", LINKDEV " has IPv6 but nothing answers in 6 s: dropped (a VPN without IPv6, or a filter)")
    else row("L3", "IPv6 to the internet", "NONE", (rc == 6 || rc == 7) ? "no IPv6 on this connection" : curl_err(rc))
}

# ---------- ICMP: what a UniFi Travel Router checks ----------

# The UTR's internet check is ICMP only (firmware 6.6.115-6.6.122): one of 1.1.1.1, 8.8.8.8,
# www.microsoft.com must answer ping, or it shows "No Internet". Since 6.6.117 its Teleport client
# then waits for WAN and never connects; its WireGuard client waits too, OpenVPN does not.
function icmp(    n, t, i, f, tg, miss, via) {
    ICMP_OK = 0; f = 0; miss = ""; ICMP_SKIP = !HAS4
    if (ICMP_SKIP) { row("L3", "ping 1.1.1.1, 8.8.8.8, www.microsoft.com", "SKIP", "no IPv4 on this link"); return }
    n = split("1.1.1.1 8.8.8.8 www.microsoft.com", t, " ")
    for (i = 1; i <= n; i++) {
        tg = t[i]
        if (tg !~ /^[0-9]/) { tg = resolve(tg, ""); if (tg == "") { miss = t[i]; continue } }
        if (run("ping -c 2 -W 2000 " tg) == 0) ICMP_OK++
        else if (contains("prohibited")) f = 1
    }
    via = HOME_EGRESS ? " (these pings went through Teleport to home: they say nothing about the uplink's ICMP)" : ""
    if (ICMP_OK) row("L3", "ping 1.1.1.1, 8.8.8.8, www.microsoft.com", "OK", ICMP_OK "/" n " reply" (miss != "" ? ", " miss " did not resolve" : "") via)
    else row("L3", "ping 1.1.1.1, 8.8.8.8, www.microsoft.com", "FAIL", (f ? "prohibited by filter" : "no reply") ": the network drops ICMP" (miss != "" ? " (" miss " did not resolve)" : "") via)
}

# ---------- UniFi cloud (Teleport brokering) ----------

# unifi.ui.com and api.ui.com decide the Teleport verdict. www.theverge.com and
# controlplane.tailscale.com are extra hosts with big TLS handshakes: with the control (1.1.1.1) they
# tell an MTU/MSS hole ("TCP connects, TLS hangs") from a host that is simply down.
function cloud(    n, h, i) {
    UI_N = 0; UI_OK = 0; UI_CERT = 0; UI_TLS = 0; UI_TCP = 0; UI_DNS = 0; HANGS = 0
    n = split("unifi.ui.com api.ui.com www.theverge.com controlplane.tailscale.com", h, " ")
    for (i = 1; i <= n; i++) {
        https_probe(h[i], "/", 0, 3)
        row("L5", "HTTPS " h[i], probe_word(), P_DETAIL)
        if (P_STAGE == "tls" && P_RC == 28) HANGS++
        if (i > 2) continue
        UI_N++
        if (P_OK) UI_OK++
        else if (P_STAGE == "cert") UI_CERT++
        else if (P_STAGE == "tls") UI_TLS++
        else if (P_STAGE == "tcp") UI_TCP++
        else if (P_STAGE == "dns") UI_DNS++
    }
    if (HANGS > 0 && HTTPS) row("L5", "TLS hangs after TCP connect", "WARN", HANGS " of " n " hosts connect over TCP and then TLS hangs, while the control (1.1.1.1) passes: path MTU/MSS suspect (docs/teleport.md), not 'unreachable'. On macOS add -v ladder=1")
}

# ---------- optional (macOS, -v ladder=1): DF ping ladder ----------

# Sizes are whole IP packets, from the Wi-Fi MTU down. Three outcomes besides a reply: "Message too
# long" or "frag needed" is the kernel or the path reporting its MTU (PMTUD works, not a black hole);
# silence is a lost packet, and silence at sizes the path reported nothing about is the black hole.
function df_ladder(    mtu, i, j, n, w, t, sz, rc, st, p, m, k, nk, szs, sts, nlost, nrep, res, okmax, tag) {
    if (PLAT != "macos") { row("L3", "DF ping ladder", "SKIP", "macOS only (ping -D is not confirmed in Blink)"); return }
    if (MACIF == "") { row("L3", "DF ping ladder", "SKIP", "no interface known"); return }
    mtu = 1500
    run("ifconfig " MACIF)
    for (i = 1; i <= NL; i++) { n = split(LINES[i], w, " "); for (j = 1; j < n; j++) if (w[j] == "mtu" && w[j + 1] ~ /^[0-9]+$/) mtu = w[j + 1] + 0 }
    if (run("ping -c 1 -W 2000 1.1.1.1") != 0) { row("L3", "DF ping ladder", "SKIP", "ICMP filtered, ladder skipped (plain ping to 1.1.1.1 got no reply)"); return }
    n = split("1500 1480 1460 1440 1420 1400 1380 1360 1340 1320 1300 1280", t, " ")
    nk = 0
    szs[++nk] = mtu
    for (i = 1; i <= n; i++) if (t[i] + 0 < mtu) szs[++nk] = t[i] + 0
    res = ""; okmax = 0
    for (k = 1; k <= nk; k++) {
        sz = szs[k]
        rc = run("ping -c 1 -D -s " (sz - 28) " -W 2000 1.1.1.1")
        if (rc == 0) st = "ok"
        else if (contains("Message too long")) st = "too long (local)"
        else if (contains("rag needed")) {
            st = "frag needed"
            for (j = 1; j <= NL; j++) { p = index(LINES[j], "(MTU "); if (p > 0) { m = substr(LINES[j], p + 5); sub(/\).*$/, "", m); st = "frag needed, MTU " m } }
        }
        else st = "lost"
        sts[k] = st
        if (st == "ok" && okmax == 0) okmax = sz
        res = res (res != "" ? ", " : "") sz " " st
    }
    nlost = 0; nrep = 0
    for (k = 1; k <= nk; k++) {
        if (szs[k] <= okmax) break
        if (sts[k] == "lost") nlost++; else nrep++
    }
    tag = "DF ping ladder (" MACIF ", MTU " mtu ")"
    if (okmax == szs[1]) row("L3", tag, "OK", res ". Everything up to the client MTU passes; sizes above it are not tested")
    else if (okmax == 0) row("L3", tag, "WARN", res ". Not even the smallest size passes although a plain ping does: not an MTU pattern")
    else if (nlost == 0) row("L3", tag, "INFO", res ". Sizes above " okmax " are reported (local refusal or ICMP): PMTUD works, path MTU is near " okmax ", not a black hole")
    else if (nrep == 0) row("L3", tag, "WARN", res ". Sizes above " okmax " vanish with no ICMP back: black hole suspect (docs/teleport.md)")
    else row("L3", tag, "WARN", res ". Mixed above " okmax ": some sizes reported, some silently lost")
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
    inet = (TCP443 || HTTPS || UI_OK > 0 || PUB6 != "" || U3478 == 1 || U19302 == 1 || U53 || U123 == 1 || ICMP_OK > 0)
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
    else if (UI_OK < UI_N) v = ui_down()
    else v = "LIKELY: UDP out and back works (tested on STUN ports), UniFi cloud reachable"
    if (V6ONLY && TUN == "" && !V6DROP) v = v ". This connection is IPv6-only (IPv4 via NAT64): if Teleport fails, IPv6 on the home gateway WAN may help"
    out("- Teleport: " (HOME_EGRESS ? "CARRYING TRAFFIC now (exit = home WAN). Rows describe the path through it. " : "") v)

    # Teleport and WireGuard on a UniFi Travel Router: gated on its ICMP check (see icmp()).
    if (TUN != "") v = "not tested: ping went through the VPN"
    else if (HOME_EGRESS) v = "not tested: ping went through Teleport to home, not out of the uplink"
    else if (ICMP_SKIP) v = "not tested: no IPv4 on this link"
    else if (ICMP_OK) v = "its internet check (ping) passes here, so the rows above apply to it too"
    else v = "LIKELY NO on firmware 6.6.117+: nothing answers ping, so the UTR shows No Internet and its Teleport and WireGuard wait for it (docs/teleport.md, H7). Its OpenVPN client is not gated"
    out("- Teleport or WireGuard on a UniFi Travel Router: " v)

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
    else if (HOME_EGRESS) out("Note: the run exits at the home WAN (home_ip): these results describe the path through Teleport/VPN to home, not the uplink alone.")
    else if (V6DROP) out("Note: IPv6 is dropped although " LINKDEV " has it: a full-tunnel VPN without IPv6 may be on. Check Settings > VPN.")
    out("Own servers and UniFi Identity need a public IP at home, not CGNAT 100.64.0.0/10 (UniFi docs).")
    out("Teleport does not, but may need IPv6 on the home gateway WAN (UniFi docs).")
    out("Final check: open the VPN app on this connection. If it fails while the rows are OK, the cause is not this network.")
}

# The UniFi cloud check failed: name the stage, never judge from one failure (3 tries per host).
function ui_down() {
    if (UI_TLS) return "UNLIKELY for now: TCP to the UniFi cloud connects, then TLS fails in 3 of 3 tries. Not a block: path MTU/MSS suspect (docs/teleport.md)"
    if (UI_TCP) return "UNLIKELY: no TCP connection to the UniFi cloud in 3 tries"
    if (UI_DNS) return "UNKNOWN: UniFi cloud names do not resolve (dig, 3 s cap): fix DNS first"
    return "UNLIKELY: the UniFi cloud gives no HTTPS answer in 3 tries"
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

# Sets NOW_L (local time with zone) and NOW_U (UTC). One `date` call: %z gives the offset.
function now(    f, n, sec, o) {
    NOW_L = "??:??:??"; NOW_U = "??:??:??"
    if (run("date \"+%H:%M:%S %Z %z\"") == 0 && NL > 0) {
        n = split(LINES[1], f, " ")
        if ((n == 2 || n == 3) && f[1] ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ && f[n] ~ /^[-+][0-9][0-9][0-9][0-9]$/) {
            NOW_L = f[1] (n == 3 ? " " f[2] : "")
            sec = substr(f[1], 1, 2) * 3600 + substr(f[1], 4, 2) * 60 + substr(f[1], 7, 2)
            o = substr(f[n], 2, 2) * 3600 + substr(f[n], 4, 2) * 60
            sec = sec - (substr(f[n], 1, 1) == "-" ? -o : o)
            sec = (sec % 86400 + 86400) % 86400
            NOW_U = sprintf("%02d:%02d:%02d", int(sec / 3600), int((sec % 3600) / 60), sec % 60)
            return
        }
    }
    run("date +%H:%M:%S"); if (NL > 0) NOW_L = LINES[1]
    run("date -u +%H:%M:%S"); if (NL > 0) NOW_U = LINES[1]
}

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
    now()
    out("== VPN check: can a VPN connect over this connection? ==")
    out("connection: " KIND "  platform: " PLAT "  started: " d " (local " NOW_L ")" (server != "" ? "  server: " server ":" tcp : "") (home_ip != "" ? "  home_ip: " home_ip : ""))
    out("")
    out("| time local | time UTC | layer | test | result | detail |")
    out("|---|---|---|---|---|---|")
}

function row(layer, test, result, detail) {
    now()
    out("| " NOW_L " | " NOW_U " | " layer " | " test " | " result " | " detail " |")
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
