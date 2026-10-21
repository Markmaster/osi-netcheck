# mosh.awk - will a mosh session survive the move between Wi-Fi and LTE?
# Runs in the Blink Shell local shell (iPhone/iPad) and in macOS Terminal. Read-only on the device;
# the UDP rows need the echo of scripts/mosh-watch.sh running on the server.
#
# Blink:  awk -v server=HOST -f ~/iCloud/scripts/mosh.awk                          (snip mosh/run)
#         awk -v server=HOST -v port=60999 -v ssh=22 -f ~/iCloud/scripts/mosh.awk
# macOS:  awk -v server=HOST -f ~/mosh/mosh.awk   (mosh.awk and stun-req.bin from scripts/ in one folder)
#
# HOST is the server's real name or IP (HostName in Blink's host config), not a Blink host alias.
# port = UDP port of the echo on the server (default 60999), ssh = SSH port (default 22).
#
# Why: a mosh session keeps the server address it started with. With its default IP resolution
# Blink's mosh connects to the address its SSH login went to and starts "mosh-server new -s", which
# listens only on the address that login arrived at (Blink Commands/mosh/mosh.swift, mosh
# src/frontend/mosh-server.cc). So the network a session starts on picks its address: on IPv6-only
# LTE with NAT64 (T-Mobile) that can be an address that exists only there (64:ff9b::/96), on Wi-Fi
# an IPv4 address that LTE reaches only through CLAT and the carrier's NAT64. Each run notes the
# address a new session gets here and sends a UDP probe to it and to the address noted on the other
# connection: run on Wi-Fi, then on LTE, and the second run says which direction freezes.
#
# Same rules as vpn.awk: Blink's local shell has no sh, each probe runs through system() with its
# output in a temp file, and replies from the network are tested with index() and == only.

BEGIN {
    server = val(server); port = val(port); ssh = val(ssh); dir = val(dir)
    if (server == "") { print "usage: awk -v server=HOST [-v port=60999] [-v ssh=22] -f mosh.awk   (HOST = real name or IP, not a Blink alias)"; exit 2 }
    if (port == "") port = "60999"
    if (ssh == "") ssh = "22"
    if (port !~ /^[0-9]+$/) { print "port=\"" port "\" is not a port number"; exit 2 }
    if (ssh !~ /^[0-9]+$/) { print "ssh=\"" ssh "\" is not a port number"; exit 2 }

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
    if (TUN != "") row("L2", "VPN on?", "WARN", TUN ": a VPN looks connected, the rows below then describe the VPN. Turn it off and run again")
    nat64()
    dns()
    ssh_addr()
    remember()
    probes()
    verdict()
    finish()
}

# ---------- link: Wi-Fi or LTE (as in vpn.awk) ----------

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
        # 192.0.0.x is skipped: iOS puts such addresses on utun0 by itself (see vpn.awk).
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

# ---------- NAT64: does this network make up IPv6 addresses for IPv4 servers? ----------

# RFC 7050: ipv4only.arpa has only A records (192.0.0.170/171); an AAAA answer comes from the network's
# DNS64, and its first 96 bits are the NAT64 prefix. dig without @ asks the network DNS, not a profile.
function nat64(    i, a) {
    STEM = ""; PFX = ""
    run("dig AAAA ipv4only.arpa +short +time=2 +tries=1")
    a = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/) { a = tolower(LINES[i]); break }
    if (a == "") { row("L3", "NAT64 (DNS64)", "NONE", "no DNS64 here: IPv4 servers are reached over IPv4"); return }
    if (substr(a, length(a) - 6) == "c000:aa" || substr(a, length(a) - 6) == "c000:ab") { STEM = substr(a, 1, length(a) - 7); PFX = STEM "/96" }
    else PFX = "prefix of " a
    row("L3", "NAT64 (DNS64)", "YES", PFX ": IPv6-only network, IPv4 servers are reached through the carrier's NAT64")
}

# ---------- DNS: what the server name resolves to on this network ----------

function dns(    i, a4, a6) {
    A4 = ""
    if (server ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { A4 = server; row("L7", "DNS " server, "SKIP", "server given as an IPv4 address"); return }
    if (server ~ /:/) { row("L7", "DNS " server, "SKIP", "server given as an IPv6 address"); return }
    run("dig A " server " +short +time=2 +tries=1")
    a4 = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { a4 = a4 (a4 == "" ? "" : " ") LINES[i]; if (A4 == "") A4 = LINES[i] }
    run("dig AAAA " server " +short +time=2 +tries=1")
    a6 = ""
    for (i = 1; i <= NL; i++) if (LINES[i] ~ /^[0-9a-fA-F:]+:[0-9a-fA-F:.]+$/) a6 = a6 (a6 == "" ? "" : " ") tolower(LINES[i]) (kind(LINES[i]) == "IPv6 NAT64" ? " (made up by DNS64: the server has no IPv6 of its own)" : "")
    if (a4 == "" && a6 == "") row("L7", "DNS " server, "FAIL", "no A or AAAA from the network DNS (a DNS profile may still resolve it: see the SSH row)")
    else row("L7", "DNS " server, "OK", "A " (a4 != "" ? a4 : "none") ", AAAA " (a6 != "" ? a6 : "none"))
}

# ---------- SSH: which server address a new session would get here ----------

# curl to the SSH port resolves through the system resolver like Blink's ssh, and "-v" names the
# address it connected to. SSH answers with its banner, curl then fails on purpose: that is fine.
# curl races IPv6 and IPv4 (Happy Eyeballs), libssh tries them in resolver order: usually the same pick.
function ssh_addr(    rc, i, s, a, b) {
    SIP = ""
    rc = run("curl -sv -m 6 -o /dev/null http://" (server ~ /:/ ? "[" server "]" : server) ":" ssh "/")
    for (i = 1; i <= NL; i++) {
        a = index(LINES[i], "Connected to ")
        if (a == 0) continue
        s = substr(LINES[i], a)
        a = index(s, "("); b = index(s, ")")
        if (a > 0 && b > a + 1) { SIP = substr(s, a + 1, b - a - 1); break }
    }
    if (SIP != "") row("L4", "SSH TCP " ssh, "OK", "connected to " SIP " (" kind(SIP) "): a session started here uses this address")
    else row("L4", "SSH TCP " ssh, "FAIL", curl_err(rc) ": no session can start from here")
}

# ---------- remember this connection's address, read the other connections' ----------

function remember(    k, n, i, f, line, w, stamp) {
    stamp = now_utc()
    MDIR = (PLAT == "blink") ? ENVIRON["HOME"] "/iCloud" : dir
    SAFE = server
    gsub(/[^A-Za-z0-9._-]/, "-", SAFE)
    SAVED = 0
    if (SIP != "" && (KIND == "wifi" || KIND == "lte" || KIND == "hotspot" || KIND == "wired")) {
        f = MDIR "/mosh-addr-" SAFE "-" KIND ".txt"
        if (system("echo " SIP " " stamp " > " f " 2>&1") == 0) {
            line = ""
            getline line < f
            close(f)
            SAVED = (index(line, SIP " ") == 1)
        }
    }
    NO = 0
    n = split("wifi lte hotspot wired", k, " ")
    for (i = 1; i <= n; i++) {
        if (k[i] == KIND) continue
        f = MDIR "/mosh-addr-" SAFE "-" k[i] ".txt"
        line = ""
        if ((getline line < f) > 0) {
            split(line, w, " ")
            if (w[1] != "") { NO++; OK_KIND[NO] = k[i]; O_IP[NO] = w[1]; O_WHEN[NO] = w[2] }
        }
        close(f)
    }
}

# ---------- UDP probes to the echo on the server ----------

function probes(    i) {
    if (SIP != "") probe(SIP, "this connection's session")
    for (i = 1; i <= NO; i++) probe(O_IP[i], "session started on " OK_KIND[i])
    if (A4 != "") probe(A4, "IPv4 address, if you connect by IP")
}

# Send stun-req.bin to the echo, wait 2 s. RES[ip]: 1 echo came back, 0 no echo, -1 not tested.
# HARD[ip]: nc itself failed (no route): a NO even when the echo is not running.
function probe(ip, why,    t, i, err) {
    if (ip in RES) return
    t = "UDP " port " to " ip
    if (!readable(dir "/stun-req.bin")) { row("L4", t, "SKIP", "stun-req.bin not found in " dir); RES[ip] = -1; return }
    run("nc -u -w 2 " ip " " port " < " dir "/stun-req.bin")
    NPROBE++
    err = ""
    for (i = 1; i <= NL; i++) if (index(LINES[i], "nc: ") == 1 || index(LINES[i], "netcat: ") == 1) err = LINES[i]
    if (err != "") { RES[ip] = 0; HARD[ip] = 1; row("L4", t, "FAIL", why ": " err); return }
    if (NL > 0) { RES[ip] = 1; NECHO++; row("L4", t, "OK", why ": echo came back"); return }
    RES[ip] = 0
    row("L4", t, "FAIL", why ": no echo in 2 s")
}

# ---------- verdict: an inference from the rows above ----------

function verdict(    i, r, v, ip) {
    out("")
    out("== mosh on this connection (" KIND "): inferred from the rows above ==")
    if (SIP == "") out("- No session can start here: SSH to " server ":" ssh " failed. Check the name (the real host, not a Blink alias), then osi/run.")
    else {
        r = RES[SIP]
        out("- Started here: the session uses " SIP " (" kind(SIP) ")" (r == 1 ? " and UDP to it works here." : (r == 0 ? ", but UDP to it gets no echo here." : ".")))
    }
    for (i = 1; i <= NO; i++) {
        ip = O_IP[i]; r = RES[ip]
        if (r == 1) v = "YES, it survives the move to this connection"
        else if (r == 0 && (NECHO > 0 || HARD[ip])) v = "NO: nothing comes back from " ip " over this connection, so that session freezes here"
        else if (r == 0) v = "UNKNOWN: no echo came back from any address here, so this says nothing yet (see below)"
        else v = "UNKNOWN: not tested"
        out("- Started on " OK_KIND[i] " (run of " O_WHEN[i] " UTC): it uses " ip " (" kind(ip) "). Here: " v ".")
    }
    if (NO == 0) out("- Run mosh/run again on the other connection (Wi-Fi <-> LTE): that run tests this run's address and says which direction freezes.")
    if (A4 != "" && A4 != SIP && (A4 in RES) && RES[A4] >= 0) out("- By IPv4 address " A4 ": UDP " (RES[A4] == 1 ? "works" : "gets no echo") " here. \"mosh user@" A4 "\" makes SSH and mosh use IPv4 on every network (IPv4 over CLAT on IPv6-only LTE).")
    if (NPROBE > 0 && NECHO == 0) out("No echo at all: is the echo running on the server (sudo sh mosh-watch.sh)? Is UDP " port " open in the server's firewall (the mosh range 60000-61000)? If mosh-watch lists the probe, it arrived and the way back is blocked.")
    if (SIP != "" && kind(SIP) == "IPv6 NAT64") out("Note: " SIP " is made up by this network's DNS64 from the server's IPv4 address. It works only behind this NAT64 (" PFX "): a session that starts here freezes on a network without it.")
    if (KIND == "wifi" && index(LINK_TXT, "cellular also up")) out("Note: cellular is also up. To test Wi-Fi alone, turn off Cellular Data and run again.")
    if (TUN != "") out("Note: a VPN looks connected (" TUN "): these results describe the VPN, not the network.")
    if (SAVED) out("Noted for the next run: " SIP " = a session started on " KIND ".")
    out("What happens to a real session: sudo sh mosh-watch.sh on the server while you switch networks (docs/mosh.md).")
}

# IPv4, IPv6, or IPv6 made up by NAT64 (64:ff9b::/96, or the prefix found by nat64()).
function kind(ip,    l) {
    l = tolower(ip)
    if (l !~ /:/) return "IPv4"
    if (index(l, "64:ff9b:") == 1 || (STEM != "" && index(l, STEM) == 1)) return "IPv6 NAT64"
    return "IPv6"
}

# ---------- helpers (as in vpn.awk) ----------

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

# Folder with stun-req.bin: Blink iCloud scripts, ~/mosh, ~/vpn, $HOME or the current folder.
function find_dir(    d, n, i) {
    n = split(ENVIRON["HOME"] "/iCloud/scripts " ENVIRON["HOME"] "/mosh " ENVIRON["HOME"] "/vpn " ENVIRON["HOME"] " .", d, " ")
    for (i = 1; i <= n; i++) if (readable(d[i] "/stun-req.bin")) return d[i]
    return (PLAT == "blink") ? ENVIRON["HOME"] "/iCloud/scripts" : "."
}

function now() { run("date -u +%H:%M:%S"); return (NL > 0) ? LINES[1] : "??:??:??" }

function now_utc() { run("date -u +%Y-%m-%dT%H:%M"); return (NL > 0) ? LINES[1] : "?" }

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

function readable(f,    r, x) {
    r = (getline x < f)
    close(f)
    return (r >= 0)
}

function curl_err(rc) {
    if (rc == 6) return "name does not resolve (curl 6)"
    if (rc == 7) return "connect failed (curl 7)"
    if (rc == 28) return "timed out (curl 28)"
    return "curl exit " rc
}

function header(    d) {
    run("date -u +%Y-%m-%dT%H:%M:%SZ")
    d = (NL > 0) ? LINES[1] : "?"
    out("== mosh check: will a session survive Wi-Fi <-> LTE? ==")
    out("connection: " KIND "  platform: " PLAT "  started: " d "  server: " server " (ssh " ssh ", echo UDP " port ")")
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

# Log in iCloud (Blink) or next to stun-req.bin (macOS), else next to the temp file.
# Like preflight: a failed "> file" in Blink still returns 0, so the file is read back.
function open_log(    stamp) {
    run("date -u +%Y%m%d-%H%M%S")
    stamp = (NL > 0) ? LINES[1] : "now"
    LOG = ""
    if (try_log(((PLAT == "blink") ? ENVIRON["HOME"] "/iCloud" : dir) "/mosh-" KIND "-" stamp ".txt")) return
    try_log(OUTDIR "/mosh-" KIND "-" stamp ".txt")
}

function try_log(f,    line) {
    if (system("echo mosh-log > " f " 2>&1") != 0) return 0
    line = ""
    getline line < f
    close(f)
    if (line != "mosh-log") return 0
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
        OUT = dirs[i] "/.mosh-out.txt"
        OUTDIR = dirs[i]
        if (system("echo mosh-ok > " OUT " 2>&1") != 0) continue
        line = ""
        getline line < OUT
        close(OUT)
        if (line == "mosh-ok") return 1
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
