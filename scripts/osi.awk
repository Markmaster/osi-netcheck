# osi.awk - step-by-step network check: is it my DNS (Control D) or the internet?
# Runs in the Blink Shell local shell (iPhone/iPad) and in macOS Terminal.
#
# Blink:  awk -f ~/iCloud/scripts/osi.awk                    (snip osi/run, works on LTE too)
#         awk -v gw=ROUTER_IP -f ~/iCloud/scripts/osi.awk    (snip osi/run-wifi, also pings the router)
#         The file lives in iCloud Drive > Blink > scripts > osi.awk (~/iCloud inside Blink).
# macOS:  awk -f ~/osi.awk   (the gateway is found via route; or pass -v gw=IP)
#
# Blink's local shell has no sh/bash, so the logic is written in awk, and the same file runs on a Mac.
# Each check is one command run through system(); its output goes to a temp file
# in $HOME and is parsed here. The "who is to blame" verdict is printed at the end.

BEGIN {
    NOFILE = 0
    VERIFY_IP = "147.185.34.1"

    print "== OSI check: Control D or the internet =="

    # Self-test: command output must be captured to a file, otherwise the verdict would be a guess.
    if (!preflight()) {
        print "STOP: cannot save command output to a temp file"
        print "(tried $HOME, $TMPDIR and the current folder). The script cannot parse"
        print "results. Check step by step instead (in Blink: snips osi/1 ... osi/7b)."
        exit 1
    }

    # 1 Gateway: -v gw=IP, otherwise auto-detect (macOS: route; Blink has no route, step skipped)
    if (gw == "") gw = find_gw()
    if (gw == "" && GW_IF != "") {
        say("--", "1 ", "Gateway: default route goes via VPN (" GW_IF "), router not checked. Pass -v gw=IP")
        gw_ok = -1
    } else if (gw == "") {
        say("--", "1 ", "Gateway: not found. On Wi-Fi pass -v gw=IP (in Blink: snip osi/run-wifi)")
        gw_ok = -1
    } else if (gw !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        say("??", "1 ", "Gateway: \"" gw "\" is not an IPv4 address, skipped")
        gw_ok = -1
    } else {
        gw_ok = (run("ping -c 2 -W 2000 " gw) == 0)
        say(gw_ok ? "OK" : "FAIL", "1 ", "Gateway " gw (gw_ok ? ": replies" : ": no reply"))
    }

    # 2 Ping by IP, no DNS involved
    rc1 = run("ping -c 2 -W 2000 1.1.1.1"); f1 = has("prohibited")
    rc2 = run("ping -c 2 -W 2000 8.8.8.8"); f2 = has("prohibited")
    ping_ok = (rc1 == 0 || rc2 == 0)
    filtered = (f1 || f2)
    if (ping_ok) say("OK", "2 ", "Ping 1.1.1.1 / 8.8.8.8")
    else if (filtered) say("FAIL", "2 ", "Ping 1.1.1.1 / 8.8.8.8: the network blocks ping (prohibited by filter)")
    else say("FAIL", "2 ", "Ping 1.1.1.1 / 8.8.8.8: no reply")

    # 3 TCP 443 by IP
    tcp_ok = (run("nc -z -G 3 1.1.1.1 443") == 0)
    say(tcp_ok ? "OK" : "FAIL", "3 ", "TCP 443 to 1.1.1.1")

    # 3b HTTPS by IP
    https_ok = (run("curl -sS -m 5 -o /dev/null https://1.1.1.1") == 0)
    say(https_ok ? "OK" : "FAIL", "3b", "HTTPS to 1.1.1.1")

    # 4 DNS bypassing Control D
    dns_ext = dig_ok("dig @1.1.1.1 example.com +short +time=2 +tries=1")
    say(dns_ext ? "OK" : "FAIL", "4 ", "DNS via 1.1.1.1 (UDP 53, bypassing Control D)")

    # 5 Control D directly over UDP 53. Only Control D answers verify.controld.com with 147.185.34.1,
    # so any other answer means the network intercepts plain DNS (hijack) and Control D never saw it.
    rc = run("dig @76.76.2.0 verify.controld.com +short +time=2 +tries=1")
    if (NOFILE) cd_dns = (rc == 0)
    else cd_dns = (rc == 0 && has("^147\\.185\\.34\\.1$"))
    hijack = (!cd_dns && rc == 0)
    if (cd_dns) say("OK", "5 ", "Control D directly 76.76.2.0 (UDP 53)")
    else if (hijack) say("??", "5 ", "Control D directly 76.76.2.0: answered, but not by Control D (network intercepts DNS)")
    else say("FAIL", "5 ", "Control D directly 76.76.2.0 (UDP 53)")

    # 5b Control D DoH endpoint over TCP 443
    cd_doh = (run("nc -z -G 3 76.76.2.22 443") == 0)
    say(cd_doh ? "OK" : "FAIL", "5b", "Control D DoH 76.76.2.22 (TCP 443)")

    # 6 System DNS of the device (ping by name; the PING line matters, not the replies)
    rc = run("ping -c 1 -W 2000 example.com")
    ip = ping_ip()
    if (NOFILE) sys_dns = (rc != 68)
    else sys_dns = (ip != "")
    say(sys_dns ? "OK" : "FAIL", "6 ", "System DNS: example.com" (ip != "" ? " -> " ip : (sys_dns ? "" : " does not resolve")))

    # 6b Network/router DNS directly (bypasses the DNS profile). On a Mac with ctrld it is the local resolver.
    ns = resolv_ns()
    if (ns ~ /^127\./ || ns == "::1") NETLBL = "local resolver " ns " (ctrld)"
    else NETLBL = "network"
    net_dns = dig_ok("dig example.com +short +time=2 +tries=1")
    say(net_dns ? "OK" : "FAIL", "6b", (NETLBL == "network" ? "Network/router DNS (bypasses the profile)" : "DNS: " NETLBL))

    # 7 Verify via the system DNS
    rc = run("ping -c 1 -W 2000 verify.controld.com")
    vip = ping_ip()
    verify_sys = (vip == VERIFY_IP)
    if (verify_sys) say("OK", "7 ", "Verify (system): " vip " = Control D")
    else if (vip != "") say("FAIL", "7 ", "Verify (system): " vip ", not Control D")
    else if (NOFILE && rc != 68) { say("??", "7 ", "Verify (system): output not readable"); verify_sys = -1 }
    else say("FAIL", "7 ", "Verify (system): does not resolve")

    # 7b Verify via the network DNS
    rc = run("dig verify.controld.com +short +time=2 +tries=1")
    verify_net = has("^147\\.185\\.34\\.1$")
    if (NOFILE) say("??", "7b", "Verify (" NETLBL "): output not readable")
    else if (verify_net) say("OK", "7b", "Verify (" NETLBL "): Control D")
    # Resolvers other than Control D return an empty answer for this name (dig exit 0, no IP):
    # that is "not Control D", not a dead DNS. Dead = dig failed, or no IP while 6b got no answer either.
    else if (rc != 0 || (!net_dns && !has("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))) say("FAIL", "7b", "Verify (" NETLBL "): DNS did not answer")
    else say("--", "7b", "Verify (" NETLBL "): not Control D" (NETLBL == "network" ? " (normal unless your router uses Control D)" : ""))

    verdict()
    system("rm -f " OUT)
}

# Default gateway from "route -n get default" (macOS). Empty if not found or not IPv4.
# If the default route goes via a VPN (utun, ppp, ipsec), the gateway is not the router: GW_IF = interface.
function find_gw(    i, n, f, g, ifc) {
    run("route -n get default")
    g = ""; ifc = ""
    for (i = 1; i <= NL; i++) {
        n = split(LINES[i], f, " ")
        if (f[1] == "gateway:") g = f[n]
        if (f[1] == "interface:") ifc = f[n]
    }
    if (ifc != "" && ifc !~ /^(en|bridge)[0-9]/) { GW_IF = ifc; return "" }
    if (g ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return g
    return ""
}

# First nameserver from /etc/resolv.conf (macOS). Blink has no such file: empty.
function resolv_ns(    line, f) {
    if (resolv == "") resolv = "/etc/resolv.conf"
    while ((getline line < resolv) > 0) {
        if (split(line, f, " ") >= 2 && f[1] == "nameserver") { close(resolv); return f[2] }
    }
    close(resolv)
    return ""
}

# Find a folder where "> file 2>&1" redirection really works. OUT = path to the temp file.
function preflight(    dirs, n, i, line) {
    n = split(ENVIRON["HOME"] " " ENVIRON["TMPDIR"] " .", dirs, " ")
    for (i = 1; i <= n; i++) {
        OUT = dirs[i] "/.osi-out.txt"
        if (system("echo osi-ok > " OUT " 2>&1") != 0) continue
        line = ""
        getline line < OUT
        close(OUT)
        if (line == "osi-ok") return 1
    }
    return 0
}

# Run a command, keep its output (stdout+stderr) in LINES[1..NL]. Return the exit code.
function run(cmd,    rc, line, r) {
    rc = system(cmd " > " OUT " 2>&1")
    # The command was killed by a signal (Ctrl-C). On macOS system() keeps awk from seeing
    # Ctrl-C itself, so stop here instead of counting the interrupted check as a FAIL.
    if (rc >= 256 || rc != int(rc)) {
        print ""
        print "Interrupted (Ctrl-C)."
        system("rm -f " OUT)
        exit 130
    }
    split("", LINES)
    NL = 0
    while ((r = (getline line < OUT)) > 0) LINES[++NL] = line
    if (r < 0) NOFILE = 1
    close(OUT)
    return rc
}

# Does any output line match the regular expression?
function has(re,    i) {
    for (i = 1; i <= NL; i++) if (LINES[i] ~ re) return 1
    return 0
}

# IP from the line "PING name (IP): ...", otherwise empty.
function ping_ip(    i, s) {
    for (i = 1; i <= NL; i++) {
        if (LINES[i] ~ /^PING .*\(/) {
            s = LINES[i]
            sub(/^[^(]*\(/, "", s)
            sub(/\).*$/, "", s)
            return s
        }
    }
    return ""
}

# dig +short: success = exit code 0 and an IPv4 in the answer.
function dig_ok(cmd,    rc) {
    rc = run(cmd)
    if (NOFILE) return (rc == 0)
    return (rc == 0 && has("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))
}

function say(status, step, text) {
    printf "[%4s] %s %s\n", status, step, text
}

function note(text) { print "  * " text }

function verdict(    inet, web) {
    # The internet works if anything outside answered: not only 1.1.1.1, but also Control D or DNS.
    inet = (ping_ok || tcp_ok || https_ok || cd_doh || cd_dns || dns_ext)
    web = 0   # 1 = internet confirmed and the verdict reached the DNS analysis

    print ""
    print "== VERDICT =="
    if (!inet) {
        print "NO INTERNET: nothing outside answers (no ping, no TCP 443, no DNS)."
        print "Control D is not the cause."
        if (gw_ok == 0) print "The router does not reply: Wi-Fi or router problem."
        else if (gw_ok == 1) print "The router replies, nothing beyond it: ISP or router settings."
        else print "Check Wi-Fi, cable or router, or switch to another network (e.g. cellular)."
    } else if (!tcp_ok && !https_ok && !cd_doh) {
        print "Something outside answers, but TCP 443 is blocked everywhere: the network blocks HTTPS (firewall)."
        print "Control D is not the cause."
    } else if (tcp_ok && !https_ok) {
        print "TCP 443 connects but HTTPS fails: looks like a Wi-Fi login page"
        print "(captive portal) or TLS interception. Open a browser."
    } else if (!sys_dns) {
        web = 1
        if (cd_doh) {
            print "Internet works, Control D is reachable on 443, but the system DNS does not work."
            print "Your setup is the cause: DNS profile, resolver ID, router or ctrld."
            print "Check: turn Control D off (DNS profile or ctrld) and run again."
        } else if (cd_dns || dns_ext) {
            print "Internet works, but TCP 443 to Control D (DoH) is blocked:"
            print "a DNS profile or ctrld (DoH) cannot reach it. The network blocks Control D:"
            print "exclude this network in the profile (Control D dashboard) or use another network."
            if (cd_dns) print "If Control D runs on your router (UDP 53), check the router too."
        } else if (net_dns && NETLBL == "network") {
            print "Internet works, but the network blocks Control D and all outside DNS:"
            print "only its own DNS answers (6b). A DNS profile or ctrld cannot work here:"
            print "exclude this network in the profile (Control D dashboard) or use another network."
        } else {
            print "The network blocks both outside DNS and Control D. System DNS does not work."
            print "Control D is not the cause: try another network (e.g. cellular)."
        }
    } else if (verify_sys == 0) {
        web = 1
        print "Internet and DNS work, but the system DNS most likely does NOT go through Control D."
        print "Usual causes: VPN, manual DNS, ctrld not running, network excluded in the profile,"
        print "iCloud Private Relay if you allowed it in Control D."
    } else if (verify_sys == -1) {
        web = 1
        print "Internet and DNS work. Could not tell whether DNS goes through Control D."
    } else {
        web = 1
        print "ALL OK: internet works, DNS goes through Control D."
    }

    if (web && !tcp_ok && !https_ok) note("1.1.1.1 is blocked on this network, but the internet works (Control D answers on 443).")
    if (web && !ping_ok) note("This network blocks ping, but the internet works. Not a fault.")
    if (web && gw_ok == 0) note("The router did not answer ping, but the internet works: the router just ignores ping.")
    if (web && !dns_ext && sys_dns) note("This network blocks outside DNS (UDP 53), but the system DNS works.")
    if (web && hijack) note("This network intercepts plain DNS (5): Control D on a router cannot work from here (DoH is checked separately in 5b).")
    if (web && !cd_dns && !hijack && cd_doh && sys_dns) note("Control D is unreachable on UDP 53 but reachable on 443: normal for DoH (profile or ctrld).")
    if (web && !net_dns && sys_dns) {
        if (NETLBL == "network") {
            note("The network/router DNS does not answer (6b). At home without a VPN this means the router DNS")
            note("is broken and other devices on the network have no DNS. In Blink, if you just switched")
            note("networks, fully close Blink and start it again: dig may still use the previous network's DNS.")
        } else note("The " NETLBL " does not answer dig (6b), but the system DNS works.")
    }
    print "Final check in a browser: https://controld.com/status"
}
