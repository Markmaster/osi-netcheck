#!/bin/sh
# mosh-watch.sh - server side of the mosh roaming check: what happens to a mosh session when the phone
# moves between Wi-Fi and LTE? Runs on the Linux server the session goes to; watch needs root (tcpdump).
# Read-only, except a UDP echo on one port for scripts/mosh.awk on the phone, which runs only while
# this script runs. Prints one Markdown table and saves it to /tmp/mosh-watch-*.txt.
#
#   sudo sh mosh-watch.sh [watch [MINUTES]]   sessions, then every mosh packet event until Ctrl-C (or MINUTES), then a summary
#   sh mosh-watch.sh sessions                 mosh-server processes and the address each one listens on
#   sh mosh-watch.sh echo [MINUTES]           only the UDP echo for mosh.awk, no capture (no root needed)
#
# Environment: ECHO_PORT=60999 (0 = no echo), PORTS=60000-61000, IFACE=any. With sudo, put them after it:
#   sudo ECHO_PORT=60010 sh mosh-watch.sh
#
# What the server can tell (mosh src/network/network.cc): the server sends to the source address of
# the newest authentic packet from the client; a client that hears nothing for 10 s sends from a new
# socket (new source port); a server that hears nothing for 40 s stops sending until the next packet.
# So per session: the phone's packets do not arrive / they arrive and the server answers the new
# address, and the answers get lost on the way to the phone / the server keeps answering the old one.

ECHO_PORT=${ECHO_PORT:-60999}
PORTS=${PORTS:-60000-61000}
IFACE=${IFACE:-any}

have() { command -v "$1" >/dev/null 2>&1; }
isnum() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }

# Offset of local time from UTC as text, e.g. UTC-07:00: the phone shows local time, the rows UTC.
tzname() { date +%z | sed 's/^\([+-]\)\(..\)\(..\)$/UTC\1\2:\3/'; }

# mawk reads a pipe in large blocks unless told otherwise: events would show up late.
pick_awk() { if awk -W version 2>&1 | grep -q mawk; then echo "awk -W interactive"; else echo awk; fi; }

# Local addresses, one line: the capture tells in from out by them.
local_ips() { ip -o addr show 2>/dev/null | awk '{sub(/\/.*/, "", $4); printf "%s ", $4}'; }

sessions() {
	echo "== mosh sessions on $(hostname 2>/dev/null) =="
	echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)  ($(tzname))"
	echo
	if ! have ss; then echo "ss not found: install iproute2"; return 1; fi
	[ "$(id -u)" = 0 ] || echo "Not root: only your own mosh-server processes are listed (sudo shows all)."
	echo "| pid | user | listens on | family | running for |"
	echo "|---|---|---|---|---|"
	n=0; old=0; v4=0; v6=0
	for s in $(ss -H -uanp 2>/dev/null | awk '/"mosh-server"/ {
		l = ""; p = ""
		for (i = 1; i <= NF; i++) {
			if (l == "" && $i ~ /:[0-9]+$/) l = $i
			if ($i ~ /pid=[0-9]+/) { p = $i; sub(/^.*pid=/, "", p); sub(/[^0-9].*$/, "", p) }
		}
		if (l != "" && p != "") print p "," l
	}'); do
		pid=${s%%,*}; addr=${s#*,}
		user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
		secs=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
		isnum "$secs" || secs=0
		case "$addr" in
			0.0.0.0:*) fam="IPv4, any address"; v4=1 ;;
			'*:'*|'[::]:'*) fam="IPv6 and IPv4, any address"; v4=1; v6=1 ;;
			'['*) fam="IPv6 only, this address"; v6=1 ;;
			*) fam="IPv4 only, this address"; v4=1 ;;
		esac
		[ "$secs" -ge 86400 ] && old=$((old + 1))
		printf '| %s | %s | %s | %s | %dd %02dh %02dm |\n' "$pid" "${user:-?}" "$addr" "$fam" $((secs / 86400)) $((secs % 86400 / 3600)) $((secs % 3600 / 60))
		n=$((n + 1))
	done
	[ "$n" = 0 ] && echo "| - | - | - | no mosh-server running | - |"
	echo
	g6=$(ip -6 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); printf "%s ", $4}')
	echo "Server IPv6: ${g6:-none}"
	[ "$v4" = 1 ] && echo "IPv4-only session: the phone must reach it over IPv4 on every network. On IPv6-only LTE (T-Mobile) that is the phone's CLAT and the carrier's NAT64."
	[ "$v6" = 1 ] && echo "IPv6 session: the phone needs IPv6 on every network it moves to; Wi-Fi without IPv6 freezes it."
	echo "Blink starts \"mosh-server new -s\": the server listens only on the address the SSH login arrived at, so the family is fixed when the session starts."
	[ "$old" -gt 0 ] && echo "$old session(s) older than a day: each is a client that never came back (mosh-server ends only on logout or with MOSH_SERVER_NETWORK_TMOUT). Harmless; \"kill PID\" ends one."
	return 0
}

ECHO_PY='
import socket, sys
port = int(sys.argv[1])
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", port))
except OSError:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
while True:
    data, peer = s.recvfrom(2048)
    s.sendto(data[:512], peer)
'

EPID=""

# Start the echo for mosh.awk; sets EPID. Returns 1 if it cannot run.
start_echo() {
	[ "$ECHO_PORT" = 0 ] && return 1
	if ! isnum "$ECHO_PORT"; then echo "ECHO_PORT=$ECHO_PORT is not a port number: no echo."; return 1; fi
	if ! have python3; then echo "python3 not found: no echo, the UDP rows of mosh.awk will FAIL."; return 1; fi
	if have ss && ss -H -uan 2>/dev/null | awk -v p=":$ECHO_PORT" '{for (i = 1; i <= NF; i++) if (substr($i, length($i) - length(p) + 1) == p) f = 1} END {exit !f}'; then
		echo "UDP $ECHO_PORT is in use: no echo. Pick a free port in the firewall's mosh range: sudo ECHO_PORT=60990 sh $0"
		return 1
	fi
	# Not as root when possible: the echo only reflects what it receives, capped at 512 bytes.
	# setpriv execs python3 itself, so EPID is the echo and "kill EPID" stops it.
	if [ "$(id -u)" = 0 ] && have setpriv && id nobody >/dev/null 2>&1; then
		setpriv --reuid="$(id -u nobody)" --regid="$(id -g nobody)" --clear-groups python3 -c "$ECHO_PY" "$ECHO_PORT" 2>/dev/null &
	else
		python3 -c "$ECHO_PY" "$ECHO_PORT" 2>/dev/null &
	fi
	EPID=$!
	sleep 1
	if ! kill -0 "$EPID" 2>/dev/null; then echo "The echo did not start on UDP $ECHO_PORT."; EPID=""; return 1; fi
	return 0
}

stop_echo() { [ -n "$EPID" ] && kill "$EPID" 2>/dev/null; EPID=""; }

echo_only() {
	mins=$1
	if [ -n "$mins" ] && ! isnum "$mins"; then echo "echo: MINUTES must be a whole number"; return 2; fi
	trap 'stop_echo' EXIT
	trap 'exit 0' INT TERM HUP
	start_echo || return 1
	echo "UDP echo on port $ECHO_PORT (IPv4 and IPv6 if the server has it). Run mosh/run on the phone now. Ctrl-C ends it."
	if [ -n "$mins" ]; then sleep $((mins * 60)); else wait "$EPID"; fi
}

ticker() { while :; do echo "TICK $(date +%s)"; sleep 1; done; }

watch() {
	mins=$1
	if [ -n "$mins" ] && ! isnum "$mins"; then echo "watch: MINUTES must be a whole number"; return 2; fi
	if [ "$(id -u)" != 0 ]; then echo "watch needs root for tcpdump: sudo sh $0 watch"; return 1; fi
	if ! have tcpdump; then echo "tcpdump not found: sudo apt install tcpdump (Debian/Ubuntu)"; return 1; fi
	case "$PORTS" in *[!0-9-]*|-*|*-) echo "PORTS=$PORTS: use LOW-HIGH, e.g. 60000-61000"; return 2 ;; esac
	log=/tmp/mosh-watch-$(date -u +%Y%m%d-%H%M%S).txt
	{ sessions; echo; } | tee "$log"
	trap 'stop_echo' EXIT
	trap ':' INT
	trap 'exit 1' TERM HUP
	if start_echo; then etxt="UDP echo on $ECHO_PORT for mosh.awk"; eport=$ECHO_PORT; else etxt="no echo"; eport=0; fi
	lo=${PORTS%-*}; hi=${PORTS#*-}
	# --foreground: without it timeout moves tcpdump out of the terminal's process group and Ctrl-C misses it.
	tmo=""; [ -n "$mins" ] && have timeout && tmo="timeout --foreground $((mins * 60))"
	printf '%s\n\n' "Watching UDP $PORTS on $IFACE ($etxt)$([ -n "$mins" ] && echo " for $mins min"). Now move the phone: Wi-Fi off/on, then back. Ctrl-C ends it." | tee -a "$log"
	# Ctrl-C (or a dropped SSH session): tcpdump ends, the subshell kills the ticker, awk and tee
	# ignore the signal, so awk gets EOF and the summary still reaches the log.
	{
		ticker &
		tk=$!
		trap 'kill "$tk" 2>/dev/null' INT TERM HUP EXIT
		# shellcheck disable=SC2086
		$tmo tcpdump -l -n -tt -i "$IFACE" "udp and portrange $lo-$hi" 2>/dev/null
		kill "$tk" 2>/dev/null
	} | (trap '' INT HUP; exec $(pick_awk) -v local="$(local_ips)" -v echo_port="$eport" -v tz="$(tzname)" "$WATCH_AWK") | (trap '' INT HUP; exec tee -a "$log")
	stop_echo
	echo
	echo "Saved (same as above): $log"
}

# shellcheck disable=SC2016 # awk program: the $ belong to awk
WATCH_AWK='
BEGIN {
    n = split(local, a, " ")
    for (i = 1; i <= n; i++) LOCAL[a[i]] = 1
    load_bound(0)
    print "| time UTC | port | who | event |"
    print "|---|---|---|---|"
    fflush()
}

$1 == "TICK" { tick($2 + 0); next }

{
    k = 0
    for (i = 2; i < NF; i++) if ($i == "IP" || $i == "IP6") { k = i; break }
    if (!k || $(k + 2) != ">") next
    dst = $(k + 3); sub(/:$/, "", dst)
    if (!split_ap($(k + 1))) next
    sip = AP_IP; sport = AP_PORT
    if (!split_ap(dst)) next
    dip = AP_IP; dport = AP_PORT
    if ((dip in LOCAL) && !((sip in LOCAL) && (sport in BOUND))) pkt($1 + 0, "in", dport, sip, sport, dip)
    else if (sip in LOCAL) pkt($1 + 0, "out", sport, dip, dport, sip)
}

END {
    print ""
    print "== Summary =="
    if (T0 == "") { print "No mosh packet seen. Was the phone in front with the session open? Is the session on this server?"; exit }
    print "From " hms(T0) " to " hms(LAST) " UTC (" tz " local)."
    for (j = 1; j <= NP; j++) summary(PORTS[j])
    if (echo_port) {
        if (!ENP) print "- echo " echo_port ": no probe arrived. mosh.awk not run, or UDP " echo_port " is closed on the way (cloud firewall, the phone network)."
        for (j = 1; j <= ENP; j++) { e = EPEER[j]; print "- echo " echo_port ": probe from " e " (" label(EIP[e]) "), answered " (EOUT[e] + 0) " of " EIN[e] }
    }
}

# ---------- per packet ----------

function pkt(t, dir, p, ip, port, lip,    peer) {
    if (T0 == "") T0 = t
    LAST = t
    peer = ap(ip, port)
    if (p == echo_port) { echo_pkt(t, dir, peer, ip); return }
    if (!(p in SEEN)) {
        SEEN[p] = 1; PORTS[++NP] = p
        if (!(p in BOUND)) load_bound(t)
        if (p in BOUND) { SPID[p] = BPID[p]; SBOUND[p] = BOUND[p] }
    }
    if (dir == "in") phone(t, p, peer, ip, lip)
    else server(t, p, peer)
}

function phone(t, p, peer, ip, lip) {
    IN_N[p]++
    if (!(p in BOUND)) {
        if (!NOSRV[p]) { NOSRV[p] = 1; ev(t, p, "PROBLEM", "packets from " peer " but no mosh-server listens on UDP " p ": the server of this session has ended (exit, kill, reboot). It cannot recover: start a new session") }
    } else if (BOUND[p] != "*" && BOUND[p] != lip && !((p, lip) in MISM)) {
        MISM[p, lip] = 1; MISMN[p]++
        ev(t, p, "PROBLEM", "packets arrive at " ap(lip, p) " but mosh-server listens on " ap(BOUND[p], p) " only: the kernel drops them. The phone uses another server address than the one SSH arrived at")
    }
    if (!(p in IN_PEER)) {
        ev(t, p, "phone", "packets from " peer " (" label(ip) ")" ((p in BPID) ? ", mosh-server pid " BPID[p] : ""))
        addpeer(p, peer, ip)
    } else if (peer != IN_PEER[p]) {
        if (ip == IN_IP[p]) hop(t, p, peer)
        else {
            MOVES[p]++
            ev(t, p, "MOVED", "phone now at " peer " (" label(ip) "), was " IN_PEER[p])
            PEND[p] = t; PKIND[p] = "move"; HOPRUN[p] = 0
            addpeer(p, peer, ip)
        }
    }
    if (QUIET[p]) { ev(t, p, "phone", "packets again after " int(t - IN_T[p]) " s, from " peer); QUIET[p] = 0; SSTOP[p] = 0 }
    IN_PEER[p] = peer; IN_IP[p] = ip; IN_T[p] = t
}

# Same IP, new source port: mosh-client opens a new socket when it has heard nothing for 10 s.
# It counts as "deaf" only if the server had been sending to the old socket for 5 s or more: right
# after a gap the client also hops once or twice while the server is still catching up.
function hop(t, p, peer,    deaf) {
    HOPS[p]++
    deaf = (OUT_PEER[p] == IN_PEER[p] && t - OUT_SINCE[p] >= 5)
    HOPRUN[p] = deaf ? HOPRUN[p] + 1 : 0
    HOP_T[p] = t
    PEND[p] = t; PKIND[p] = "hop"
    if (HOPRUN[p] == 2) {
        DEAF[p]++; DEAF_LABEL[p] = label(IN_IP[p])
        ev(t, p, "PROBLEM", "the phone hears nothing from the server: twice it opened a new socket while the server kept sending to the old one (mosh does that when no answer arrives), now " peer)
    }
}

function server(t, p, peer) {
    OUT_N[p]++
    if (peer != OUT_PEER[p]) {
        if (PEND[p] && peer == IN_PEER[p]) {
            if (PKIND[p] == "move") { FOLLOWED[p]++; ev(t, p, "server", "follows: now sends to " peer ", " sprintf("%.1f", t - PEND[p]) " s after the move") }
            else HOPFOLLOW[p]++
            PEND[p] = 0
        } else if (OUT_PEER[p] == "") ev(t, p, "server", "sends to " peer)
        else if (!PEND[p]) ev(t, p, "server", "now sends to " peer)
    }
    if (peer != OUT_PEER[p]) OUT_SINCE[p] = t
    OUT_PEER[p] = peer; OUT_T[p] = t
}

function echo_pkt(t, dir, peer, ip) {
    if (dir != "in") { EOUT[peer]++; return }
    if (!(peer in EIN)) { EPEER[++ENP] = peer; EIP[peer] = ip; ev(t, "echo", "probe", "from " peer " (" label(ip) ")") }
    EIN[peer]++
}

# ---------- every second ----------

function tick(t,    j, p) {
    for (j = 1; j <= NP; j++) {
        p = PORTS[j]
        if (PEND[p] && t - PEND[p] >= 4) {
            if (OUT_T[p] > PEND[p] && OUT_PEER[p] != IN_PEER[p]) {
                NOFOLLOW[p]++
                ev(t, p, "PROBLEM", "the server keeps sending to " OUT_PEER[p] " although the phone sends from " IN_PEER[p] ": it does not take these packets for roaming (mosh only follows packets newer than any before, with the session key)")
            } else if (OUT_T[p] <= PEND[p] && !NOSRV[p] && !MISMN[p]) {
                ev(t, p, "server", "has sent nothing for 4 s although the phone sends: mosh-server stopped or stuck?")
            }
            PEND[p] = 0
        }
        # The phone sends, the server is silent: is its mosh-server still there?
        if (!NOSRV[p] && IN_T[p] && t - IN_T[p] < 3 && t - OUT_T[p] >= 5 && t - LOADED >= 5) {
            load_bound(t)
            if (!(p in BOUND)) { NOSRV[p] = 1; ev(t, p, "PROBLEM", "the phone sends, but no mosh-server listens on UDP " p " any more: the server of this session has ended (exit, kill, reboot). It cannot recover: start a new session") }
        }
        if (IN_T[p] && !QUIET[p] && t - IN_T[p] >= 7) {
            QUIET[p] = 1; QUIETN[p]++
            ev(t, p, "phone", "no packets for 7 s (last from " IN_PEER[p] ")" (t - OUT_T[p] < 4 ? ", the server still sends to " OUT_PEER[p] : "") ". Blink in the background sends nothing; in front, it means the phone packets do not reach this server")
        }
        if (QUIET[p] && !SSTOP[p] && OUT_T[p] && t - OUT_T[p] >= 7 && t - IN_T[p] >= 40) {
            SSTOP[p] = 1
            ev(t, p, "server", "stopped sending: 40 s without the phone, as mosh does. It answers again at the next phone packet")
        }
        if (HOPRUN[p] >= 2 && t - HOP_T[p] >= 25 && t - IN_T[p] < 5) {
            HOPRUN[p] = 0
            ev(t, p, "phone", "no new socket for 25 s: the phone hears the server again (recovered, if the screen updates)")
        }
    }
}

# ---------- summary ----------

function summary(p,    s, v, i) {
    s = "- " p ((p in SPID) ? " (mosh-server pid " SPID[p] ", listens on " ap(SBOUND[p], p) ")" : "") ": in " (IN_N[p] + 0) ", out " (OUT_N[p] + 0) " packets"
    if (PN[p]) { s = s "; phone at"; for (i = 1; i <= PN[p]; i++) s = s (i > 1 ? " ->" : "") " " PEER[p, i] " (" PEERL[p, i] ")" }
    if (MOVES[p]) s = s "; moved " MOVES[p] "x, server followed " (FOLLOWED[p] + 0) "x"
    if (HOPS[p]) s = s "; new phone sockets " HOPS[p]
    print s
    if (NOSRV[p]) v = "the server of this session is gone: nothing can revive it, start a new session"
    else if (MISMN[p]) v = "the phone sends to a server address mosh-server does not listen on (it listens only where the SSH login arrived): SSH and mosh must use the same server address (docs/mosh.md)"
    else if (NOFOLLOW[p]) v = "the server did not follow the phone to its new address: a mosh/Blink problem, not the network. Keep this log"
    else if (DEAF[p]) v = "the server answered the phone, the phone heard nothing (" DEAF_LABEL[p] "): answers are lost on the way to the phone on that network"
    else if (QUIETN[p] && !MOVES[p]) v = "the phone went silent and no packet came from another address: from its new network nothing reaches this server (or Blink was in the background)"
    else if (MOVES[p] && FOLLOWED[p] >= MOVES[p]) v = "roaming worked in this run: the server followed every move"
    else v = "no network change seen: move the phone (Wi-Fi off/on) while this runs"
    print "  => " v
}

# ---------- helpers ----------

function ev(t, p, who, text) { print "| " hms(t) " | " p " | " who " | " text " |"; fflush() }

function addpeer(p, peer, ip) { PEER[p, ++PN[p]] = peer; PEERL[p, PN[p]] = label(ip) }

function hms(t,    s) { s = int(t) % 86400; return sprintf("%02d:%02d:%02d", int(s / 3600), int(s % 3600 / 60), s % 60) }

# "1.2.3.4.5678" or "2001:db8::1.5678" (tcpdump) -> AP_IP, AP_PORT
function split_ap(s) {
    if (!match(s, /\.[0-9]+$/)) return 0
    AP_IP = substr(s, 1, RSTART - 1); AP_PORT = substr(s, RSTART + 1)
    return 1
}

function ap(ip, port) { return (ip ~ /:/) ? "[" ip "]:" port : ip ":" port }

# Family, and T-Mobile US by ARIN (172.32.0.0/11, 2607:fb90::/28, 2607:fc20::/32). Its phones are
# IPv6-only: IPv4 from T-Mobile is the carrier NAT64.
function label(ip,    a, l) {
    l = tolower(ip)
    if (l ~ /:/) return (l ~ /^2607:fb9[0-9a-f]:/ || l ~ /^2607:fc20:/) ? "IPv6, T-Mobile" : "IPv6"
    split(l, a, ".")
    return (a[1] == 172 && a[2] >= 32 && a[2] <= 63) ? "IPv4, T-Mobile NAT64" : "IPv4"
}

# mosh-server sockets from ss: BOUND[port] = address ("*" = any), BPID[port] = pid.
function load_bound(t,    cmd, line, f, n, i, l, ip, port, pid) {
    split("", BOUND); split("", BPID); LOADED = t
    cmd = "ss -H -uanp 2>/dev/null"
    while ((cmd | getline line) > 0) {
        if (index(line, "\"mosh-server\"") == 0) continue
        n = split(line, f, " ")
        l = ""; pid = ""
        for (i = 1; i <= n; i++) {
            if (l == "" && f[i] ~ /:[0-9]+$/) l = f[i]
            if (f[i] ~ /pid=[0-9]+/) { pid = f[i]; sub(/^.*pid=/, "", pid); sub(/[^0-9].*$/, "", pid) }
        }
        if (l == "" || !match(l, /:[0-9]+$/)) continue
        port = substr(l, RSTART + 1); ip = substr(l, 1, RSTART - 1)
        gsub(/[\[\]]/, "", ip); sub(/%.*$/, "", ip)
        if (ip == "*" || ip == "0.0.0.0" || ip == "::") ip = "*"
        BOUND[port] = ip; BPID[port] = pid
    }
    close(cmd)
}
'

case "${1:-watch}" in
	sessions) sessions ;;
	watch) [ $# -gt 0 ] && shift; watch "$@" ;;
	echo) shift; echo_only "$@" ;;
	*) echo "usage: sudo sh $0 [watch [MINUTES]] | sessions | echo [MINUTES]"; exit 2 ;;
esac
