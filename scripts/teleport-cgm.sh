#!/bin/sh
# teleport-cgm.sh - home side of the UTR Teleport check. Runs on the UniFi gateway (UCG Max) as root over SSH.
# Read-only: prints state and captures packets, changes no config. Never prints private or preshared keys;
# public keys are cut to 8 characters.
#
#   sh teleport-cgm.sh info                                WAN and NAT, WireGuard, UDP listeners, DNS and TLS to UI hosts, log lines
#   sh teleport-cgm.sh capture [SECONDS] [SRC_IP] [PORTS]  what reaches the WAN (default 180 s). Run it while the client probes
#                                                          and while the UTR tries Teleport. SRC_IP = client public IP from teleport.awk
#   sh teleport-cgm.sh watch [MINUTES]                     WireGuard handshakes and endpoints every 5 s (default 10 min)
#
# Environment: WAN_IF=eth4 overrides WAN detection, HOSTS="a b" the UI hosts.
# Every command is checked with "command -v" first: UniFi OS builds differ, nothing here is assumed to exist.

HOSTS=${HOSTS:-"unifi.ui.com sso.ui.com api.ui.com account.ui.com"}
PORTS_DEFAULT="51820 443 3478"
VERIFY_IP=147.185.34.1

have() { command -v "$1" >/dev/null 2>&1; }
isnum() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
ts() { date -u +%H:%M:%S; }
row() { printf '| %s | %s | %s | %s | %s |\n' "$(ts)" "$1" "$2" "$3" "$4"; }
short() { printf '%.8s' "$1"; }
joinl() { tr '\n' ' ' | sed 's/ *$//'; }

header() {
	echo "== UTR Teleport check, CGM side: $1 =="
	echo "host: $(hostname 2>/dev/null)  started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo
}

thead() {
	echo "| time UTC | layer | test | result | detail |"
	echo "|---|---|---|---|---|"
}

# WAN interface: WAN_IF, else the default route of the main table, else the first default route in any table
# that is not a tunnel (UniFi OS uses policy routing tables).
wan_if() {
	if [ -n "$WAN_IF" ]; then echo "$WAN_IF"; return; fi
	i=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
	if [ -z "$i" ]; then
		i=$(ip -4 route show table all 2>/dev/null | awk '$1 == "default" {for (i = 1; i < NF; i++) if ($i == "dev" && $(i + 1) !~ /^(wg|tun)/) { print $(i + 1); exit }}')
	fi
	echo "$i"
}

wan_ip() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}'; }

ipclass() {
	case "$1" in
		"") echo none ;;
		10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) echo private ;;
		100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) echo cgnat ;;
		*) echo public ;;
	esac
}

public_ip() { curl -sS -m 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '$1 == "ip" {print $2}'; }

wg_ports() { have wg && wg show all listen-port 2>/dev/null | awk '{print $2}'; }

info() {
	header info
	thead
	if [ -r /etc/os-release ]; then row SYS "OS" INFO "$(. /etc/os-release; echo "$PRETTY_NAME")"; fi
	if have ubnt-device-info; then row SYS "firmware" INFO "$(ubnt-device-info firmware 2>/dev/null)"; else row SYS "firmware" SKIP "ubnt-device-info not found: read it in the UniFi UI"; fi
	row SYS "kernel" INFO "$(uname -r)"

	IF=$(wan_if)
	if [ -z "$IF" ]; then row L3 "WAN interface" FAIL "not found: pass WAN_IF=..."; else row L3 "WAN interface" INFO "$IF"; fi
	WIP=$(wan_ip "$IF")
	PIP=$(public_ip)
	row L3 "WAN IP" INFO "${WIP:-none} ($(ipclass "$WIP"))"
	row L3 "public IP" "$([ -n "$PIP" ] && echo INFO || echo FAIL)" "${PIP:-no answer from 1.1.1.1 trace}"
	if [ -n "$WIP" ] && [ "$WIP" = "$PIP" ]; then
		row L3 "inbound to WAN" OK "WAN IP is the public IP: probes from outside can reach this interface"
	elif [ -n "$WIP" ] && [ -n "$PIP" ]; then
		row L3 "inbound to WAN" WARN "WAN $WIP is behind NAT ($PIP): outside probes stop upstream unless forwarded, the capture cannot see them (Teleport itself works behind NAT per UniFi docs)"
	fi
	W6=$(ip -6 -o addr show dev "$IF" scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')
	if [ -n "$W6" ]; then row L3 "WAN IPv6" OK "$W6"; else row L3 "WAN IPv6" WARN "none: UniFi docs say Teleport needs IPv6 on the gateway WAN in some circumstances"; fi

	if have wg; then
		ifs=$(wg show interfaces 2>/dev/null)
		[ -z "$ifs" ] && row VPN "WireGuard" INFO "wg found, no interfaces"
		for w in $ifs; do
			lp=$(wg show "$w" listen-port 2>/dev/null)
			np=$(wg show "$w" peers 2>/dev/null | wc -l | tr -d ' ')
			row VPN "wg $w" INFO "listen port ${lp:-none}, peers $np"
			nowe=$(date +%s)
			wg show "$w" latest-handshakes 2>/dev/null | while read -r pk t; do
				ep=$(wg show "$w" endpoints 2>/dev/null | awk -v k="$pk" '$1 == k {print $2}')
				tr=$(wg show "$w" transfer 2>/dev/null | awk -v k="$pk" '$1 == k {print "rx " $2 " B, tx " $3 " B"}')
				if [ "${t:-0}" -eq 0 ]; then age=never; else age="$((nowe - t)) s ago"; fi
				row VPN "  peer $(short "$pk")" INFO "endpoint ${ep:-none}, handshake $age, $tr"
			done
		done
	else
		row VPN "WireGuard" WARN "wg not found; interfaces: $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | joinl)"
	fi

	if have ss; then
		u=$(ss -uln 2>/dev/null | awk 'NR > 1 {n = split($4, a, ":"); print a[n]}' | sort -un | joinl)
	elif have netstat; then
		u=$(netstat -uln 2>/dev/null | awk '$1 ~ /^udp/ {n = split($4, a, ":"); print a[n]}' | sort -un | joinl)
	fi
	row L4 "UDP listening ports" INFO "${u:-ss and netstat not found}"

	ns=$(awk '$1 == "nameserver" {print $2}' /etc/resolv.conf 2>/dev/null | joinl)
	# shellcheck disable=SC2009
	if have pgrep; then c=$(pgrep -l ctrld 2>/dev/null | head -1); else c=$(ps 2>/dev/null | grep '[c]trld' | head -1); fi
	row L7 "resolver" INFO "nameserver ${ns:-none}; ctrld process: $([ -n "$c" ] && echo yes || echo no)"
	if have getent; then
		for h in verify.controld.com $HOSTS; do
			a=$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u | joinl)
			if [ -z "$a" ]; then row L7 "DNS $h" FAIL "no answer (blocked, NXDOMAIN or DNS down)"
			elif [ "$a" = "0.0.0.0" ]; then row L7 "DNS $h" FAIL "0.0.0.0: blocked by the DNS filter"
			elif [ "$h" = verify.controld.com ]; then row L7 "DNS $h" INFO "$a $(echo "$a" | grep -q "$VERIFY_IP" && echo '= Control D' || echo '(not Control D)')"
			else row L7 "DNS $h" OK "$a"; fi
		done
	else
		row L7 "DNS" SKIP "getent not found"
	fi

	for h in $HOSTS; do
		r=$(curl -sS -o /dev/null -m 10 -w 'HTTP %{http_code}, TLS done at %{time_appconnect} s, %{remote_ip}' "https://$h/" 2>&1)
		rc=$?
		if [ $rc -eq 0 ]; then row L5 "TLS $h" OK "$r"; else row L5 "TLS $h" FAIL "curl exit $rc: $(echo "$r" | head -1)"; fi
	done

	files=$(grep -rIli teleport /var/log /data/unifi-core/logs /usr/lib/unifi/logs 2>/dev/null | head -10)
	if [ -z "$files" ]; then row LOG "teleport in logs" INFO "no file under /var/log, /data/unifi-core/logs, /usr/lib/unifi/logs mentions teleport"; fi
	for f in $files; do
		row LOG "$f" INFO "$(grep -ci teleport "$f") lines mention teleport, last 15 below"
	done
	for f in $files; do
		echo
		echo "--- $f"
		grep -i teleport "$f" | tail -15
	done
}

capture() {
	dur=${1:-180}; src=$2; ports=${3:-$PORTS_DEFAULT}
	isnum "$dur" || { echo "capture: SECONDS must be a whole number"; return 2; }
	header "capture $dur s"
	if ! have tcpdump; then thead; row L4 "capture" FAIL "tcpdump not found"; return 1; fi
	IF=$(wan_if)
	if [ -z "$IF" ]; then thead; row L4 "capture" FAIL "WAN interface not found: pass WAN_IF=..."; return 1; fi
	WIP=$(wan_ip "$IF")
	# shellcheck disable=SC2046,SC2086  # word splitting of the port lists is intended
	all=$(printf '%s\n' $ports $(wg_ports) | sort -un | joinl)
	pf=""
	for p in $all; do pf="${pf:+$pf or }dst port $p"; done
	if [ -n "$src" ]; then
		filt="src host $src and (udp or tcp[tcpflags] & tcp-syn != 0)"
	else
		filt="(udp and ($pf)) or (tcp[tcpflags] & tcp-syn != 0 and (dst port 443 or dst port 80))"
	fi
	[ -n "$WIP" ] && filt="dst host $WIP and ($filt)"
	raw=/tmp/tp-capture-$(date -u +%Y%m%d-%H%M%S).txt
	echo "interface $IF, filter: $filt"
	echo "raw packets: $raw"
	echo "expected ports: $all (WireGuard listen ports included)"
	echo
	trap ':' INT
	if have timeout; then
		TZ=UTC timeout "$dur" tcpdump -l -n -q -tttt -i "$IF" "$filt" | tee "$raw"
	else
		echo "no timeout command: stop with Ctrl-C"
		TZ=UTC tcpdump -l -n -q -tttt -i "$IF" "$filt" | tee "$raw"
	fi
	trap - INT TERM
	echo
	thead
	summarize "$raw" "$all"
}

# One row per protocol/port that arrived, then NONE rows for expected ports that did not.
summarize() {
	awk -v expect="$2" '
	$3 == "IP" {
		src = $4; sub(/\.[0-9]+$/, "", src)
		dp = $6; sub(/:$/, "", dp); sub(/^.*\./, "", dp)
		proto = ($7 == "UDP,") ? "udp" : "tcp"
		len = (proto == "udp") ? $NF " B" : "SYN"
		k = proto "/" dp
		t = substr($2, 1, 8)
		if (!(k in n)) { first[k] = t; order[++nk] = k }
		n[k]++; last[k] = t
		if (index(" " srcs[k] ",", " " src ",") == 0) srcs[k] = srcs[k] " " src ","
		if (index(" " lens[k] ",", " " len ",") == 0) lens[k] = lens[k] " " len ","
	}
	END {
		for (i = 1; i <= nk; i++) {
			k = order[i]; s = srcs[k]; l = lens[k]; sub(/,$/, "", s); sub(/,$/, "", l)
			printf "| %s-%s | L4 | arrived %s | OK | %d pkt, sizes%s, from%s |\n", first[k], last[k], k, n[k], l, s
		}
		m = split(expect, e, " ")
		for (i = 1; i <= m; i++) if (!(("udp/" e[i]) in n)) printf "| - | L4 | arrived udp/%s | NONE | nothing reached the WAN |\n", e[i]
		if (!("tcp/443" in n)) print "| - | L4 | arrived tcp/443 | NONE | no SYN reached the WAN |"
		if (!("tcp/80" in n)) print "| - | L4 | arrived tcp/80 | NONE | no SYN reached the WAN |"
	}' "$1"
}

# Snapshot: "iface peer8 handshake_epoch endpoint" per peer. $EPF holds the endpoints.
snap() {
	wg show all endpoints 2>/dev/null | awk '{print $1, substr($2, 1, 8), $3}' > "$EPF"
	wg show all latest-handshakes 2>/dev/null | awk -v ep="$EPF" '
		BEGIN { while ((getline l < ep) > 0) { split(l, a, " "); e[a[1] " " a[2]] = a[3] } }
		{ k = $1 " " substr($2, 1, 8); print k, $3, ((k in e) ? e[k] : "(none)") }' > "$1"
}

watch() {
	mins=${1:-10}
	isnum "$mins" || { echo "watch: MINUTES must be a whole number"; return 2; }
	header "watch $mins min"
	thead
	if ! have wg; then row VPN "watch" FAIL "wg not found: use capture instead"; return 1; fi
	end=$(($(date +%s) + mins * 60))
	prev=$(mktemp); cur=$(mktemp); EPF=$(mktemp)
	trap 'end=0' INT TERM
	snap "$prev"
	while read -r w p t e; do
		if [ "$t" -eq 0 ]; then h=never; else h=$(date -u -d "@$t" +%H:%M:%S 2>/dev/null || echo "$t"); fi
		row VPN "$w peer $p" BASE "handshake $h, endpoint $e"
	done < "$prev"
	while [ "$(date +%s)" -lt "$end" ]; do
		sleep 5
		snap "$cur"
		awk 'NR == FNR {p[$0] = 1; next} !($0 in p)' "$prev" "$cur" | while read -r w p t e; do
			if [ "$t" -eq 0 ]; then h=never; else h=$(date -u -d "@$t" +%H:%M:%S 2>/dev/null || echo "$t"); fi
			row VPN "$w peer $p" CHANGE "handshake $h, endpoint $e"
		done
		awk 'NR == FNR {c[$1 " " $2] = 1; next} !(($1 " " $2) in c) {print $1, $2}' "$cur" "$prev" | while read -r w p; do
			row VPN "$w peer $p" GONE "peer removed"
		done
		cp "$cur" "$prev"
	done
	trap - INT TERM
	rm -f "$prev" "$cur" "$EPF"
}

case "$1" in
	info|"") info ;;
	capture) shift; capture "$@" ;;
	watch) shift; watch "$@" ;;
	*) sed -n '2,12p' "$0"; exit 2 ;;
esac
