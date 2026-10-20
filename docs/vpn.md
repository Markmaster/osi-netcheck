# VPN check: can a VPN connect over this connection?

One command, any connection (Wi-Fi, LTE, iPhone hotspot), no server of your own. [`scripts/vpn.awk`](../scripts/vpn.awk) runs in the Blink local shell and in macOS Terminal, prints a table and a verdict per VPN type, and saves both to a log.

| Where | Install | Run |
|---|---|---|
| Blink | `scripts/vpn.awk`, `stun-req.bin`, `ntp-req.bin` -> iCloud Drive > Blink > scripts; `blink/snips/vpn/` -> iCloud Drive > Blink > snips > vpn | snip `vpn/run` (no fields, `⌘↩` from the list works); `vpn/run-server` adds a TCP test to your server |
| macOS | `mkdir -p ~/vpn && cd ~/vpn && for f in vpn.awk stun-req.bin ntp-req.bin; do curl -sSLO https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/$f; done` | `awk -f ~/vpn/vpn.awk`, optional `-v server=IP -v tcp=PORT` |

Run it once on Wi-Fi and once on LTE (on iPhone: Wi-Fi off, or Cellular Data off for a Wi-Fi-only run). The same output is saved as a text file, for sending it on without copying from the terminal: Files > iCloud Drive > Blink > `vpn-wifi-…`, `vpn-lte-…`, `vpn-hotspot-…`.

## What it checks

| Row | Probe | Needed by |
|---|---|---|
| connection | iOS: `ifconfig en0` / `pdp_ip0` (169.254 = no Wi-Fi IP, 192.0.0.x = IPv6-only with CLAT), a `utun`/`ipsec` with IPv4 = a VPN is already on; macOS: route to 1.1.1.1 (follows VPN split routes), `networksetup` for Wi-Fi, `172.20.10.x` = iPhone hotspot | context |
| TCP 443, HTTPS to 1.1.1.1 | `nc`, `curl` by IP | everything |
| Wi-Fi login page | Apple captive probe | everything: no VPN before the portal login |
| UDP 3478, 19302 | STUN binding request to Cloudflare and Google over IPv4 (`nc -4`; `-6` on IPv6-only links), answer expected | WireGuard, Teleport, UniFi Identity, OpenVPN UDP, L2TP/IPsec |
| UDP 123, 53 | NTP to time.apple.com; `id.server` CHAOS TXT to 1.1.1.1, which only Cloudflare answers with its site code (`HIJACK` = the network answers DNS itself; Control D is named when `verify.controld.com` comes back as `147.185.34.1`) | tells "UDP blocked" from "UDP only to DNS/NTP" |
| IPv6 | `curl -6` to one.one.one.one | context (Teleport needs IPv6 on the gateway WAN in some cases: home side, not checked here) |
| HTTPS unifi.ui.com, api.ui.com | `curl`, certificate checked | Teleport (cloud brokering) |
| TCP server:port | `nc -z`, only with `-v server=` | OpenVPN over TCP |

## Verdict

Inferred from the rows, not measured on the VPN itself. UniFi Identity's One-Click VPN is WireGuard (51820) or OpenVPN (10118, UDP or TCP) straight to the console's public IP, so it is rated with them, not with Teleport.

| Rows | Teleport | WireGuard, OpenVPN UDP, Identity (UDP) | OpenVPN TCP, Identity (TCP) | L2TP/IPsec |
|---|---|---|---|---|
| login page | NO until login | NO until login | NO until login | NO until login |
| nothing outside answers (1.1.1.1, UniFi cloud, IPv6, UDP) | NO | NO | NO | NO |
| STUN answers, UniFi cloud OK | LIKELY | POSSIBLE (STUN ports only; your port not testable) | LIKELY on 443 | UNKNOWN (500/4500 not testable) |
| STUN no answer, DNS/NTP answer | NO (likely) | NO (likely) | depends on TCP | NO (likely) |
| no UDP answer at all | NO (likely) | NO (likely) | depends on TCP | NO (likely) |
| TLS to the UniFi cloud intercepted | NO (likely) | not affected | UNLIKELY | not affected |
| STUN names do not resolve / request files missing | UNKNOWN (fix DNS / copy files) | UNKNOWN | depends on TCP | UNKNOWN |

POSSIBLE, not LIKELY, for your own WireGuard/OpenVPN port: networks that open only video-call ports (3478, 19302) pass STUN and still drop 51820 or 1194. The final word is the VPN app on the same connection. If the app fails while the rows say LIKELY, the cause is not this network: server side, account, binding, firmware.

## Claims

| Claim | Status | Source |
|---|---|---|
| Teleport uses WireGuard; works with the gateway and the client behind NAT; needs IPv6 on the gateway WAN in some circumstances | CONFIRMED | UniFi Help Center, "UniFi Gateway - Teleport VPN" |
| Most VPNs except Teleport need a public IP at home | CONFIRMED | UniFi Help Center, "UniFi Remote Access: VPN and Port Forwarding" |
| UniFi Identity One-Click VPN = OpenVPN (port 10118, UDP recommended, TCP possible) or WireGuard (51820); the console needs a public IP, not CGNAT 100.64.0.0/10 | CONFIRMED | help.ui.com articles 17167292342295, 17198673056151, 27900437407895 (fetched 2026-10-20) |
| `dig @1.1.1.1 CH TXT id.server` returns a Cloudflare site code | CONFIRMED on an iPhone 2026-10-20: `"sea07"` (the first version expected 3 capitals like `"SJC"` and printed a false HIJACK) | that a hijacking resolver does not return one: HYPOTHESIS |
| An iOS DNS profile (Control D) does not catch `dig @1.1.1.1`, so it cannot cause HIJACK | CONFIRMED on an iPhone 2026-10-20 with the Control D profile on: `dig @1.1.1.1 verify.controld.com` empty (Control D answers `147.185.34.1`), `id.server` = `"sea07"`. The HIJACK rows of that run came from the site-code pattern | first device run |
| WireGuard runs over UDP only | CONFIRMED | WireGuard protocol design |
| A TCP or relay fallback for Teleport | UNKNOWN | not documented, so "NO (likely)" when UDP is blocked |
| UDP to STUN on 3478 and 19302 working means a WireGuard port works too | HYPOTHESIS | a filter can block single ports; the verdict says LIKELY, not YES |
| Blink commands used here (`nc -u -w N < file`, `curl -6`, `ifconfig`, `uname`, `date`) | CONFIRMED on an iPhone 2026-10-20 (Wi-Fi behind a UniFi Travel Router, and T-Mobile LTE with CLAT): all rows ran, STUN/NTP answered on both | first device run |
| iOS puts 192.0.0.x on `utun0` by itself (seen with no full-tunnel VPN: the public IP was the carrier's on each network), so 192.0.0.x is not treated as a VPN | CONFIRMED on that run (what owns `utun0`: UNKNOWN) | first device run |

## Limits

- UDP to your own server's port cannot be confirmed from the phone: WireGuard and most VPN servers stay silent to unknown packets. For that, watch the server side (`scripts/teleport-cgm.sh capture` on a UniFi gateway).
- UDP 443 (QUIC) is not tested: Blink's curl has no HTTP/3 and its `nc` sends at most 1024 bytes per datagram, below QUIC's 1200.
- UDP probes go over IPv4 (IPv6 on IPv6-only links); IPv6 is otherwise checked over HTTPS only.
- Blink's awk aborts (`towc: multibyte conversion failure`) when a regex meets bytes that are not valid UTF-8, and UDP replies and web pages contain such bytes. Replies are therefore tested with `index()` and `==` only (reproduced with a native build of Blink's awk: the first version of this script crashed on a real NTP reply, this one does not).
- First iPhone run 2026-10-20: Wi-Fi and LTE both ran through the UDP rows; the LTE paste ended at the IPv6 row with no error text, so whether that run finished is not known yet.
- Fake commands: binary STUN/NTP replies and a Latin-1 portal page, 152 platform/network/argument combinations in a UTF-8 locale, identical output on Blink's awk build, mawk and nawk. Not run on an iPhone or a Mac yet.
