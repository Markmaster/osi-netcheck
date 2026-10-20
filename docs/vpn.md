# VPN check: can a VPN connect over this connection?

One command, any connection (Wi-Fi, LTE, iPhone hotspot), no server of your own. [`scripts/vpn.awk`](../scripts/vpn.awk) runs in the Blink local shell and in macOS Terminal, prints a table and a verdict per VPN type, and saves both to a log.

| Where | Install | Run |
|---|---|---|
| Blink | `scripts/vpn.awk`, `stun-req.bin`, `ntp-req.bin` -> iCloud Drive > Blink > scripts; `blink/snips/vpn/` -> iCloud Drive > Blink > snips > vpn | snip `vpn/run` (no fields, `⌘↩` from the list works); `vpn/run-server` adds a TCP test to your server |
| macOS | `mkdir -p ~/vpn && cd ~/vpn && for f in vpn.awk stun-req.bin ntp-req.bin; do curl -sSLO https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/$f; done` | `awk -f ~/vpn/vpn.awk`, optional `-v server=IP -v tcp=PORT` |

Run it once on Wi-Fi and once on LTE (on iPhone: Wi-Fi off, or Cellular Data off for a Wi-Fi-only run). The log name carries the connection type: `vpn-wifi-…`, `vpn-lte-…`, `vpn-hotspot-…`.

## What it checks

| Row | Probe | Needed by |
|---|---|---|
| connection | iOS: `ifconfig en0` / `pdp_ip0`; macOS: default route, `system_profiler`, `172.20.10.x` = iPhone hotspot, `utun` = a VPN is already on | context |
| TCP 443, HTTPS to 1.1.1.1 | `nc`, `curl` by IP | everything |
| Wi-Fi login page | Apple captive probe | everything: no VPN before the portal login |
| UDP 3478, 19302 | STUN binding request to Cloudflare and Google, answer expected | WireGuard, Teleport, UniFi Identity, OpenVPN UDP, L2TP/IPsec |
| UDP 123, 53 | NTP to time.apple.com, DNS to 1.1.1.1 | tells "UDP blocked" from "UDP only to DNS/NTP" |
| IPv6 | `curl -6` to one.one.one.one | context (Teleport needs IPv6 on the gateway WAN in some cases: home side, not checked here) |
| HTTPS unifi.ui.com, api.ui.com | `curl`, certificate checked | Teleport, UniFi Identity (cloud brokering) |
| TCP server:port | `nc -z`, only with `-v server=` | OpenVPN over TCP |

## Verdict

Inferred from the rows, not measured on the VPN itself:

| Rows | Teleport / Identity | WireGuard, OpenVPN UDP | OpenVPN TCP | L2TP/IPsec |
|---|---|---|---|---|
| nothing outside answers | NO | NO | NO | NO |
| login page | NO until login | NO until login | NO until login | NO until login |
| STUN 3478/19302 answer, UI cloud OK | LIKELY | LIKELY (your port not testable) | LIKELY on 443 | UNKNOWN (500/4500 not testable) |
| STUN fails, DNS/NTP answer | NO (likely) | NO | depends on TCP | NO |
| STUN fails, nothing on UDP | NO (likely) | NO | depends on TCP | NO |
| TLS to UI intercepted | NO (likely) | not affected | not affected | not affected |
| STUN names do not resolve | UNKNOWN (fix DNS) | UNKNOWN | depends on TCP | UNKNOWN |

The final word is the VPN app on the same connection. If the app fails while the rows say LIKELY, the cause is not this network: server side, account, binding, firmware.

## Claims

| Claim | Status | Source |
|---|---|---|
| Teleport uses WireGuard; works with the gateway and the client behind NAT; needs IPv6 on the gateway WAN in some circumstances | CONFIRMED | UniFi Help Center, "UniFi Gateway - Teleport VPN" |
| Most VPNs except Teleport need a public IP at home | CONFIRMED | UniFi Help Center, "UniFi Remote Access: VPN and Port Forwarding" |
| WireGuard runs over UDP only | CONFIRMED | WireGuard protocol design |
| A TCP or relay fallback for Teleport | UNKNOWN | not documented, so "NO (likely)" when UDP is blocked |
| UDP to STUN on 3478 and 19302 working means a WireGuard port works too | HYPOTHESIS | a filter can block single ports; the verdict says LIKELY, not YES |
| Blink commands used here (`nc -u -w N < file`, `curl -6`, `ifconfig`, `uname`, `date`) | CONFIRMED by source, not run on a device yet | see [teleport.md](teleport.md) for source lines |

## Limits

- UDP to your own server's port cannot be confirmed from the phone: WireGuard and most VPN servers stay silent to unknown packets. For that, watch the server side (`scripts/teleport-cgm.sh capture` on a UniFi gateway).
- UDP 443 (QUIC) is not tested: Blink's curl has no HTTP/3 and its `nc` sends at most 1024 bytes per datagram, below QUIC's 1200.
- IPv4 for UDP probes; IPv6 is checked over HTTPS only.
- Simulation only so far: fake commands, 96 platform/network/argument combinations, identical output on Blink's awk build, mawk and nawk.
