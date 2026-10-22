# VPN check: can a VPN connect over this connection?

One command, any connection (Wi-Fi, LTE, iPhone hotspot), no server of your own. [`scripts/vpn.awk`](../scripts/vpn.awk) runs in the Blink local shell and in macOS Terminal, prints a table and a verdict per VPN type, and saves both to a log.

| Where | Install | Run |
|---|---|---|
| Blink | `scripts/vpn.awk`, `stun-req.bin`, `ntp-req.bin` -> iCloud Drive > Blink > scripts; `blink/snips/vpn/` -> iCloud Drive > Blink > snips > vpn | snip `vpn/run` (no fields, `⌘↩` from the list works); `vpn/run-server` adds a TCP test to your server; `vpn/run-home` adds your home WAN IP |
| macOS | `mkdir -p ~/vpn && cd ~/vpn && for f in vpn.awk stun-req.bin ntp-req.bin; do curl -sSLO https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/$f; done` | `awk -f ~/vpn/vpn.awk`, optional `-v server=IP -v tcp=PORT`, `-v home_ip=IP`, `-v ladder=1` |

Optional parameters: `-v home_ip=IP` is your home WAN IPv4. If the run exits there, Teleport (or another VPN, also one on the router) is carrying the traffic, and a home resolver answering `dig @1.1.1.1` is INFO, not HIJACK. `-v ladder=1` (macOS only) adds a DF ping ladder.

The time columns show local time first (with the zone), then UTC; the log file name stays in UTC.

Run it once on Wi-Fi and once on LTE (on iPhone: Wi-Fi off, or Cellular Data off for a Wi-Fi-only run). The same output is saved as a text file, for sending it on without copying from the terminal: Files > iCloud Drive > Blink > `vpn-wifi-…`, `vpn-lte-…`, `vpn-hotspot-…`.

## What it checks

| Row | Probe | Needed by |
|---|---|---|
| connection | iOS: `ifconfig en0` / `pdp_ip0` (169.254 = no Wi-Fi IP, 192.0.0.x = IPv6-only with CLAT); macOS: route to 1.1.1.1 (follows VPN split routes), `networksetup` for Wi-Fi, `172.20.10.x` = iPhone hotspot. No link found but the probes pass: WARN, printed after them | context |
| DNS system resolver, dig @gateway, dig @1.1.1.1 | one name (example.com), 3 s cap each. System resolver: `curl` (getaddrinfo, what apps use). Gateway: macOS route gateway; Blink has no `route`, so `dig` with the configured server. Then `dig @1.1.1.1`. System FAIL with raw OK = WARN row "DNS reading": the break is in the system resolver path, not named further | everything: STUN, NTP, the HTTPS hosts and the ping name are resolved once each (`dig`, 3 s cap, first the configured server, then 1.1.1.1) and passed as addresses |
| VPN already on? | iOS: a `utun`/`ipsec`/`ppp` with IPv4 outside 192.0.0.x and outside 100.64.0.0/10, or the public IPv4 of the default path in another /16 than a request bound to the link (`curl --interface en0` / `pdp_ip0`). A `utun` in 100.64.0.0/10 (Tailscale-like) alone is not a VPN finding. On Wi-Fi with cellular up, a match with `pdp_ip0` means iOS sends the run over LTE (row `path`). If the bound request itself fails, row `path` is WARN: "Wi-Fi itself has no internet, this run uses another path (LTE/VPN)". macOS: the route to 1.1.1.1 goes via `utun`/`ppp`/`ipsec` | WARN = the rows describe the VPN, not the network |
| traffic exits at home WAN | only with `-v home_ip=`: public IPv4 of the run = home_ip. YES = Teleport carries the traffic (also when it runs on the router and the device sees no tunnel; then "VPN already on?" is INFO) | context: rows then describe the path through the tunnel |
| TCP 443, HTTPS to 1.1.1.1 (control) | `nc`, `curl` by IP, `/cdn-cgi/trace`, with stage times (tcp, tls, total) | everything |
| login page (Apple probe) | Apple captive probe; the name is resolved first, no address = login page not tested | everything: no VPN before the portal login |
| UDP 3478, 19302 | STUN binding request to Cloudflare and Google over IPv4 (`nc -4`; `-6` on IPv6-only links), answer expected | WireGuard, Teleport, UniFi Identity, OpenVPN UDP, L2TP/IPsec |
| UDP 123, 53 | NTP to time.apple.com; "UDP 53 (transport only)": `id.server` CHAOS TXT to 1.1.1.1, which only Cloudflare answers with its site code. It says that UDP 53 goes out and an answer comes back, nothing about the device. Someone else answering is `HIJACK` (Control D is named when `verify.controld.com` comes back as `147.185.34.1`), or INFO when the run exits at `home_ip` (the home resolver behind Teleport) | tells "UDP blocked" from "UDP only to DNS/NTP" |
| IPv6 | `curl -6` to one.one.one.one; FAIL = the link has IPv6 but nothing answers (dropped, e.g. by a VPN without IPv6) | context (Teleport needs IPv6 on the gateway WAN in some cases: home side, not checked here) |
| ping 1.1.1.1, 8.8.8.8, www.microsoft.com | `ping -c 2` to each: the targets of a UniFi Travel Router's internet check | Teleport and WireGuard on a UTR (firmware 6.6.117+, [teleport.md](teleport.md) H7) |
| HTTPS unifi.ui.com, api.ui.com | `curl`, certificate checked, stage times (dns from `dig`, tcp, tls, total), up to 3 tries per host | Teleport (cloud brokering) |
| HTTPS www.theverge.com, controlplane.tailscale.com | same; big TLS handshakes, next to the control (1.1.1.1) they tell an MTU/MSS hole from a host that is down. TCP connects and TLS hangs (curl 28) = `HANG`, WARN row "TLS hangs after TCP connect": path MTU/MSS suspect, not "unreachable" | context ([teleport.md](teleport.md) F1) |
| DF ping ladder | only macOS, only with `-v ladder=1`: `ping -D -s` from the Wi-Fi MTU down to 1280, after a plain ping (no reply = "ICMP filtered, ladder skipped"). "Message too long" or "frag needed" = the kernel or the path reports its MTU (PMTUD works). Silence at sizes nothing reported on = black hole suspect | MTU hole between the uplink and the tunnel |
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

One more line, for Teleport or WireGuard on a UniFi Travel Router: LIKELY NO on firmware 6.6.117+ when none of the three ping targets answers (the UTR then shows "No Internet" and its Teleport and WireGuard clients wait for that check; its OpenVPN client does not), "not tested" when a VPN is on, the run exits at `home_ip` (the pings went through Teleport) or the link has no IPv4.

No verdict rests on one failure: each HTTPS host gets 3 tries, and the verdict names the stage (TLS hangs after TCP / no TCP / DNS / certificate).

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
| iOS puts 192.0.0.x on `utun0` by itself (seen with no full-tunnel VPN: the public IP was the carrier's on each network), so 192.0.0.x is not treated as a VPN | CONFIRMED on that run. What owns it: UNKNOWN (192.0.0.0/29 is the RFC 7335 CLAT block). The interface pattern then missed `pdp_ip0:` (underscore), so a `pdp_ip` address could show under the `utun` before it; fixed 2026-10-21 | first device run |
| A VPN can be on without a `utun` address the script sees | CONFIRMED on an iPhone 2026-10-20 22:33 UTC: on T-Mobile LTE with a VPN home, egress 71.231.163.56 (Comcast, home) instead of 172.56.x (T-Mobile), IPv6 timed out, no "VPN already on?" row. Why the interface scan missed it: UNKNOWN | hence the egress comparison |
| `curl --interface en0` / `pdp_ip0` in Blink binds to the link and gets around a normal full-tunnel VPN | HYPOTHESIS: by xnu and curl source; not yet run on an iPhone, and a VPN with enforced routes defeats it. On failure the row stays as before | |
| A UniFi Travel Router decides "Internet" by ping to 1.1.1.1, 8.8.8.8 or www.microsoft.com, and from 6.6.117 its Teleport client waits for that check | CONFIRMED by static analysis of firmware 6.6.115, 6.6.117, 6.6.118, 6.6.122 (nothing run); that it is the cause on a given uplink: LIKELY until the app shows "Waiting for WAN to become reachable" | [teleport.md](teleport.md) H7 |

| Tailscale's `utun` (100.64.0.0/10) is not a full-tunnel VPN by itself | HYPOTHESIS: by the address range (the user's Mac runs Tailscale; no run compared the two). The script now says "VPN" for such a `utun` only when the egress differs from the one bound to the link | [teleport.md](teleport.md) |
| A router-level Teleport leaves no `utun` on the iPhone: the old run printed "VPN: none seen" while the traffic exited at the home WAN | CONFIRMED on an iPhone 2026-10-21 07:51 PDT (xfinitywifi, UTR with Teleport: exit 71.231.163.56) | user report; the log is not in the repo |
| A broken system resolver costs 30 s per name (so per row that resolves a name) | CONFIRMED on that run (iPhone, 07:51 PDT); hence the 3 s cap and one lookup per name | user report |
| `ping -D` "Message too long" is the local kernel refusing a size it learned from ICMP (PMTUD works); a black hole is silent loss | CONFIRMED on a Mac 2026-10-21: 1372-byte payload refused locally, 1272 passes, path MTU through Teleport between 1300 and 1400. Whether such a path also hangs TLS: see [teleport.md](teleport.md) F1 and the open question next to it | user report |
| Blink's `dig` takes `+noall +answer +stats +time=3 +tries=1`, `curl` takes `--resolve` (also `[IPv6]`) and `--interface`, `ping` takes `-D` | HYPOTHESIS: standard options, nothing run in Blink yet. A refused `--interface` (curl 2 or 45) is reported as INFO; a refused `dig` option shows as DNS FAIL | |

## Limits

- UDP to your own server's port cannot be confirmed from the phone: WireGuard and most VPN servers stay silent to unknown packets. For that, watch the server side (`scripts/teleport-cgm.sh capture` on a UniFi gateway).
- UDP 443 (QUIC) is not tested: Blink's curl has no HTTP/3 and its `nc` sends at most 1024 bytes per datagram, below QUIC's 1200.
- UDP probes go over IPv4 (IPv6 on IPv6-only links); IPv6 is otherwise checked over HTTPS only.
- Blink's awk aborts (`towc: multibyte conversion failure`) when a regex meets bytes that are not valid UTF-8, and UDP replies and web pages contain such bytes. Replies are therefore tested with `index()` and `==` only (reproduced with a native build of Blink's awk: the first version of this script crashed on a real NTP reply, this one does not).
- First iPhone run 2026-10-20: the LTE screen output stopped at the IPv6 row, but the saved log has every row and the verdict, so the script finished. When the screen looks cut off, the log is the result.
- The names are resolved with `dig`, not the system resolver, so a host can resolve here and still fail in an app; the "DNS system resolver" row is the only one that uses `getaddrinfo`. On Blink the gateway row is the configured server (no `route`); if `dig` prints no `;; SERVER:` line, the row names none.
- DNS rows and the DF ladder were run with fake commands only (macOS and Blink layouts, dead resolver, home exit, Tailscale `utun`, MTU hang, ICMP filtered; identical output on mawk and nawk, 2026-10-22). Not run on an iPhone or a Mac.
- Fake commands: binary STUN/NTP replies and a Latin-1 portal page, 152 platform/network/argument combinations in a UTF-8 locale, identical output on Blink's awk build, mawk and nawk. Not run on an iPhone or a Mac yet.
