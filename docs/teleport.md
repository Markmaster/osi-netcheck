# UniFi Teleport on a travel router: uplink or router?

Question: UniFi Teleport on a UniFi Travel Router (UTR) never connects. Is the cause (a) the uplink filtering Teleport/WireGuard, or (b) the UTR firmware or its binding? The scripts collect facts layer by layer and do not print a verdict. The verdict comes from comparing runs (table at the end).

| File | Runs on | Does |
|---|---|---|
| [`scripts/teleport.awk`](../scripts/teleport.awk) | Mac or iPhone (Blink) behind the UTR | L1-L7 checks, UDP/TCP probes to home, one table per run, saved to a log |
| [`scripts/teleport-cgm.sh`](../scripts/teleport-cgm.sh) | UniFi gateway (CGM, UCG Max), root over SSH | `info`: WAN/NAT, WireGuard, DNS/TLS to UI hosts, log lines. `capture`: what reaches the WAN. `watch`: WireGuard handshakes |
| `scripts/stun-req.bin`, `scripts/wg-probe.bin` | next to `teleport.awk` | 20-byte STUN binding request; 148 bytes shaped like a WireGuard handshake initiation (filler, no keys) |
| [`blink/snips/tp`](../blink/snips/tp) | Blink | `tp/run`, `tp/watch`, `tp/cgm-copy`, `tp/cgm`, `tp/0-runs` (cheat sheet) |

## Claims

| Claim | Status | Source |
|---|---|---|
| UTR 6.6.122 EA, bound to a UCG Max, LAN 10.10.10.0/24, gateway and DNS 10.10.10.1 | CONFIRMED | user |
| Uplink xfinitywifi / XFINITY_Guest, 5 GHz; portal shows "success" only for the router; phones and laptops get internet without a portal | CONFIRMED | user. On 2026-10-20 22:34 UTC the app showed XFINITY_Guest on 2.4 GHz Ch. 1, -64 dBm: band and AP are not fixed, note them per run |
| Clients behind the UTR have internet; Teleport never connects, also after a UTR reboot | CONFIRMED | user |
| Teleport worked on 6.6.115 on the same kind of uplink, fails on 118 and 122 | CONFIRMED | user |
| ICMP is filtered on this uplink | CONFIRMED | user, earlier run (SSID, AP and targets not recorded: re-test with the ping row, Cellular Data off) |
| Home DNS is fail-close: ctrld to Control D over DoQ | CONFIRMED | user |
| H1: the office uplink blocks WireGuard UDP | HYPOTHESIS | against it: 115 worked on the same uplink type; on 2026-10-20 UDP 3478, 19302, 123 and 53 went out and back from behind the UTR on XFINITY_Guest. Teleport's own port and the WG-shaped probe were not tested |
| H2: firmware 118+ changed how Teleport connects | HYPOTHESIS | for it: the version boundary |
| H3: this UTR's binding on the CGM is broken | HYPOTHESIS | |
| H4: the home DNS filter blocks a host Teleport needs | HYPOTHESIS | `teleport-cgm.sh info` DNS rows, Control D activity log for the CGM |
| H5: the CGM WAN is behind NAT, so nothing from outside reaches it directly | testable | `teleport-cgm.sh info`, row "inbound to WAN". Per UniFi docs Teleport works behind NAT on both sides, so H5 alone does not break Teleport; it only blinds `capture` |
| H6: the CGM WAN has no IPv6 and this setup is one of the cases where Teleport needs it | HYPOTHESIS | UniFi docs: "Teleport requires an IPv6 connection on your gateway's WAN in some circumstances" (which ones: not documented). `teleport-cgm.sh info`, row "WAN IPv6" |
| Teleport uses WireGuard; works with gateway and client behind NAT | CONFIRMED | UniFi Help Center, "UniFi Gateway - Teleport VPN". Port, relay and NAT-traversal details are not documented |
| Quick check of any connection (no UTR, no server): can a VPN connect here? | - | [vpn.md](vpn.md), `scripts/vpn.awk` |
| Which UI host the UTR's Teleport client uses for brokering | CONFIRMED by firmware strings (6.6.115-6.6.122): `https://cloudaccess.svc.ubnt.com/teleport/` (request access, ICE config, connect) | `usr/bin/teleport-client`. Now first in the `hosts` default; the ui.com hosts stay as context (`*.ui.com` has wildcard DNS) |
| 2026-10-20 22:33-22:34 UTC, iPhone behind the UTR on XFINITY_Guest: TCP 443, HTTPS, STUN 3478/19302, NTP, DNS to Cloudflare, unifi.ui.com and api.ui.com all OK; egress 67.164.242.64 (Comcast, Cloudflare ORD), not home. Same minute, UniFi app: uplink "No Internet", Teleport row "Browse..." | CONFIRMED | vpn-wifi logs 223348, 223436 and an app screenshot. The DNS site (ORD on Wi-Fi, SEA on LTE) shows these probes did not leave over LTE |
| 2026-10-20 22:33 UTC, iPhone on T-Mobile LTE with Teleport home: egress 71.231.163.56 (Comcast Washington, LIKELY the CGM WAN). Every VPN works on LTE; the failing case is the UTR's Teleport on the office guest Wi-Fi | CONFIRMED | vpn-lte log 223300, user. So the CGM's Teleport server and brokering work for a phone on IPv6-only LTE (CLAT): H4 and H6 weakened for that path |
| H7: the UTR's own internet check is ICMP only: `unifi_mwan` pings 1.1.1.1, 8.8.8.8, www.microsoft.com and writes `/var/run/unifi_mwan.status.ping.<if>` only on a reply; `mcad` (app status) falls back to ping 8.8.8.8, 1.1.1.1. When all fail, ARP to the gateway keeps routing up ("ICMP blocked? -> consider UP"), so clients have internet while the app says "No Internet". From 6.6.117 `teleport-client` checks that file before every connect, including the app's play button, and otherwise sets "Waiting for WAN to become reachable" and never contacts the broker. 6.6.115 gated only auto-reconnect | code: CONFIRMED by static analysis of the dl.ui.com images 6.6.115, 117, 118, 122 (nothing run; two independent re-checks). Cause here: LIKELY until the ping row fails behind the UTR or the app shows that status text | `usr/bin/unifi_mwan`, `mcad`, `teleport-client`. Against it: the user's own posts on the 6.6.118 thread (2026-10-14, comment f9a75544) and the 6.6.122 thread say Teleport held 6h+ on xfinitywifi and on XFINITY_Guest came up when started manually; that fits only if ping passed on that AP then. Which SSID/AP each earlier fact was on is the open question |
| No user setting changes the UTR's check targets; switching to the Official channel (6.6.118) does not help: `teleport-client` is byte-identical in 6.6.117, 118 and 122 | CONFIRMED by firmware (fixed inittab arguments, md5) | the targets are not configurable in the app (LIKELY: app not inspected) |
| The UTR's WireGuard client waits for the same ICMP file; its OpenVPN client has no such check | WireGuard: CONFIRMED by firmware. OpenVPN not gated: LIKELY (one 6.6.115 user report, untested here) | `usr/etc/wireguard-wan-ready.sh`, `usr/bin/openvpn-client` |
| H8: no Teleport target is active on the UTR. "Browse..." on the Teleport row appears when no console is selected; a failed connect also clears the active flag (`saved_vpns.sh --clear-active teleport`), so "Browse..." does not tell H7 from H3/H8 | LIKELY (community screenshots, firmware) | select CGM and press play, then read the status text (table below) |

## What each side can see

| Test | Mac | Blink (iPhone) | CGM |
|---|---|---|---|
| L1 UTR uplink RSSI, band, reconnects | no | no | no: manual, UniFi app |
| L2 own Wi-Fi link to the UTR | RSSI, channel (`system_profiler`) | no: iOS gives apps no RSSI | - |
| L2 behind the UTR (client IP, route) | yes | `ifconfig en0`; warns if cellular (`pdp_ip0`) has an address | - |
| L3 public IP, egress = home? | yes | yes | own WAN and public IP |
| L3 traceroute | yes | no: not in Blink | - |
| L4 TCP 443/80 | yes | yes | - |
| L4 UDP out and back (STUN) | yes | yes | - |
| L4 UDP/TCP probes to home: sent | yes | yes | - |
| L4 probes to home: arrived | - | - | `tcpdump` on the WAN, sees packets before the firewall |
| L5/L6 TLS timings, chain, interception | yes | yes | yes (home side) |
| L7 DNS via the UTR and its upstream | yes | yes | own resolver, ctrld |
| L7 captive portal probes (Apple, Google, Firefox) | yes | yes | - |
| Teleport handshake | no | no | `wg show` |
| Watch for N minutes | yes | only in the foreground, screen on | yes |

Blink facts behind the "yes" (sources: Blink `a90b442`, `holzschu/ios_system` v3.0.3, `holzschu/network_ios` v0.3):

| Fact | Status | Where |
|---|---|---|
| `nc -u` exists; `-uz` writes 4 x 1 byte "X" and exits, the exit code says nothing about delivery | CONFIRMED by source | `network_ios sources/netcat/netcat.c:514,1415-1426` |
| `nc -u -w N < file` sends the file, then returns after N s without input | CONFIRMED by source | `netcat.c:1212-1236` |
| `curl` 8.1.2 uses Secure Transport on iOS: `-v` prints one `Server certificate: <subject>` line per certificate | CONFIRMED by source | `curl/config_iphone/curl_config.h:926`, `lib/vtls/sectransp.c:2970` |
| `date`, `ifconfig`, `uname` exist; `sleep`, `printf`, `traceroute`, `route`, `sh` do not | CONFIRMED by source | Blink `Resources/commandDictionary.plist` |
| `geo track` exists | CONFIRMED by source | Blink `Blink/Commands/geo.m:107`. That it keeps local commands running in the background: HYPOTHESIS |
| `uname -m` returns the model (`iPhone…`) on iOS; `ifconfig` output format | HYPOTHESIS | the script also checks `$HOME` for the iOS app container |
| All of the above on a device for this script | NOT RUN YET | |

## Install

| Where | How |
|---|---|
| Mac | `mkdir -p ~/tp && cd ~/tp && for f in teleport.awk teleport-cgm.sh stun-req.bin wg-probe.bin; do curl -sSLO https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/$f; done` |
| Blink | `scripts/` -> iCloud Drive > Blink > scripts, `blink/snips/tp/` -> iCloud Drive > Blink > snips > tp ([HOWTO](../blink/HOWTO.md)) |
| CGM | from the Mac: `scp ~/tp/teleport-cgm.sh root@CGM_LAN_IP:/tmp/`; from Blink: snip `tp/cgm-copy`; or on the CGM: `curl -sSLo /tmp/teleport-cgm.sh https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/teleport-cgm.sh` |

SSH to the CGM from the office needs a path home that is not the UTR's Teleport: for example the iPhone on LTE with a VPN home, with Blink as the SSH client. That VPN's own handshake then shows up in `watch`; tell it apart by its endpoint IP.

## Runs

Same for every run: UTR firmware 6.6.122, same binding, same UTR placement, same client device for runs you compare, same home config. Change one thing per run and write it down.

| Run | Changed vs run 1 | UTR uplink | Client | CGM |
|---|---|---|---|---|
| 0 | - | - | - | `info` once: note the Teleport WireGuard port and the "inbound to WAN" row |
| 1 | baseline | office xfinitywifi | Mac behind the UTR (or iPhone with Cellular Data off) | `capture 300 CLIENT_PUBLIC_IP`, then `watch 10` |
| 1b | Teleport off in the UTR | office | same | `capture` |
| 2 | uplink = iPhone hotspot (LTE), the control run | iPhone hotspot | Mac behind the UTR | `capture 300 LTE_PUBLIC_IP`, `watch 10` |
| 3 | no UTR (optional) | - | Mac directly on xfinitywifi | `capture` |

Next, after the 2026-10-20 findings (cheapest and most decisive first). Paused by the user on 2026-10-21: steps A-E are still open.

| Step | Do | Decides |
|---|---|---|
| A | UniFi app > UTR > Teleport row ("Browse...") > Consoles you manage > CGM (or gear > VPN & Teleport > Select Host), press play, read the status text for 60 s, screenshot with time | "Waiting for WAN to become reachable": H7 on this device. CGM missing or "Unavailable": binding or the Teleport checkbox on the CGM (H3). "Access denied", "Token rejected", "re-pair", "Cannot reach teleport server": binding or broker, not ICMP. Connected: H8, nothing was selected |
| B | iPhone behind the UTR, Cellular Data off, no VPN: snip `vpn/run` (ping row), then `tp/run` | ping 0/3: H7's precondition holds on this AP. Any reply: the ICMP form of H7 is out for this AP |
| C | Same office, UTR uplink on xfinitywifi instead of XFINITY_Guest: repeat A and B | ping and Teleport work there but not on XFINITY_Guest: the SSID/AP drops ICMP, the 117+ check does the rest |
| D | Control: UTR uplink = iPhone hotspot, repeat A | connects: uplink-specific cause. Fails: binding or home side; take a UTR support file at once, without a reboot (the UTR keeps logs in RAM) |
| E | If H7 holds and a tunnel is needed now: OpenVPN server on the CGM, `.ovpn` imported on the UTR (not gated, LIKELY), or the UTR uplink on the hotspot. Downgrade to 6.6.115 only via Recovery Mode + TFTP (wipes the config, auto-update may bring 118 back) | |

Report for UI (6.6.122 thread or ticket): the status text from A, the ping row from B, and a support file taken without a reboot. The fix to ask for: let the Teleport gate also accept the portal state "open" or an HTTP check, as `utr-runtime-stat-collector` in 6.6.122 already does for its own log.

Run 1, in order:

1. CGM: `sh /tmp/teleport-cgm.sh capture 300 CLIENT_PUBLIC_IP` (client public IP from an earlier client run, or omit it to filter by port).
2. Client, within those 300 s: `awk -v home=HOME_WAN_IP -v tport=TELEPORT_PORT -v homelan=CGM_LAN_IP -v label=office-wifi -v tp=on -f ~/tp/teleport.awk` (Blink: snip `tp/run`).
3. Still within the window: turn Teleport off and on in the UniFi app, note the time.
4. CGM: `sh /tmp/teleport-cgm.sh watch 10` while you toggle Teleport again.
5. Long uplink test (optional): `-v watch=15` on the client logs UTR link, internet and public IP changes with timestamps. Compare with the UTR events in the UniFi app.

The client and the CGM both print UTC, so rows line up by time. On iPhone keep Cellular Data off for runs through the UTR: the script warns when cellular has an address, because iOS can then send probes over LTE.

## Reading the results

| Office run | LTE run | CGM capture during the office run | Reading |
|---|---|---|---|
| fails | works | client UDP probes: NONE; STUN on the client: FAIL | the office uplink drops outbound UDP (H1), CONFIRMED for this uplink. Then 115 must have used another path: test by downgrade if available |
| fails | works | 1-byte probes arrive, the 148 B WG-shaped one does not | the uplink filters the WireGuard handshake shape (H1, protocol filter) |
| fails | works | probes arrive incl. the WG-shaped one; nothing from the UTR when Teleport is toggled | not a port block: the UTR does not send to the CGM (H2/H3), or sends to a relay. In the LTE run `watch` shows the UTR peer's endpoint: client IP = direct, other IP = relay |
| fails | works | UTR packets reach the Teleport port, `watch` shows no handshake | the CGM drops them: keys or binding (H3) |
| fails | fails | - | not the uplink: firmware, binding (H2/H3) or home side (H4/H6): check the CGM `info` DNS and "WAN IPv6" rows |
| fails, ping row FAIL | works, ping row OK | nothing from the UTR | H7: the UTR never tries. The app status reads "Waiting for WAN to become reachable" |
| works | works | - | not reproduced: keep the logs, repeat |

If "inbound to WAN" is WARN (H5), the capture cannot see outside probes at all: NONE there means nothing. Fix that before reading the capture.

## Bug reports

- Paste the tables from the logs as they are. Rows are observations; MANUAL rows are yours to fill from the UniFi app, with time.
- Put guesses in a separate "Hypotheses" section, labelled as such.
- Public IPs and the home WAN IP are personal: redact before posting in public. The CGM script never prints private or preshared keys and cuts public keys to 8 characters.

## Limits

- UDP probes are 1-byte payloads plus one 148-byte WireGuard-shaped packet without valid keys. A filter that validates whole handshakes, or rate-limits them, is not covered.
- The client cannot see the UTR's own traffic. DNS and TLS rows test the same path from the client, not the UTR's broker connection.
- The UTR's own captive probes (firmware `portal-detect.sh`: `connectivitycheck.gstatic.com/generate_204`, `captive.apple.com`, `www.msftconnecttest.com/connecttest.txt`, plain HTTP over IPv4) do not feed "No Internet" or the Teleport gate. The client's captive rows test the same kind of URLs from behind the UTR.
- `capture` with a source IP assumes the UTR and the client leave the uplink with the same public IP. Large NATs can use a pool; run `capture` without a source IP to filter by port instead.
- IPv4 only.
- Network replies (STUN answers, portal pages, server headers in `curl -v`) are parsed with `index()`/`substr()` only: Blink's awk aborts when a regex meets bytes that are not valid UTF-8 (see [vpn.md](vpn.md#limits)). Retested with binary STUN replies, a Latin-1 portal page and a Latin-1 header, 36 combinations in a UTF-8 locale.
- Simulation only so far: fake `ping`/`nc`/`curl`/`dig`/`ifconfig`/`route`/`traceroute` for the client, 66 platform/fault/argument combinations with identical output on Blink's awk build (`awk-awk-35` from ios_system v3.0.3), mawk and nawk; fake `ip`/`wg`/`tcpdump`/`getent`/`ss` for the CGM script, `shellcheck` clean. Not yet run on a UTR, a Mac or a CGM. `vpn.awk` ran on an iPhone behind the UTR on 2026-10-20 (see Claims).
