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
| Uplink xfinitywifi / XFINITY_Guest, 5 GHz; portal shows "success" only for the router; phones and laptops get internet without a portal | CONFIRMED | user |
| Clients behind the UTR have internet; Teleport never connects, also after a UTR reboot | CONFIRMED | user |
| Teleport worked on 6.6.115 on the same kind of uplink, fails on 118 and 122 | CONFIRMED | user |
| ICMP is filtered on this uplink | CONFIRMED | user, earlier run |
| Home DNS is fail-close: ctrld to Control D over DoQ | CONFIRMED | user |
| H1: the office uplink blocks WireGuard UDP | HYPOTHESIS | against it: 115 worked on the same uplink type |
| H2: firmware 118+ changed how Teleport connects | HYPOTHESIS | for it: the version boundary |
| H3: this UTR's binding on the CGM is broken | HYPOTHESIS | |
| H4: the home DNS filter blocks a host Teleport needs | HYPOTHESIS | `teleport-cgm.sh info` DNS rows, Control D activity log for the CGM |
| H5: the CGM WAN is behind NAT, so nothing from outside reaches it directly | testable | `teleport-cgm.sh info`, row "inbound to WAN" |
| Teleport uses WireGuard over UDP | HYPOTHESIS | not verified here; port and relay behaviour are not documented |
| Which UI hosts Teleport uses for brokering | UNKNOWN | default list = UI hosts that answer with their own servers (checked 2026-10-20), not proven to be Teleport's. `*.ui.com` has wildcard DNS: a made-up name also resolves |

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
| fails | fails | - | not the uplink: firmware, binding (H2/H3) or home side (H4/H5): check the CGM `info` DNS and "inbound to WAN" rows |
| works | works | - | not reproduced: keep the logs, repeat |

If "inbound to WAN" is WARN (H5), the capture cannot see outside probes at all: NONE there means nothing. Fix that before reading the capture.

## Bug reports

- Paste the tables from the logs as they are. Rows are observations; MANUAL rows are yours to fill from the UniFi app, with time.
- Put guesses in a separate "Hypotheses" section, labelled as such.
- Public IPs and the home WAN IP are personal: redact before posting in public. The CGM script never prints private or preshared keys and cuts public keys to 8 characters.

## Limits

- UDP probes are 1-byte payloads plus one 148-byte WireGuard-shaped packet without valid keys. A filter that validates whole handshakes, or rate-limits them, is not covered.
- The client cannot see the UTR's own traffic. DNS and TLS rows test the same path from the client, not the UTR's broker connection.
- UI's captive probe URL is not documented, so it is not tested (MANUAL row).
- `capture` with a source IP assumes the UTR and the client leave the uplink with the same public IP. Large NATs can use a pool; run `capture` without a source IP to filter by port instead.
- IPv4 only.
- Simulation only so far: fake `ping`/`nc`/`curl`/`dig`/`ifconfig`/`route`/`traceroute` for the client, 66 platform/fault/argument combinations with identical output on Blink's awk build (`awk-awk-35` from ios_system v3.0.3), mawk and nawk; fake `ip`/`wg`/`tcpdump`/`getent`/`ss` for the CGM script, `shellcheck` clean. Not yet run on a UTR, a Mac or a CGM.
