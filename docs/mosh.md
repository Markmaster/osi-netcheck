# mosh check: why does a session freeze between Wi-Fi and LTE?

Case: Blink on an iPhone, T-Mobile LTE. A mosh session started on Wi-Fi freezes on LTE ("Last contact N seconds ago") and does not come back when the phone returns to Wi-Fi. A session started on LTE seems to move both ways. Three servers (AWS, DigitalOcean, Yandex Cloud) lost contact in the same minute, so the cause is on the phone's side of the path, not in one server.

| File | Runs on | Does |
|---|---|---|
| [`scripts/mosh.awk`](../scripts/mosh.awk) | iPhone (Blink) or Mac | which server address a new session gets on this connection, UDP probes to it and to the address noted on the other connection, verdict per direction |
| [`scripts/mosh-watch.sh`](../scripts/mosh-watch.sh) | the Linux server, `sudo` | mosh-server sessions and the address each listens on; a UDP echo for `mosh.awk`; a live timeline of every session while the phone moves, with a verdict per session |
| `scripts/stun-req.bin` | next to `mosh.awk` | 20-byte probe the echo sends back |
| [`blink/snips/mosh`](../blink/snips/mosh) | Blink | `mosh/run`, `mosh/copy`, `mosh/watch`, `mosh/0-runs` (cheat sheet) |

## How a session keeps or loses the phone

| Claim | Status | Source |
|---|---|---|
| A mosh session never changes the server address it started with; the client opens a new socket (new source port) after 10 s without an answer; the server sends to the source of the newest authentic packet and stops after 40 s without one | CONFIRMED by source | mosh `decd9b7` `src/network/network.cc:393,397,483,542`, `network.h` (`PORT_HOP_INTERVAL` 10000, `SERVER_ASSOCIATION_TIMEOUT` 40000) |
| Blink's mosh (default IP resolution) connects to the address its SSH login went to | CONFIRMED by source | Blink `a90b442` `Blink/Commands/mosh/mosh.swift:356` (`clientAddressIP()` = `getpeername` of the SSH socket) |
| Blink starts `mosh-server new -s`: the server listens only on the address the SSH login arrived at, so the address family is fixed at start | CONFIRMED by source | `mosh.swift:285`; mosh `src/frontend/mosh-server.cc:237-241` |
| Roaming from native IPv4 to a NAT64 network (and back) does not work in mosh | CONFIRMED, open since 2022 | [mobile-shell/mosh#1214](https://github.com/mobile-shell/mosh/issues/1214), milestone 1.5.0 |
| T-Mobile LTE on this iPhone is IPv6-only with CLAT (`192.0.0.2`); `nc -4` UDP (STUN 3478/19302, NTP 123) answered there | CONFIRMED on the iPhone 2026-10-20 | [vpn.md](vpn.md) |
| On an IPv6-only network an A-only server name gets an AAAA from DNS64 (`64:ff9b::/96`); an address like that exists only behind that NAT64 | CONFIRMED | RFC 6147, RFC 7050; `mosh.awk` shows it per network |
| T-Mobile IPv4 = `172.32.0.0/11`, IPv6 = `2607:fb90::/28`, `2607:fc20::/32` (used for labels in `mosh-watch.sh`) | CONFIRMED | ARIN RDAP, 2026-10-21 |
| Blink saves the packet counter when it suspends a session and restores it, so a resumed session is not ignored by the server as a replay | CONFIRMED by source | blinksh/mosh `3640d36` `src/frontend/iosclient.cc:263,391` |
| Blink's mosh fork, on `ENOTCONN` from `recvmsg`: `hop_port()` then `socks.erase( it-- )` on the same `std::deque`. `hop_port()` appends and may prune, which invalidates `it`; at `begin()` `it--` is undefined too | CONFIRMED by source | blinksh/mosh `src/network/network.cc:412-415`. That it fires on a network change: UNKNOWN |

## Hypotheses for this case

| | Hypothesis | For | Against | Settled by |
|---|---|---|---|---|
| H1 | The session's server address does not exist on the other network: started on LTE = `64:ff9b::...`, started on Wi-Fi = IPv4 or the server's IPv6 | mosh#1214; `-s` and `getpeername` fix the address at start | the reported direction: Wi-Fi start fails, LTE start works | `mosh.awk` on Wi-Fi, then LTE: "Here: NO" for the other run's address |
| H2 | T-Mobile drops UDP to the mosh ports (or only on one family) | forum reports of UDP drops on T-Mobile (several years old, not read: the page returned 403) | own run: UDP via CLAT answered on 3478, 19302, 123 | `mosh.awk` probe to port 60999 over LTE, and the echo row in `mosh-watch.sh` |
| H3 | Answers reach the phone's network but not the app (NAT64/CLAT state, or the app socket) | "does not recover on Wi-Fi" points at state, not at a path | | `mosh-watch.sh`: "the phone hears nothing" while the server follows |
| H4 | Blink-side: the `ENOTCONN` path above leaves the client without a working socket | the fork's undefined behaviour | when iOS returns `ENOTCONN` here: not known | `mosh-watch.sh`: the phone sends nothing with Blink in front |

## Install

| Where | How |
|---|---|
| Blink | `scripts/` -> iCloud Drive > Blink > scripts (`mosh.awk`, `mosh-watch.sh`, `stun-req.bin`), `blink/snips/mosh/` -> iCloud Drive > Blink > snips > mosh ([HOWTO](../blink/HOWTO.md)) |
| Server | from Blink: snip `mosh/copy`; or on the server: `curl -sSLO https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/mosh-watch.sh`. Needs `tcpdump`, `ss` (iproute2), `python3` for the echo: all in stock Ubuntu |
| Mac | `mkdir -p ~/mosh && cd ~/mosh && for f in mosh.awk stun-req.bin; do curl -sSLO https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/$f; done`, then `awk -v server=HOST -f ~/mosh/mosh.awk` |

The echo listens on UDP 60999, inside the usual mosh range. If the server's firewall opens fewer ports, use one of them on both sides: `sudo ECHO_PORT=60010 sh ~/mosh-watch.sh watch 10` and `-v port=60010` on the phone.

## Run

1. Server: `sudo sh ~/mosh-watch.sh watch 10` (snip `mosh/watch`). Inside a mosh session is fine: if that session freezes too, the script keeps running and writes `/tmp/mosh-watch-*.txt`.
2. Phone on Wi-Fi, Cellular Data off: snip `mosh/run` with the server's real name or IP. Then Wi-Fi off: `mosh/run` again. Each run notes its session address in Files > iCloud Drive > Blink > `mosh-addr-*`, so the second run tests the first.
3. Within the 10 minutes: start a mosh session on Wi-Fi, keep Blink in front, Wi-Fi off, wait 40 s, Wi-Fi on. Then the same with a session started on LTE. Note the times (the rows are UTC).
4. Read the summary on the server and the verdicts on the phone.

## Reading the results

| mosh.awk | mosh-watch.sh | Reading | Fix to try |
|---|---|---|---|
| LTE run: "Started on wifi ... Here: NO" | phone silent after the move | H1 or H2 for the Wi-Fi address on LTE | if the "By IPv4 address" row works on LTE and Wi-Fi: connect by that IPv4 address |
| Wi-Fi run: "Started on lte ... Here: NO", address `64:ff9b::...` | phone silent after the move | H1: the LTE session's address exists only on T-Mobile | connect by the IPv4 address, or give the server a real IPv6 (Wi-Fi then needs IPv6 too) |
| YES both ways | "server follows", then "the phone hears nothing" | H3: answers lost on the way to the phone | Tailscale on phone and server, mosh to the server's `100.x` address: the tunnel roams, the mosh address never changes |
| YES both ways | phone silent although Blink is in front | H4: the app does not send | Blink issue with this log; workaround as above |
| YES both ways | "server keeps sending to" the old address | mosh/Blink bug | Blink issue with this log |
| any | "no mosh-server listens" | the session's server is gone | new session |
| no echo at all | no probe listed | echo not running or the port closed in the firewall | open the port, or `ECHO_PORT` |

## Limits

- The phone probe is a fresh UDP socket. It shows whether a path exists, not what a long-lived socket in Blink does: `mosh-watch.sh` shows that.
- The address a session gets is measured with `curl` to the SSH port through the system resolver, as Blink's ssh resolves. `curl` races IPv6 and IPv4, libssh tries them in order: normally the same pick. Blink hosts with ProxyJump or `-R local/remote` resolve differently.
- `mosh-watch.sh` sees packets, not their content: a graceful end (`exit`, `SIGTERM` to mosh-server) looks like the phone going quiet.
- Tested in simulation only: `mosh-watch.sh` with real `mosh-server`/`mosh-client` 1.4.0 in Linux network namespaces (roaming, answers dropped towards the phone, phone packets dropped, mosh-server killed) plus a synthetic capture for the IPv6, old-tcpdump-format, wrong-address and server-does-not-follow paths, same output on mawk and BWK awk, `shellcheck` clean. `mosh.awk` with fake `ifconfig`/`dig`/`curl`/`nc`/`uname` (Wi-Fi, LTE with CLAT and DNS64, no echo, SSH down, no request file, macOS), identical output on BWK awk and mawk in a UTF-8 locale, with non-UTF-8 bytes in the replies. Not yet run on the iPhone or the servers.
