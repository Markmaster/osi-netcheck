# How it works

## The problem

A DNS filter like Control D sits on the path of every connection: on the router, as a DNS profile on the phone, or as the `ctrld` daemon on a computer. When "the internet is down", the first question is whether the internet is really down or the DNS filter is. Answering that by hand means running a dozen commands and knowing how to read each one. On an iPhone it is worse: there is no real shell, and the usual tools do not see the DNS profile.

## The approach: bottom-up, first failure wins

The checks go up the stack, like the OSI model. Every step depends only on the steps below it, so **the first step that fails is the answer**. Everything above it fails as a consequence and tells you nothing new.

| Step | Layer | Check | If it fails (and everything below passed) |
|---|---|---|---|
| 1 | L1-L3 local | Ping the gateway (router) | Wi-Fi, cable or router |
| 2 | L3 | Ping 1.1.1.1 and 8.8.8.8 by IP | Internet or ISP. Or the network only blocks ICMP: step 3 decides |
| 3 | L4 | TCP connect to 1.1.1.1:443 | The network blocks outbound TCP 443 (firewall) |
| 3b | L5-L7 | HTTPS request to https://1.1.1.1 | TCP works but TLS does not: captive portal or TLS interception |
| 4 | L7 DNS | DNS query straight to 1.1.1.1 (UDP 53) | The network blocks outside DNS |
| 5 | L7 DNS | DNS query straight to Control D, 76.76.2.0 (UDP 53) | The network blocks Control D specifically |
| 5b | L4 | TCP connect to the Control D DoH endpoint, 76.76.2.22:443 | A DoH profile has nowhere to go: the network blocks Control D |
| 6 | L7 DNS | Resolve a name through the **system** resolver | Your setup: profile, `ctrld`, router DNS, VPN |
| 6b | L7 DNS | Resolve a name through the **network/router** DNS directly | The router DNS is broken (other devices are affected too) |
| 7 | L7 DNS | `verify.controld.com` through the system resolver | DNS works but does not go through Control D |
| 7b | L7 DNS | `verify.controld.com` through the network DNS | Only tells you whether the router itself uses Control D (an empty answer is normal otherwise) |

Why some choices:

- **TCP 443 before DNS.** Steps 2-3 use bare IP addresses, so they work without any DNS. If they pass, the internet is there, and whatever breaks later is DNS.
- **Ping alone proves nothing.** Plenty of networks drop ICMP. That is why "internet works" is any outside probe answering: ping, TCP 443, HTTPS, Control D or plain DNS. Some networks block 1.1.1.1 but let Control D through, and the script handles that too.
- **HTTPS separately from TCP.** A captive portal accepts the TCP connection and then breaks TLS. TCP OK + HTTPS FAIL is its signature.
- **Step 5 vs 5b.** A router usually talks to Control D over plain DNS (UDP 53, step 5). A phone profile uses DoH over TCP 443 (step 5b). They can fail independently: UDP 53 to Control D blocked while 443 works is normal on many networks and does not hurt a DoH profile.
- **verify.controld.com.** Control D resolvers answer this name with `147.185.34.1` (CNAME `api.controld.com`). Other public resolvers return an empty answer (checked against Cloudflare and Google). Per the Control D docs, the expected answer is evidence that this DNS path reaches Control D, and a missing answer alone does not tell another resolver apart from a DNS or verify-service failure. That is why the script also resolves a normal domain (step 6) and says "most likely" in that verdict.

## Two DNS paths on iOS

This was the non-obvious part, and it was confirmed on a real iPhone.

- `dig`, `nslookup` and `host` in Blink are built from BIND. iOS has no `/etc/resolv.conf`, so they ask the system for the DNS server list and send it **plain UDP 53**. They cannot do DoH or DoT, so they **do not see** a DoH DNS profile. `dig` without `@` asks the DNS servers iOS lists for the current connection directly: the router's, or a VPN's when a VPN is on.
- `ping example.com` resolves the name through the system resolver (`gethostbyname2`), the same path apps use, and prints `PING name (IP)`. The IP in that line is what the system resolver returned, even if no ping reply ever comes.

So steps 6 and 7 use `ping` by name (the phone's real DNS path), and 6b/7b use `dig` without `@` (the network's DNS). Proof from an iPhone on a network without Control D on the router: `ping verify.controld.com` printed `147.185.34.1` (the DNS profile works), while `dig verify.controld.com` returned no Control D address (the network's own DNS).

Packet loss in steps 6 and 7 does not matter, only the name resolution does. The awk script decides by the `PING name (IP)` line, which ping prints only after the name has resolved. Ping's exit code (`68` = the name did not resolve, `2` = no reply) is used only as a fallback when the output cannot be read back.

## Why awk

The Blink local shell is `ios_system`, not bash. It runs one command per line: no `;`, `&&`, `||`, `$(...)`, no `sh`, no scripts, no aliases. Pipes and redirections do work.

But Blink ships `awk` (BWK "one true awk", version 20200816), and awk is a full language with `if/else`, functions and file reading. Its `system()` runs a command through `ios_system` and returns the exit code. That is enough:

1. Each check is one command, run as `system("cmd > tmpfile 2>&1")`.
2. awk reads the output back with `getline`, looks for patterns (`PING name (IP)`, `prohibited by filter`, an IPv4 in `dig +short` output) and combines them with the exit codes.
3. The verdict is a chain of rules over those results, in the bottom-up order above.

One command, `awk -f osi.awk`, fits into a single Blink snip. The same file runs unchanged in macOS Terminal (macOS also ships BWK awk). On a Mac it also finds the gateway via `route -n get default`, detects a VPN default route, labels a `ctrld` local resolver from `/etc/resolv.conf`, and stops on Ctrl-C (on macOS `system()` makes awk ignore SIGINT, so the script checks the exit status for a signal itself). `ping` catches Ctrl-C and exits normally, so a Ctrl-C during a ping step only ends that step: press it again at the next one.

Before any check the script makes sure it can actually write and read back a temp file (`$HOME`, then `$TMPDIR`, then the current folder). If it cannot, it stops instead of guessing.

## Windows

`osi.ps1` is a port of the same logic to PowerShell (5.1 and 7), with Windows-native probes:

- Ping: `ping.exe`, a reply is `TTL=` in the output (the same in localized Windows).
- TCP: `System.Net.Sockets.TcpClient` with a 3 s timeout.
- HTTPS: `curl.exe` (built into Windows 10 1803+) with `--ssl-no-revoke`. Without it, Schannel checks certificate revocation through the system DNS, and with broken DNS the HTTPS step fails falsely and looks like a captive portal.
- DNS: `Resolve-DnsName`. Without `-Server` it goes through the Windows DNS client and NRPT, the same as apps. Per the Control D docs, `nslookup.exe` bypasses the DNS Client and NRPT, so it does not show what apps get when `ctrld` runs in DNS Intercept Mode.
- Gateway and adapter DNS: `Get-NetRoute` and `Get-DnsClientServerAddress`.

## What it cannot tell

- It checks IPv4 only.
- It checks the DoH endpoint at the TCP level (connect to 443), not a full DoH query.
- A browser can have its own Secure DNS (DoH) and bypass the system resolver. The script checks the system path; https://controld.com/status checks the browser path. Run both.
- `verify.controld.com` shows that a Control D resolver answered, not which one: Free DNS, and a router on Legacy DNS whose IP is not authorized, return `147.185.34.1` too. With your own profile, check the Resolver row on https://controld.com/status (N/A is expected only for Free DNS).
- On a Mac running `ctrld --intercept-mode dns`, pf redirects every port-53 query to ctrld and `/etc/resolv.conf` stays unchanged. Steps 4, 5, 6b and 7b then do not bypass Control D and the ctrld label is not shown. To test the network itself, run the script with ctrld stopped.
- On iOS there is no way to read the gateway from Blink (`route` and `netstat` are not available), so the router IP is asked for or the step is skipped.

## Testing

- **iPhone:** each command was run by hand in Blink v18.7.1 at home and on another network, and several snips were sent from the snips menu. An earlier version of `osi.awk` ran end to end once on a real network (the all-OK case). The current version and the failure verdicts (no internet, captive portal, broken setup, Control D blocked) were checked only with fake commands.
- **Logic:** fake `ping`, `nc`, `curl`, `dig` and `route` commands, driven by environment variables, simulate each network state. The awk script was run against 1536 combinations of probe results on three awks: BWK awk, mawk and the exact build Blink ships (version 20200816), with identical output on all three. The checks: every run finishes with all 11 steps, step 7b fails only when the network DNS is dead, and no note contradicts a no-internet, firewall or captive-portal verdict. Named scenarios cover a profile-only iPhone, DoH blocked, ctrld on a Mac, a VPN default route and more.
- **PowerShell:** the probe functions were mocked and the verdict checked on PowerShell 7. Windows PowerShell 5.1 compatibility was checked with PSScriptAnalyzer.
- **Not yet:** a real run on macOS and Windows hardware.

## Sources

- Control D: [Free DNS](https://docs.controld.com/docs/free-dns) (76.76.2.0, 76.76.10.0), [IP ranges](https://docs.controld.com/docs/control-d-ip-ranges) (dns.controld.com = 76.76.2.22), [Check if DNS is working](https://docs.controld.com/docs/check-if-dns-is-working) (verify.controld.com), [Status page](https://docs.controld.com/docs/status-page), [DNS Intercept Mode](https://docs.controld.com/docs/dns-intercept) (nslookup vs Resolve-DnsName), [iOS](https://docs.controld.com/docs/ios-platform).
- Blink Shell: [Snips](https://docs.blink.sh/basics/snips), [UNIX Roundup](https://docs.blink.sh/advanced/unix-roundup), source code at [blinksh/blink](https://github.com/blinksh/blink); local shell [holzschu/ios_system](https://github.com/holzschu/ios_system) v3.0.3 (awk, `system()`, redirections), network tools [holzschu/network_ios](https://github.com/holzschu/network_ios) (ping exit codes, `nc -G`, BIND `dig`).
