# How it works

## Method

Each step depends only on the ones below it, so the first failure is the answer and everything above it is noise.

| Step | Layer | Probe | FAIL with everything below OK |
|---|---|---|---|
| 1 | L1-L3 | ping gateway | Wi-Fi, cable, router |
| 2 | L3 | ping 1.1.1.1, 8.8.8.8 | ISP, or ICMP filtered |
| 3 | L4 | TCP connect 1.1.1.1:443 | Outbound 443 blocked |
| 3b | L5-7 | HTTPS to 1.1.1.1 | Captive portal or TLS interception |
| 4 | DNS | `example.com` @1.1.1.1, UDP 53 | Outside DNS blocked |
| 5 | DNS | `verify.controld.com` @76.76.2.0, UDP 53 | Control D plain DNS blocked; non-Control D answer = interception |
| 5b | L4 | TCP connect 76.76.2.22:443 (dns.controld.com) | DoH to Control D blocked |
| 6 | DNS | `example.com` via the system resolver | Your setup: profile, ctrld, router, VPN |
| 6b | DNS | `example.com` via the network DNS directly | Router (or VPN) DNS broken |
| 7 | DNS | `verify.controld.com` via the system resolver | DNS works but bypasses Control D |
| 7b | DNS | `verify.controld.com` via the network DNS | Network DNS did not answer (`--` = router not on Control D, normal) |

Design notes:

- Steps 2-3 use bare IPs, so they work without DNS. "Internet works" means any outside probe answered (ping, 443, HTTPS, Control D, plain DNS): many networks drop ICMP, some block 1.1.1.1 but not Control D.
- A captive portal accepts the TCP connection and then breaks TLS: 3 OK + 3b FAIL is its signature.
- A router usually talks to Control D over UDP 53 (step 5), a phone profile or ctrld over DoH (step 5b). UDP 53 to Control D blocked while 443 works is common and harmless for DoH.
- Only Control D answers `verify.controld.com` with `147.185.34.1` (CNAME `api.controld.com`); Cloudflare and Google return an empty answer. That makes step 5 catch networks that intercept port 53, and 7/7b tell which path reaches Control D. Per the Control D docs a missing answer alone does not prove another resolver, so the script also resolves a normal name and says "most likely".

## iOS: two DNS paths

- `dig`, `nslookup`, `host` in Blink are BIND builds. They take the server list from the system (`res_getservers`) and send plain UDP 53: they do not see a DoH/DoT profile. `dig` without `@` = the router's DNS, or the VPN's.
- `ping name` resolves through the system resolver (`gethostbyname2`), like apps, and prints `PING name (IP)` before any reply. The script reads that line; exit code 68 (cannot resolve) vs 2 (no reply) is only a fallback.

Confirmed on an iPhone away from home: `ping verify.controld.com` -> `147.185.34.1` (profile works), `dig verify.controld.com` -> no Control D address (network DNS).

## Why awk

The Blink local shell is `ios_system`: one command per line, no `;` `&&` `||` `$()`, no `sh`, no aliases. `|` and redirections work. Multi-line snips only make sense over ssh, where they test the server, not the phone.

Blink ships BWK awk (20200816), and its `system()` returns the exit code. So each probe is `system("cmd > tmp 2>&1")`, awk greps the output with `getline`, and the verdict is a rule chain over the results. One command, `awk -f osi.awk`, fits one snip, and the same file runs in macOS Terminal.

macOS extras: gateway from `route -n get default`, VPN default route detected, ctrld recognised from `/etc/resolv.conf`. `system()` makes awk ignore SIGINT, so the script checks the exit status for a signal; `ping` traps Ctrl-C itself, so Ctrl-C during a ping step only ends that step. The script first proves it can write and read back a temp file (`$HOME`, `$TMPDIR`, `.`) and stops otherwise.

## Windows

`osi.ps1`, PowerShell 5.1 and 7, same verdict logic:

- `ping.exe` (reply = `TTL=` in output, any locale), `TcpClient` with a 3 s timeout.
- `curl.exe --ssl-no-revoke`: without it Schannel checks revocation through the system DNS, and broken DNS looks like a captive portal.
- `Resolve-DnsName`: without `-Server` it goes through the DNS Client and NRPT, like apps. `nslookup.exe` bypasses NRPT.
- `Get-NetRoute`, `Get-DnsClientServerAddress` for gateway and adapter DNS.

## Limits

- IPv4 only. DoH is checked at TCP level, not with a real DoH query.
- A browser with its own Secure DNS bypasses the system resolver: check https://controld.com/status in the browser too.
- 147.185.34.1 means "a Control D resolver", not "your profile": Free DNS and an unauthorized Legacy DNS router return it too. With your own profile, check the Resolver row on the status page (N/A is expected only for Free DNS).
- `ctrld --intercept-mode dns` on macOS redirects all port 53 via pf and leaves `/etc/resolv.conf` alone: steps 4, 5, 6b, 7b then go through ctrld unlabeled. Stop ctrld to test the bare network.
- Blink cannot read routes, so the gateway is asked for or skipped.

## Testing

- iPhone, Blink 18.7.1: every command by hand at home and on another network (incl. `dig @76.76.2.0 verify.controld.com` -> `147.185.34.1`). An earlier `osi.awk` ran end to end once (all-OK). Current verdicts: simulation only.
- awk: fake `ping`/`nc`/`curl`/`dig`/`route` driven by env vars; 2304 probe combinations, identical output on BWK awk, mawk and Blink's awk build; asserts: 11 steps always, step 5 matches the network state, 7b FAIL only with dead network DNS, no note contradicting a no-internet/firewall/captive verdict.
- PowerShell: mocked probes on PowerShell 7, 5.1 compatibility checked with PSScriptAnalyzer.
- Not yet: real macOS and Windows runs.

## Sources

Control D: [Free DNS](https://docs.controld.com/docs/free-dns), [IP ranges](https://docs.controld.com/docs/control-d-ip-ranges), [Check if DNS is working](https://docs.controld.com/docs/check-if-dns-is-working), [Status page](https://docs.controld.com/docs/status-page), [DNS Intercept Mode](https://docs.controld.com/docs/dns-intercept), [iOS](https://docs.controld.com/docs/ios-platform). Blink: [Snips](https://docs.blink.sh/basics/snips), [UNIX Roundup](https://docs.blink.sh/advanced/unix-roundup), [blinksh/blink](https://github.com/blinksh/blink), [holzschu/ios_system](https://github.com/holzschu/ios_system) v3.0.3, [holzschu/network_ios](https://github.com/holzschu/network_ios).
