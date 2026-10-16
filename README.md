# osi-netcheck

**Is it my DNS filter (Control D) or the internet?** A bottom-up network check for iPhone/iPad (Blink Shell), macOS and Windows. It runs the checks layer by layer, from the router up to DNS, and tells you which layer broke first.

```
== VERDICT ==
Internet works, but TCP 443 to Control D (DoH) is blocked:
the DNS profile (DoH) cannot reach it. The network blocks Control D:
exclude this network in the profile or use another network (LTE).
```

Three ways to use it:

| What | Where | How |
|---|---|---|
| **Auto check** with a verdict | Blink Shell (iOS), macOS, Windows | One command: `awk -f osi.awk` or `osi.ps1`. See [`scripts/`](scripts/) |
| **Blink snips** | Blink Shell on iPhone/iPad | `⌘` + `<` -> `osi/run`, or one step at a time. See [`blink/HOWTO.md`](blink/HOWTO.md) |
| **Plain-text snippets** | Any snippet manager, any terminal | One step per snippet, with a hint on how to read the result. See [`snippets/`](snippets/) |

No install, no dependencies, nothing changed on the system: only ping, TCP connects, DNS queries and one HTTPS request to 1.1.1.1.

## Quick start

**iPhone/iPad (Blink Shell):** download the repo (Code -> Download ZIP), put `blink/snips/osi` into **iCloud Drive > Blink > snips** and `scripts` into **iCloud Drive > Blink**. In Blink: `⌘` + `<` -> `osi/run` -> ➤ -> Enter.

**macOS:** save `scripts/osi.awk` as `~/osi.awk`, then in Terminal:

```sh
awk -f ~/osi.awk
```

**Windows:** save `scripts/osi.ps1` as `C:\Users\<name>\osi.ps1`, then in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File "$HOME\osi.ps1"
```

## The steps

The first failing step is the answer: everything above it fails as a consequence.

| Step | Checks | Fails means |
|---|---|---|
| 1 | Gateway (router) | Wi-Fi, cable or router |
| 2 | Ping 1.1.1.1 / 8.8.8.8 by IP | Internet or ISP (or only ICMP is blocked) |
| 3 / 3b | TCP 443 and HTTPS to 1.1.1.1 | Firewall, captive portal, TLS interception |
| 4 | DNS straight to 1.1.1.1 | The network blocks outside DNS |
| 5 / 5b | Control D directly: UDP 53 and the DoH endpoint on 443 | The network blocks Control D |
| 6 / 6b | System DNS, and the network/router DNS | Your setup: profile, ctrld, router, VPN |
| 7 / 7b | `verify.controld.com` = Control D's own IP | DNS works but bypasses Control D |

Why this order, why `ping` instead of `dig` on iOS, and why the logic is written in awk: [`docs/how-it-works.md`](docs/how-it-works.md).

## Not using Control D?

Steps 1-4 and 6/6b work with any DNS setup. Steps 5 and 7 are Control D specific: to adapt it to another DNS service, change the resolver IPs and the verify name in the script.

## Status

- Blink Shell on iPhone: tested on real networks (Blink v18.7.1).
- macOS and Windows: the logic is tested against simulated network states, not yet on real machines. Reports welcome.

Not affiliated with Control D or Blink Shell.

## Credits

Designed and tested by Mark. Implemented with [Claude Code](https://claude.com/claude-code).

## License

[MIT](LICENSE)
