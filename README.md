# osi-netcheck

Bottom-up network check: is it the DNS filter (Control D) or the network? Runs in Blink Shell (iOS), macOS Terminal and Windows PowerShell. Read-only: ping, TCP connects, DNS queries, one HTTPS request.

```
== OSI check: Control D or the internet ==
[  OK] 1  Gateway 192.0.2.1: replies
[FAIL] 2  Ping 1.1.1.1 / 8.8.8.8: the network blocks ping (prohibited by filter)
[  OK] 3  TCP 443 to 1.1.1.1
[  OK] 3b HTTPS to 1.1.1.1
[  OK] 4  DNS via 1.1.1.1 (UDP 53, bypassing Control D)
[  OK] 5  Control D directly 76.76.2.0 (UDP 53)
[  OK] 5b Control D DoH 76.76.2.22 (TCP 443)
[  OK] 6  System DNS: example.com -> 104.20.23.154
[  OK] 6b Network/router DNS (bypasses the profile)
[  OK] 7  Verify (system): 147.185.34.1 = Control D
[  --] 7b Verify (network): not Control D (normal unless your router uses Control D)

== VERDICT ==
ALL OK: internet works, DNS goes through Control D.
  * This network blocks ping, but the internet works. Not a fault.
Final check in a browser: https://controld.com/status
```

## Run

| Platform | Install | Run |
|---|---|---|
| iOS, Blink 18.6.0+ | `blink/snips/osi` -> iCloud Drive > Blink > snips, `scripts` -> iCloud Drive > Blink ([details](blink/HOWTO.md)) | `⌘<` -> `osi/run` |
| macOS | `curl -sSLo ~/osi.awk https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/osi.awk` | `awk -f ~/osi.awk` |
| Windows | `curl.exe -sSLo "$HOME\osi.ps1" https://raw.githubusercontent.com/Markmaster/osi-netcheck/main/scripts/osi.ps1` | `powershell -ExecutionPolicy Bypass -File "$HOME\osi.ps1"` |

- Gateway is auto-detected on macOS and Windows. Override: `-v gw=IP` (awk), `-Gateway IP` (ps1). Blink cannot read routes: use `osi/run-wifi`, which asks for the router IP.
- macOS 15+: non-Apple terminals may need Local Network access, otherwise step 1 fails falsely.
- Windows: `Bypass` covers this run only (client default is Restricted). Group Policy can still block it.

## Steps

First failing step is the answer.

| Step | Check | FAIL means |
|---|---|---|
| 1 | Ping gateway | Wi-Fi, cable, router |
| 2 | Ping 1.1.1.1, 8.8.8.8 | ISP down, or ICMP filtered (step 3 decides) |
| 3 / 3b | TCP 443, HTTPS to 1.1.1.1 | Firewall; TCP OK + HTTPS FAIL = captive portal or TLS interception |
| 4 | DNS @1.1.1.1 | Outside DNS blocked |
| 5 / 5b | `verify.controld.com` @76.76.2.0 (UDP 53), TCP 443 to 76.76.2.22 (DoH) | Control D blocked; `??` on 5 = network intercepts DNS |
| 6 / 6b | System resolver, network/router DNS | Your setup: profile, ctrld, router, VPN |
| 7 / 7b | `verify.controld.com` = `147.185.34.1` via system / network DNS | 7: DNS bypasses Control D. 7b: network DNS did not answer (`--` = router not on Control D, normal) |

Steps 1-4 and 6/6b are DNS-agnostic; 5 and 7 are Control D specific.

## Also here

- [`blink/snips/osi`](blink/snips/osi): one snip per step for the Blink local shell.
- [`snippets/`](snippets/): the same steps as plain text for any snippet manager, plus a cheat sheet and an iPhone checklist.
- [`docs/how-it-works.md`](docs/how-it-works.md): why this order, why `ping` and not `dig` on iOS, why awk, limits, testing.

## Status

iPhone (Blink 18.7.1): every command tested on real networks; an earlier `osi.awk` ran end to end once, the current verdict logic is tested in simulation. macOS and Windows: simulation only. Issues with real output welcome.

Designed and tested by Mark. Implemented with [Claude Code](https://claude.com/claude-code). MIT. Not affiliated with Control D or Blink Shell.
