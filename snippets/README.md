# Snippets

Same steps as plain text for any snippet manager. Copy raw files (rich-text formats can add characters). Go 1 -> 7, the first failure is the answer.

## iOS (Blink local shell)

One command per file, no trailing newline: Blink glues multi-line pastes and has no `;`. Two-part steps are split into `N` and `Nb`. Put the hint into the manager's description field.

| Key | File | Hint |
|---|---|---|
| `ni1` | `ios/1-gateway.txt` | Replace `ROUTER_IP` first. 100% loss = Wi-Fi/router. Skip on LTE |
| `ni2` | `ios/2-ping-ip.txt` | 100% loss + ni3 FAIL = no internet. "prohibited by filter" = ICMP filtered |
| `ni3` | `ios/3-tcp-443.txt` | `succeeded` = TCP out works. Timeout = 443 blocked |
| `ni3b` | `ios/3b-https.txt` | 301/200 = TLS works. 000 while ni3 OK = captive portal or TLS interception |
| `ni4` | `ios/4-dns-bypass.txt` | IP = outside DNS works. Timeout = UDP 53 blocked |
| `ni5` | `ios/5-dns-controld.txt` | `147.185.34.1` = Control D. Empty = DNS intercepted. Timeout = UDP 53 to Control D blocked (matters for a router; DoH is ni5b) |
| `ni5b` | `ios/5b-controld-doh.txt` | `succeeded` = DoH endpoint reachable |
| `ni6` | `ios/6-dns-system.txt` | Look at the `PING name (IP)` line only. `cannot resolve` = your DNS setup |
| `ni6b` | `ios/6b-dns-network.txt` | Network/router/VPN DNS, bypassing the profile |
| `ni7` | `ios/7-verify-system.txt` | Expect `api.controld.com (147.185.34.1)` |
| `ni7b` | `ios/7b-verify-network.txt` | `147.185.34.1` only if the router uses Control D, otherwise empty |

`ping` by name is the system resolver (sees the DoH profile); `dig` without `@` is plain UDP 53 to the network DNS (does not). See [`docs/how-it-works.md`](../docs/how-it-works.md).

## macOS (zsh) and Windows (PowerShell)

Multi-line, hint printed at the end of each step. No `#` comments in the macOS files: interactive zsh does not treat them as comments by default.

| Step | macOS | Windows |
|---|---|---|
| 1 gateway | `macos/1-gateway.sh` `nm1` | `windows/1-gateway.ps1` `nw1` |
| 2 ping by IP | `macos/2-ping-ip.sh` `nm2` | `windows/2-ping-ip.ps1` `nw2` |
| 3 TCP 443 + HTTPS | `macos/3-tcp-443.sh` `nm3` | `windows/3-tcp-443.ps1` `nw3` |
| 4 DNS @1.1.1.1 / @8.8.8.8 | `macos/4-dns-bypass.sh` `nm4` | `windows/4-dns-bypass.ps1` `nw4` |
| 5 Control D UDP 53 + DoH 443 | `macos/5-dns-controld.sh` `nm5` | `windows/5-dns-controld.ps1` `nw5` |
| 6 system DNS | `macos/6-dns-system.sh` `nm6` | `windows/6-dns-system.ps1` `nw6` |
| 7 verify | `macos/7-verify-controld.sh` `nm7` | `windows/7-verify-controld.ps1` `nw7` |
| 1-7 at once | `macos/all-in-one.sh` `nm0` | `windows/all-in-one.ps1` `nw0` |
| auto + verdict | `macos/run.sh` `nmrun` | `windows/run.ps1` `nwrun` |

Windows: `Resolve-DnsName`, not `nslookup.exe` (bypasses NRPT, so it does not show what apps get under ctrld Intercept Mode).

## Cheat sheets

`verdict.txt` (`nwho`): who is to blame, step by step. `ios/checklist-iphone.txt` (`nchk`): manual iPhone check with Safari and Settings only.
