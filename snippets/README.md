# Plain-text snippets

The same checks as the scripts, one step per snippet, for any snippet manager (Snippety, Raycast, Alfred, TextExpander, Apple Notes, a plain text file). Every file is plain text: copy it, paste it into a terminal, press Enter.

Go 1 -> 7. The first failing step is the answer. TCP 443 is step 3 because it is L4, below DNS.

## iOS (Blink Shell)

The Blink local shell takes **one command per paste** (multi-line pastes get glued into one line, and `;` is not a separator). So two-part steps are split into a main snippet and a `b` variant (`ni3` and `ni3b`). The files have no trailing newline, so nothing runs before you press Enter.

The Description column is the "how to read the result" hint. Put it into your manager's description or notes field.

| Keyword | Name | File | Command | Description |
|---|---|---|---|---|
| `ni1` | `iOS 1 · Gateway` | `ios/1-gateway.txt` | `ping -c 3 ROUTER_IP` | Gateway. Replies = Wi-Fi and router OK. 100% loss = Wi-Fi or router. Before Enter replace ROUTER_IP with the router address: Settings > Wi-Fi > (i) > Router. Skip on LTE |
| `ni2` | `iOS 2 · Ping by IP` | `ios/2-ping-ip.txt` | `ping -c 3 1.1.1.1` | Internet by IP, no DNS. Replies = the internet works. 100% loss = internet or ISP. "prohibited by filter" or ni3/ni3b OK = the network blocks ping, the internet works |
| `ni3` | `iOS 3 · TCP 443` | `ios/3-tcp-443.txt` | `nc -zv -G 3 1.1.1.1 443` | TCP 443 by IP. succeeded = outbound TCP works. Error or timed out = the network blocks TCP 443. Total silence = the command did not start, paste again |
| `ni3b` | `iOS 3b · HTTPS` | `ios/3b-https.txt` | `curl -sS -m 5 -o /dev/null -w "%{http_code}\n" https://1.1.1.1` | HTTPS by IP. 301 or 200 = TLS gets through. 000 or a curl error while ni3 succeeds = captive portal or TLS interception |
| `ni4` | `iOS 4 · DNS bypassing Control D` | `ios/4-dns-bypass.txt` | `dig @1.1.1.1 example.com +short +time=2 +tries=1` | DNS bypassing Control D. An IP = outside DNS works. timed out = the network blocks UDP 53 |
| `ni5` | `iOS 5 · Control D directly` | `ios/5-dns-controld.txt` | `dig @76.76.2.0 example.com +short +time=2 +tries=1` | Control D directly, without the profile. An IP = Control D is reachable. ni4 OK but timed out here = the network blocks Control D plain DNS (matters for Control D on a router; a DoH profile uses ni5b) |
| `ni5b` | `iOS 5b · Control D DoH` | `ios/5b-controld-doh.txt` | `nc -zv -G 3 76.76.2.22 443` | Control D DoH endpoint (dns.controld.com = 76.76.2.22, port 443). succeeded = TCP 443 to Control D gets through |
| `ni6` | `iOS 6 · System DNS` | `ios/6-dns-system.txt` | `ping -c 1 -W 2000 example.com` | iPhone system DNS, same as apps use. Look at the "PING name (IP)" line. cannot resolve = your DNS setup is broken. Packet loss does not matter |
| `ni6b` | `iOS 6b · Network DNS` | `ios/6b-dns-network.txt` | `dig example.com +short +time=2 +tries=1` | Network or router DNS directly, bypassing the profile. At home that is your router (or your VPN, if one is on). On another network it is their DNS |
| `ni7` | `iOS 7 · Verify system` | `ios/7-verify-system.txt` | `ping -c 1 -W 2000 verify.controld.com` | Verify via the iPhone system DNS. Expect PING api.controld.com (147.185.34.1). Packet loss does not matter |
| `ni7b` | `iOS 7b · Verify network` | `ios/7b-verify-network.txt` | `dig verify.controld.com +short +time=2 +tries=1` | Verify via the network DNS. With Control D on your router expect api.controld.com and 147.185.34.1. Otherwise an empty answer is normal: other resolvers do not answer this name |

Why `ping` for steps 6 and 7: on iOS, `dig` without `@` sends plain UDP 53 to the network DNS and does not see a DoH/DoT DNS profile. `ping` by name uses the system resolver, the same path apps take. Details: [`docs/how-it-works.md`](../docs/how-it-works.md).

## macOS and Windows

Multi-line pastes work in Terminal and PowerShell, so each step is one snippet with the "how to read" hint printed by `echo` (macOS) or a string line (PowerShell). The macOS files have no `#` comments on purpose: interactive zsh has comments turned off by default.

| Step | What it checks | macOS (Terminal) | Windows (PowerShell) |
|---|---|---|---|
| 1 | Gateway (router) | `macos/1-gateway.sh` · `nm1` | `windows/1-gateway.ps1` · `nw1` |
| 2 | Ping by IP, no DNS | `macos/2-ping-ip.sh` · `nm2` | `windows/2-ping-ip.ps1` · `nw2` |
| 3 | TCP 443 and HTTPS by IP | `macos/3-tcp-443.sh` · `nm3` | `windows/3-tcp-443.ps1` · `nw3` |
| 4 | DNS bypassing Control D (1.1.1.1, 8.8.8.8) | `macos/4-dns-bypass.sh` · `nm4` | `windows/4-dns-bypass.ps1` · `nw4` |
| 5 | Control D directly (76.76.2.0 and DoH 443) | `macos/5-dns-controld.sh` · `nm5` | `windows/5-dns-controld.ps1` · `nw5` |
| 6 | System DNS (your setup) | `macos/6-dns-system.sh` · `nm6` | `windows/6-dns-system.ps1` · `nw6` |
| 7 | verify.controld.com | `macos/7-verify-controld.sh` · `nm7` | `windows/7-verify-controld.ps1` · `nw7` |
| all | Steps 1-7 at once, read it yourself | `macos/all-in-one.sh` · `nm0` | `windows/all-in-one.ps1` · `nw0` |
| auto | All steps + "who is to blame" verdict (needs the script from `scripts/`) | `macos/run.sh` · `nmrun` | `windows/run.ps1` · `nwrun` |

Suggested names: `Mac 6 · System DNS`, `Win 7 · Verify` and so on.

On Windows use `Resolve-DnsName`, not `nslookup.exe`: per the Control D docs, `nslookup.exe` bypasses the DNS Client and NRPT, so it does not show what apps get when `ctrld` runs in DNS Intercept Mode.

## Cheat sheets

| File | Keyword | What it is |
|---|---|---|
| `verdict.txt` | `nwho` | "Who is to blame" by step 1-7 |
| `ios/checklist-iphone.txt` | `nchk` | Manual iPhone checklist using only Safari and Settings |

## Tips

- Copy the raw file from GitHub (the Raw view or the copy button), not from a rendered page or a chat window. In testing, commands copied from a chat window did not run in Blink, while the same line copied through Notes did.
- Use your manager's plain-text format. Rich text, HTML or Markdown formats can add characters.
- Do not use placeholder syntax your manager may have: on iOS an unfilled placeholder would be pasted into the shell as text. The only placeholder here is `ROUTER_IP` in `ni1`, replace it by hand.
- Total silence after Enter in Blink means the command did not start (a paste problem), not a network diagnosis. Paste again.

Snippety users: the `Format` field should be **Plain Text**. The suggested keywords above work with Snippety's default `:` trigger on macOS (`:nm3`).
