# Auto check: Control D or the internet

One command runs steps 1-7b, prints `[  OK]`/`[FAIL]` for each, and ends with who is to blame: the internet, the network or your Control D setup. The scripts change nothing on the system: only ping, TCP connects, DNS queries and one HTTPS request. No data is sent anywhere except those probes.

| File | Runs on | Command |
|---|---|---|
| `osi.awk` | Blink Shell on iPhone/iPad (local `blink>` shell) | `awk -f ~/iCloud/scripts/osi.awk` or snip `osi/run` |
| `osi.awk` | macOS, Terminal | `awk -f ~/osi.awk` |
| `osi.ps1` | Windows, PowerShell 5.1 or 7 | `powershell -ExecutionPolicy Bypass -File "$HOME\osi.ps1"` |

## Install

- **iPhone/iPad (Blink):** put the `scripts` folder into **iCloud Drive > Blink**, next to `snips`. Details: [`blink/HOWTO.md`](../blink/HOWTO.md).
- **macOS:** put `osi.awk` into your home folder (`~/osi.awk`). The script finds the gateway itself via `route`.
- **macOS 15+:** run it from Terminal.app. Third-party terminals (iTerm2, Warp, VS Code) may need Local Network access (System Settings > Privacy & Security > Local Network), otherwise step 1 (router) fails falsely.
- **Windows:** download `osi.ps1` as a file (GitHub -> Raw -> Save as, or Code -> Download ZIP) and put it into your user folder (`C:\Users\<name>\osi.ps1`). Paste the command into a **PowerShell** window: only PowerShell expands `$HOME`. From cmd: `powershell -ExecutionPolicy Bypass -File "%USERPROFILE%\osi.ps1"`.
- `-ExecutionPolicy Bypass` is needed because Windows clients do not run `.ps1` files at all by default (policy Restricted). It applies to this one run and does not change the system policy. On a work PC, Group Policy can still block it.

Set the gateway by hand: `awk -v gw=IP -f ~/osi.awk` on a Mac, `powershell -ExecutionPolicy Bypass -File "$HOME\osi.ps1" -Gateway IP` on Windows.

## Example output

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

(The gateway address is from the documentation range 192.0.2.0/24, not a real network.)

## What is checked

| Step | Check | macOS / Blink | Windows |
|---|---|---|---|
| 1 | Gateway | `ping` (on a Mac the gateway comes from `route -n get default`) | `ping.exe`, gateway from `Get-NetRoute` |
| 2 | Ping 1.1.1.1 and 8.8.8.8 | `ping -c 2 -W 2000` | `ping.exe -n 2 -w 2000` |
| 3 | TCP 443 to 1.1.1.1 | `nc -z -G 3` | `TcpClient`, 3 s |
| 3b | HTTPS to 1.1.1.1 | `curl -m 5` | `curl.exe -m 5 --ssl-no-revoke` |
| 4 | DNS via 1.1.1.1 | `dig @1.1.1.1` | `Resolve-DnsName -Server 1.1.1.1` |
| 5 | Control D over UDP 53 (catches DNS interception) | `dig @76.76.2.0 verify.controld.com` | `Resolve-DnsName verify.controld.com -Server 76.76.2.0` |
| 5b | Control D DoH, TCP 443 | `nc -z -G 3 76.76.2.22 443` | `TcpClient` to 76.76.2.22:443 |
| 6 | System DNS | `ping` by name (the `PING` line) | `Resolve-DnsName` without `-Server` (DNS client with NRPT) |
| 6b | Network DNS | `dig` without `@` | `Resolve-DnsName` against the adapter DNS |
| 7 / 7b | `verify.controld.com` = `147.185.34.1` | same, both paths | same, both paths |

The verdict logic is the same in both scripts. Why each step is there: [`docs/how-it-works.md`](../docs/how-it-works.md).

## What has been tested

- `osi.awk` in Blink on an iPhone: an earlier version ran end to end once on a real network (the all-OK case). The current version and the failure verdicts were checked only with fake commands.
- `osi.awk` on macOS and `osi.ps1` on Windows have not been run on real devices yet. The logic was run against fake commands: awk on BWK awk, mawk and the exact awk build Blink ships, PowerShell on PowerShell 7 with the network functions mocked. Windows PowerShell 5.1 compatibility of `osi.ps1` was checked with PSScriptAnalyzer.

If you run it on a Mac or a Windows PC, an issue with the output is welcome.
