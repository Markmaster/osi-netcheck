# Blink Shell

For the local `blink>` shell, before any ssh/mosh. Needs Blink 18.6.0+ (older versions do not run snips at the local prompt, [blinksh/blink#2241](https://github.com/blinksh/blink/issues/2241)) and iCloud Drive enabled for Blink.

## Install

| Copy | To | Inside Blink |
|---|---|---|
| `blink/snips/osi/` | iCloud Drive > Blink > snips > osi | snips `osi/*` |
| `blink/snips/vpn/` ([VPN check](../docs/vpn.md)) | iCloud Drive > Blink > snips > vpn | snips `vpn/*` |
| `blink/snips/tp/` (optional, [Teleport check](../docs/teleport.md)) | iCloud Drive > Blink > snips > tp | snips `tp/*` |
| `blink/snips/mosh/` (optional, [mosh check](../docs/mosh.md)) | iCloud Drive > Blink > snips > mosh | snips `mosh/*` |
| `scripts/` | iCloud Drive > Blink > scripts (next to `snips`, not inside) | `~/iCloud/scripts/osi.awk`, `vpn.awk`, `teleport.awk`, `mosh.awk`, `mosh-watch.sh` and the `.bin` request files |

- `scripts` inside `snips` = `awk: can't open file` on `osi/run`, plus a stray snip `scripts/osi`.
- Cloud icon on a file = not downloaded yet: long-press -> Download Now. Blink skips files that are not on the device.
- Every file in `osi/`, `vpn/`, `tp/` and `mosh/` becomes a snip; keep nothing else there.
- Blink reads snips only from Settings > Snips > Default Location: set it to iCloud Drive.

## Use

`⌘<` (no keyboard: double-tap ⌘ on the bar above the keyboard -> Snips) -> type `osi` -> pick a snip -> the editor opens -> ➤ (or `⌘↩`) puts the command on the prompt -> Enter.

| Snip | Does |
|---|---|
| `osi/run` | All steps except the gateway + verdict |
| `osi/run-wifi` | Same + gateway; fill `${router_ip}` (Settings > Wi-Fi > (i) > Router) before ➤ |
| `osi/0-verdict` | Cheat sheet, comments only, sends nothing |
| `osi/1` ... `osi/7b` | One raw check each (`osi/1` asks for `${router_ip}`); the hint is the snip's first line |

- `⌘↩` straight from the list skips the editor and sends `${router_ip}` unfilled: use it only for snips without a parameter.
- Close the editor with ✕, not save, or your edit stays in the file.
- No output at all after Enter = the command did not start; paste again.
