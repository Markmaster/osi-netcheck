# Blink Shell snips: install and use

**TL;DR:** put the `osi` folder into **iCloud Drive > Blink > snips** and the `scripts` folder into **iCloud Drive > Blink**. In Blink: `⌘` + `<` -> `osi/run` -> ➤ -> Enter. The script runs every step and tells you who is to blame.

These snips are for the Blink local shell (`blink>`), before you connect to any server. Each snip sends exactly one command.

Needs Blink 18.6.0 or later: in 18.5.x snips did nothing at the local `blink>` prompt ([blinksh/blink#2241](https://github.com/blinksh/blink/issues/2241)). Tested on v18.7.1.

Two modes:
- **Auto:** `osi/run` (or `osi/run-wifi`, which also checks the router) runs `scripts/osi.awk`. It runs every check in turn, prints `[  OK]`, `[FAIL]`, `[  --]` (skipped or not an error) or `[  ??]` (could not tell) for each, and ends with a verdict.
- **Manual:** `osi/1-gateway` ... `osi/7b-verify-network`, one command each. Use them when you want the full output of one check.

## 1. Download

GitHub -> **Code -> Download ZIP**. You need two folders: `blink/snips/osi` and `scripts` (from the repo root).

## 2. Put them into Blink

1. Files app -> **iCloud Drive > Blink > snips**. This is the folder Blink reads: Settings -> Snips -> Default Location = iCloud Drive -> "Open in Files.app". This needs iCloud Drive turned on for Blink; if it is off, Settings -> Snips says "iCloud is disabled on this device" and `osi/run` cannot find `~/iCloud/scripts/osi.awk`.
2. Copy the whole `osi` folder there. You get `snips/osi/1-gateway.sh` and so on.
3. Put the `scripts` folder (with `osi.awk`) one level up, into **iCloud Drive > Blink**, next to `snips`, not inside it. You get `Blink/scripts/osi.awk`, which is `~/iCloud/scripts/osi.awk` inside Blink. If `scripts` ends up inside `snips`, `osi/run` prints `awk: can't open file` and the script shows up in the list as a snip called `scripts/osi`.
4. If the files show a cloud icon, they are not downloaded yet: long-press the folder -> **Download Now**. Blink does not show files that are not downloaded.

Blink rules (from the Blink source code):
- Files directly in the `snips` root are ignored. A subfolder (`osi`) is required.
- Do not put anything else into `osi`: every file there becomes a snip. Do not copy this HOWTO into `snips`.
- Only the folder selected in Default Location is read. With iCloud Drive selected, On My iPhone > Blink > snips is not read.

## 3. Use

- `⌘` + `<` (or double-tap `⌘` on the bar above the keyboard -> Snips) -> type `osi`.
- Pick a step (tap or Return). The `#` hint line shows under the name in the list.
- The snip editor opens (tested on iPhone). Tap ➤ (top right) or press `⌘` + Enter: the command lands on the `blink>` line. You press Enter yourself.
- Shortcut: `⌘` + Enter right in the list sends the selected snip without the editor (from the source code). Do not do this for `osi/1-gateway` and `osi/run-wifi`: `${router_ip}` would be sent as is.
- In `osi/1-gateway` and `osi/run-wifi` the editor highlights `${router_ip}`: type the router IP (Settings > Wi-Fi > (i) > Router), press Return or Complete, then ➤. On LTE skip step 1 and use `osi/run`.
- Do not save the editor (✕ = close without saving), otherwise an accidental edit stays in the file.
- `osi/0-verdict` is the "who is to blame" cheat sheet. Open it and read. Sending it sends nothing, because it only has `#` lines.
- Blink re-reads the folder every time the snips menu opens. No restart needed.

## Snips

| Snip | Command | What it checks |
|---|---|---|
| `osi/run` | `awk -f ~/iCloud/scripts/osi.awk` | **Auto:** every step except the gateway + verdict |
| `osi/run-wifi` | `awk -v gw=${router_ip} -f ~/iCloud/scripts/osi.awk` | **Auto** + gateway (asks for the router IP) |
| `osi/0-verdict` | none | "Who is to blame" cheat sheet |
| `osi/1-gateway` | `ping -c 3 ${router_ip}` | Gateway (router). Skip on LTE |
| `osi/2-ping-ip` | `echo 1.1.1.1 8.8.8.8 \| xargs -n 1 ping -c 3` | Internet by IP, no DNS, two targets. "prohibited by filter" = the network blocks ping |
| `osi/3-tcp-443` | `nc -zv -G 3 1.1.1.1 443` | TCP 443 by IP |
| `osi/3b-https` | `curl -sS -m 5 -o /dev/null -w "%{http_code}\n" https://1.1.1.1` | HTTPS by IP |
| `osi/4-dns-bypass` | `dig @1.1.1.1 example.com +short +time=2 +tries=1` | DNS bypassing Control D |
| `osi/5-dns-controld` | `dig @76.76.2.0 example.com +short +time=2 +tries=1` | Control D directly, without the profile |
| `osi/5b-controld-doh` | `nc -zv -G 3 76.76.2.22 443` | TCP 443 to the Control D DoH endpoint |
| `osi/6-dns-system` | `ping -c 1 -W 2000 example.com` | iPhone system DNS (the PING line) |
| `osi/6b-dns-network` | `dig example.com +short +time=2 +tries=1` | Network or router DNS, bypassing the profile |
| `osi/7-verify-system` | `ping -c 1 -W 2000 verify.controld.com` | Verify via the iPhone system DNS |
| `osi/7b-verify-network` | `dig verify.controld.com +short +time=2 +tries=1` | Verify via the network DNS |

## Writing your own snip

One file = one snip: `snips/<folder>/<name>.sh`.

```bash
# description: the first line, shown in the list, dropped when a one-command snip is sent
command ${parameter}
```

- The first line must not be empty, otherwise the snip does not show up.
- File name: Latin letters, hyphens, no spaces. A dot only before `.sh`: `dns-8.8.8.8.sh` becomes `dns-8`.
- Blink asks you to fill `${name}`. Identical `${name}` fields are filled at once. Write shell variables without braces: `$HOME`, not `${HOME}`.
- UTF-8, LF line endings.

**What works in the local `blink>` shell:**
- Works: one command, `|`, `>`, `>>`, `<`, `2>`.
- Tested on iPhone: `echo 1.1.1.1 8.8.8.8 | xargs -n 1 ping -c 1` runs one command against several targets.
- Does not work: `;`, `&&`, `||`, `$(...)`, `\` at the end of a line, several command lines. By default Blink joins snip lines with `; `, and the local shell does not understand `;`. Multi-line snips only make sense inside ssh/mosh on a server.
- There is no `sh`/`bash` and no aliases in the local shell. If/then logic can be written in `awk` and run as one command, `awk -f file.awk`, like `osi.awk`. A script on a server over ssh/mosh checks the server's network, not the phone's.

How it works and why: [`docs/how-it-works.md`](../docs/how-it-works.md).
