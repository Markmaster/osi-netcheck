# TP watch: logs UTR link, internet and public IP changes for N minutes (10 if empty). Keep Blink in front with the screen on
awk -v mode=watch -v minutes=${minutes} -v label=${run_label} -f ~/iCloud/scripts/teleport.awk
