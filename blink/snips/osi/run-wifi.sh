# AUTO on Wi-Fi: same + router check (asks for its IP). On LTE use osi/run
awk -v gw=${router_ip} -f ~/iCloud/scripts/osi.awk
