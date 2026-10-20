# VPN + TCP connect to your own server (OpenVPN over TCP): fill server IP/name and TCP port
awk -v server=${server} -v tcp=${tcp_port} -f ~/iCloud/scripts/vpn.awk
