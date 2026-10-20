# TP client check behind the UTR. Fill home WAN IP, run label, Teleport on/off; teleport port and home LAN IP if known
awk -v home=${home_wan_ip} -v label=${run_label} -v tp=${teleport_on_off} -v tport=${teleport_port} -v homelan=${home_lan_ip} -f ~/iCloud/scripts/teleport.awk
