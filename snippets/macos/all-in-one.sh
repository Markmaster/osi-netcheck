echo "== 1. Gateway (router) =="
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
echo "Gateway: ${GW:-not found}"
[ -n "$GW" ] && ping -c 3 "$GW"
echo "Replies = Wi-Fi/cable and router are fine. 100% loss or no gateway = local problem: Wi-Fi, cable, router."
echo
echo "== 2. Internet by IP, no DNS =="
ping -c 3 1.1.1.1
ping -c 3 8.8.8.8
echo "Replies = the internet works. Both 100% loss = internet or ISP (or ICMP is blocked, compare with step 3). Not Control D."
echo
echo "== 3. TCP 443 and TLS by IP =="
nc -zv -G 3 1.1.1.1 443
nc -zv -G 3 8.8.8.8 443
curl -sS -m 5 -o /dev/null -w "HTTPS 1.1.1.1: %{http_code}\n" https://1.1.1.1
echo "succeeded and a code other than 000 = outbound TCP and TLS work. failed/timeout = the network blocks TCP 443 (firewall, captive portal). succeeded but 000 = captive portal or TLS interception."
echo
echo "== 4. DNS bypassing Control D =="
dig @1.1.1.1 example.com +short +time=2 +tries=1
dig @8.8.8.8 example.com +short +time=2 +tries=1
echo "An IP = DNS over the internet works. timed out = the network blocks outside DNS (UDP 53)."
echo
echo "== 5. Control D directly, without your profile =="
dig @76.76.2.0 example.com +short +time=2 +tries=1
dig @76.76.10.0 example.com +short +time=2 +tries=1
nc -zv -G 3 76.76.2.22 443
echo "An IP and succeeded = Control D is reachable from this network (DNS 53 and DoH 443). Step 4 OK but dig timed out here = the network blocks Control D on UDP 53 (matters for Control D on a router). nc failed = a DoH profile or ctrld cannot reach Control D."
echo
echo "== 6. System DNS (your setup) =="
echo "System DNS servers:"
scutil --dns | awk '/nameserver\[/{print "  " $3}' | sort -u
dscacheutil -q host -a name example.com
echo "ip_address present = the system resolver works. Empty = system DNS is broken: profile, ctrld, router, VPN."
echo
echo "== 7. Control D verify =="
echo "-- network DNS from /etc/resolv.conf (does not see a DNS profile; ctrld shows as 127.0.0.1):"
nslookup verify.controld.com
echo "-- system resolver (what apps use):"
dscacheutil -q host -a name verify.controld.com
echo "Look at the system resolver part: 147.185.34.1 there = apps go through Control D. No answer there while step 6 works = most likely another resolver."
echo "The first part shows only the network (or ctrld) path: no answer there is normal unless your router uses Control D. Final check: https://controld.com/status"