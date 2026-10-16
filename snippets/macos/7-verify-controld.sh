echo "== 7. Control D verify =="
echo "-- network DNS from /etc/resolv.conf (does not see a DNS profile; ctrld shows as 127.0.0.1):"
nslookup verify.controld.com
echo "-- system resolver (what apps use):"
dscacheutil -q host -a name verify.controld.com
echo "Look at the system resolver part: 147.185.34.1 there = apps go through Control D. No answer there while step 6 works = most likely another resolver."
echo "The first part shows only the network (or ctrld) path: no answer there is normal unless your router uses Control D. Final check: https://controld.com/status"