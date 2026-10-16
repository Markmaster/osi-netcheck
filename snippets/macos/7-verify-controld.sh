echo "== 7. Control D verify =="
nslookup verify.controld.com
echo "-- system resolver (what apps use):"
dscacheutil -q host -a name verify.controld.com
echo "Expect api.controld.com, 147.185.34.1 and 2606:1a40:3::1. Present = this path goes through Control D."
echo "A different answer while step 6 works = most likely another resolver. Final check: https://controld.com/status"