echo "== 5. Control D directly, without your profile =="
dig @76.76.2.0 example.com +short +time=2 +tries=1
dig @76.76.10.0 example.com +short +time=2 +tries=1
nc -zv -G 3 76.76.2.22 443
echo "An IP and succeeded = Control D is reachable from this network (DNS 53 and DoH 443). Step 4 OK but timed out here = the network blocks Control D."