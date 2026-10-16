echo "== 5. Control D directly, without your profile =="
dig @76.76.2.0 verify.controld.com +short +time=2 +tries=1
dig @76.76.10.0 verify.controld.com +short +time=2 +tries=1
nc -zv -G 3 76.76.2.22 443
echo "147.185.34.1 and succeeded = Control D is reachable from this network (DNS 53 and DoH 443). Empty answer while step 4 works = the network intercepts DNS. dig timed out = the network blocks Control D on UDP 53 (matters for Control D on a router). nc failed = a DoH profile or ctrld cannot reach Control D."