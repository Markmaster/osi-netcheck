echo "== 4. DNS bypassing Control D =="
dig @1.1.1.1 example.com +short +time=2 +tries=1
dig @8.8.8.8 example.com +short +time=2 +tries=1
echo "An IP = DNS over the internet works. timed out = the network blocks outside DNS (UDP 53)."