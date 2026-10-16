# 4 DNS bypassing Control D: an IP = outside DNS works, timed out = the network blocks UDP 53
dig @1.1.1.1 example.com +short +time=2 +tries=1
