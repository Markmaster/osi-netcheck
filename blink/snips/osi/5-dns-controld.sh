# 5 Control D on UDP 53, no profile: 147.185.34.1 = Control D answered. Empty while 4 works = the network intercepts DNS. timed out = blocked (matters for Control D on a router; DoH is 5b)
dig @76.76.2.0 verify.controld.com +short +time=2 +tries=1
