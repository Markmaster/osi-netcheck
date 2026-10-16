# 5 Control D on UDP 53, no profile: an IP = reachable, timed out while 4 works = UDP 53 to Control D blocked (matters for Control D on a router; DoH is 5b)
dig @76.76.2.0 example.com +short +time=2 +tries=1
