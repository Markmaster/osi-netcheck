# 5 Control D directly, no profile: an IP = reachable, timed out while 4 works = Control D is blocked
dig @76.76.2.0 example.com +short +time=2 +tries=1
