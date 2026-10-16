# WHO IS TO BLAME: cheat sheet. Read only, sending it sends nothing
# Auto: osi/run (all steps + verdict). Manual: osi/1 -> osi/7b, the first failing step is the answer.
#
# 1  Gateway FAIL -> Wi-Fi or router. Not Control D. Skip step 1 on LTE.
# 2  Ping by IP FAIL and 3 FAIL -> internet or ISP. Not Control D.
#    Ping FAIL but 3 OK -> the network blocks ICMP, the internet works.
# 3  TCP 443 FAIL while ping works -> the network blocks 443 (firewall, captive portal).
#    3 OK but 3b HTTPS FAIL -> captive portal or TLS interception.
# 4  DNS @1.1.1.1 FAIL while 3 works -> the network blocks outside DNS (UDP 53).
# 5  Control D on UDP 53 FAIL while 4 works -> the network blocks Control D plain DNS
#    (matters for Control D on a router; a DoH profile does not use it).
#    Answer without 147.185.34.1 -> the network intercepts DNS (same effect for a router).
# 5b TCP 443 to Control D DoH FAIL -> the iPhone DNS profile cannot reach Control D.
# 6  System DNS (the PING line) cannot resolve while 5b works -> your setup.
# 7  Verify is not 147.185.34.1 while 6 works -> DNS most likely bypasses Control D:
#    VPN, manual DNS, network excluded in the profile,
#    iCloud Private Relay if you allowed it in Control D.
#
# 6/7 (ping by name) = the iPhone system resolver, same as apps use.
# 6b/7b (dig without @) = the network, router or VPN DNS directly, the profile does not see it.
# 7b shows Control D only if it runs on your router. Otherwise 7b prints nothing, that is normal.
#
# Total silence after Enter = the command did not start, paste it again.
# Final check in Safari: https://controld.com/status
