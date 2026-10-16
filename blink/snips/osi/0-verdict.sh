# WHO IS TO BLAME: cheat sheet. Read only, sending it sends nothing
# Auto: osi/run (all steps + verdict). Manual: osi/1 -> osi/7b, the first failing step is the answer.
#
# 1  Gateway FAIL -> Wi-Fi or router. Not Control D. Skip step 1 on LTE.
# 2  Ping by IP FAIL and 3 FAIL -> internet or ISP. Not Control D.
#    Ping FAIL but 3 OK -> the network blocks ICMP, the internet works.
# 3  TCP 443 / 3b HTTPS FAIL while ping works -> the network blocks 443 (firewall, captive portal).
# 4  DNS @1.1.1.1 FAIL while 3 works -> the network blocks outside DNS (UDP 53).
# 5  Control D directly FAIL while 4 works -> the network blocks Control D.
# 5b TCP 443 to Control D DoH FAIL -> the iPhone DNS profile cannot reach Control D.
# 6  System DNS (the PING line) cannot resolve while 5 works -> your setup.
# 7  Verify is not 147.185.34.1 while 6 works -> DNS most likely bypasses Control D:
#    VPN, iCloud Private Relay, manual DNS, network excluded in the profile.
#
# 6/7 (ping by name) = the iPhone system resolver, same as apps use.
# 6b/7b (dig without @) = the network or router DNS directly, the profile does not see it.
# At home both show Control D. On another network 7b shows their DNS, that is normal.
#
# Total silence after Enter = the command did not start, paste it again.
# Final check in Safari: https://controld.com/status
