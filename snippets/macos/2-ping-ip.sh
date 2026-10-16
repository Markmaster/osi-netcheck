echo "== 2. Internet by IP, no DNS =="
ping -c 3 1.1.1.1
ping -c 3 8.8.8.8
echo "Replies = the internet works. Both 100% loss = internet or ISP (or ICMP is blocked, compare with step 3). Not Control D."