# 2 Ping by IP: replies = internet works. 100% loss and 3/3b FAIL = no internet. "prohibited by filter" or 3b OK = the network blocks ping
echo 1.1.1.1 8.8.8.8 | xargs -n 1 ping -c 3
