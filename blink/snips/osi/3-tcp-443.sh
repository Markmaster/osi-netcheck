# 3 TCP 443 by IP: succeeded = outbound TCP works, error/timed out = the network blocks 443
nc -zv -G 3 1.1.1.1 443
