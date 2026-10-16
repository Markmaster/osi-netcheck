# 3b HTTPS by IP: 301 or 200 = TLS gets through, 000 or a curl error = HTTPS is blocked
curl -sS -m 5 -o /dev/null -w "%{http_code}\n" https://1.1.1.1
