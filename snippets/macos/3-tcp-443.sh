echo "== 3. TCP 443 and TLS by IP =="
nc -zv -G 3 1.1.1.1 443
nc -zv -G 3 8.8.8.8 443
curl -sS -m 5 -o /dev/null -w "HTTPS 1.1.1.1: %{http_code}\n" https://1.1.1.1
echo "succeeded and a code other than 000 = outbound TCP and TLS work. failed/timeout = the network blocks TCP 443 (firewall, captive portal). succeeded but 000 = captive portal or TLS interception."