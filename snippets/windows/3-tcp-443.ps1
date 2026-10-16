"== 3. TCP 443 and TLS by IP =="
"TCP 1.1.1.1:443 = $(Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet)"
"TCP 8.8.8.8:443 = $(Test-NetConnection 8.8.8.8 -Port 443 -InformationLevel Quiet)"
curl.exe -sS -m 5 --ssl-no-revoke -o NUL -w "HTTPS 1.1.1.1: %{http_code}\n" https://1.1.1.1
"True and a code other than 000 = outbound TCP and TLS work. False = the network blocks TCP 443 (firewall, captive portal). True but 000 = captive portal or TLS interception."