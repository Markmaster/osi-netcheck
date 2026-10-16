"== 1. Gateway (router) =="
$gw = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
"Gateway: $gw"
if ($gw) { ping -n 3 $gw }
"Replies = Wi-Fi/cable and router are fine. No reply or empty gateway = local problem: Wi-Fi, cable, router."
""
"== 2. Internet by IP, no DNS =="
ping -n 3 1.1.1.1
ping -n 3 8.8.8.8
"Replies = the internet works. Both without reply = internet or ISP (or ICMP is blocked, compare with step 3). Not Control D."
""
"== 3. TCP 443 and TLS by IP =="
"TCP 1.1.1.1:443 = $(Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet)"
"TCP 8.8.8.8:443 = $(Test-NetConnection 8.8.8.8 -Port 443 -InformationLevel Quiet)"
curl.exe -sS -m 5 --ssl-no-revoke -o NUL -w "HTTPS 1.1.1.1: %{http_code}\n" https://1.1.1.1
"True and a code other than 000 = outbound TCP and TLS work. False = the network blocks TCP 443 (firewall, captive portal). True but 000 = captive portal or TLS interception."
""
"== 4. DNS bypassing Control D =="
Resolve-DnsName example.com -Server 1.1.1.1 -Type A -DnsOnly
Resolve-DnsName example.com -Server 8.8.8.8 -Type A -DnsOnly
"IPAddress present = DNS over the internet works. Error or timeout = the network blocks outside DNS (UDP 53)."
""
"== 5. Control D directly, without your profile =="
Resolve-DnsName example.com -Server 76.76.2.0 -Type A -DnsOnly
Resolve-DnsName example.com -Server 76.76.10.0 -Type A -DnsOnly
"TCP 76.76.2.22:443 (DoH dns.controld.com) = $(Test-NetConnection 76.76.2.22 -Port 443 -InformationLevel Quiet)"
"IPAddress and True = Control D is reachable from this network. Step 4 OK but Resolve-DnsName error here = the network blocks Control D on UDP 53 (matters for Control D on a router). False = ctrld (DoH) cannot reach Control D."
""
"== 6. System DNS (your setup) =="
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Format-Table InterfaceAlias, ServerAddresses -AutoSize
Resolve-DnsName example.com
"IPAddress present = the system resolver works. Error = system DNS is broken: ctrld, adapter, router, VPN."
""
"== 7. Control D verify =="
Resolve-DnsName verify.controld.com
"Expect api.controld.com, 147.185.34.1 and 2606:1a40:3::1. Present = the system path goes through Control D."
"Do not use nslookup.exe here: per the Control D docs it bypasses NRPT (DNS Intercept Mode). Final check: https://controld.com/status"