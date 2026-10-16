"== 5. Control D directly, without your profile =="
Resolve-DnsName example.com -Server 76.76.2.0 -Type A -DnsOnly
Resolve-DnsName example.com -Server 76.76.10.0 -Type A -DnsOnly
"TCP 76.76.2.22:443 (DoH dns.controld.com) = $(Test-NetConnection 76.76.2.22 -Port 443 -InformationLevel Quiet)"
"IPAddress and True = Control D is reachable from this network. Step 4 OK but error or False here = the network blocks Control D."