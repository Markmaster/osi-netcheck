"== 5. Control D directly, without your profile =="
Resolve-DnsName verify.controld.com -Server 76.76.2.0 -Type A -DnsOnly
Resolve-DnsName verify.controld.com -Server 76.76.10.0 -Type A -DnsOnly
"TCP 76.76.2.22:443 (DoH dns.controld.com) = $(Test-NetConnection 76.76.2.22 -Port 443 -InformationLevel Quiet)"
"IPAddress 147.185.34.1 and True = Control D is reachable from this network. Other or no address while step 4 works = the network intercepts DNS. Error = the network blocks Control D on UDP 53 (matters for Control D on a router). False = ctrld (DoH) cannot reach Control D."