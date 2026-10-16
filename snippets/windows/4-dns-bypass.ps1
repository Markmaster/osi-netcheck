"== 4. DNS bypassing Control D =="
Resolve-DnsName example.com -Server 1.1.1.1 -Type A -DnsOnly
Resolve-DnsName example.com -Server 8.8.8.8 -Type A -DnsOnly
"IPAddress present = DNS over the internet works. Error or timeout = the network blocks outside DNS (UDP 53)."