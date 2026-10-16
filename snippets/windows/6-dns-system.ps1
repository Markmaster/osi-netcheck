"== 6. System DNS (your setup) =="
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Format-Table InterfaceAlias, ServerAddresses -AutoSize
Resolve-DnsName example.com
"IPAddress present = the system resolver works. Error = system DNS is broken: ctrld, adapter, router, VPN."