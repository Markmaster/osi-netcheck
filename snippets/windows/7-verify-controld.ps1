"== 7. Control D verify =="
Resolve-DnsName verify.controld.com
"Expect api.controld.com, 147.185.34.1 and 2606:1a40:3::1. Present = the system path goes through Control D."
"Do not use nslookup.exe here: per the Control D docs it bypasses NRPT (DNS Intercept Mode). Final check: https://controld.com/status"