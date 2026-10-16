echo "== 6. System DNS (your setup) =="
echo "System DNS servers:"
scutil --dns | awk '/nameserver\[/{print "  " $3}' | sort -u
dscacheutil -q host -a name example.com
echo "ip_address present = the system resolver works. Empty = system DNS is broken: profile, ctrld, router, VPN."