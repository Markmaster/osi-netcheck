# 7b Verify via the network DNS: 147.185.34.1 only if your router uses Control D, otherwise empty (normal)
dig verify.controld.com +short +time=2 +tries=1
