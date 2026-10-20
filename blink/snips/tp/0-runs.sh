# TP RUNS: cheat sheet. Read only, sending it sends nothing
# Same UTR firmware, binding and placement every run. Change one thing per run.
# 0  CGM: tp/cgm "info" once. Note the Teleport WireGuard port and whether WAN IP = public IP.
# 1  Office xfinitywifi as UTR uplink. CGM: tp/cgm "capture 300 CLIENT_PUBLIC_IP".
#    Client (Mac, or iPhone with Cellular Data off): tp/run, then toggle Teleport in the UniFi app.
#    1b: same with Teleport off in the UTR (compare the public IP rows).
# 2  Control: iPhone hotspot (LTE) as UTR uplink, client = Mac behind the UTR. Same steps.
#    The hotspot iPhone cannot be the client behind the UTR at the same time.
# 3  Optional: Mac straight on xfinitywifi, no UTR. Same probes.
#
# Read: office fails + LTE works + nothing arrives at the CGM (UDP probes NONE, STUN FAIL) -> uplink blocks UDP.
#       office fails + LTE works + probes arrive, incl. the 148 B WG-shaped one -> not a port block: UTR or relay path.
#       1-byte probes arrive, 148 B WG-shaped does not -> the uplink filters the WireGuard handshake shape.
#       office fails + LTE fails -> not the uplink: firmware, binding or home side (CGM info: DNS, inbound rows).
# Full table: docs/teleport.md
