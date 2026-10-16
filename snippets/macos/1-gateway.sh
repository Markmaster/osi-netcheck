echo "== 1. Gateway (router) =="
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
echo "Gateway: ${GW:-not found}"
[ -n "$GW" ] && ping -c 3 "$GW"
echo "Replies = Wi-Fi/cable and router are fine. 100% loss or no gateway = local problem: Wi-Fi, cable, router."