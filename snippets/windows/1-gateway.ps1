"== 1. Gateway (router) =="
$gw = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
"Gateway: $gw"
if ($gw) { ping -n 3 $gw }
"Replies = Wi-Fi/cable and router are fine. No reply or empty gateway = local problem: Wi-Fi, cable, router."