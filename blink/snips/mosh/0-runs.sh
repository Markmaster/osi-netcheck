# MOSH RUNS: cheat sheet. Read only, sending it sends nothing
# 0  Once per server: mosh/copy. Firewall opens only a few mosh ports? Use one of them: sudo ECHO_PORT=60010 sh ~/mosh-watch.sh watch 10, and -v port=60010 on the phone.
# 1  Server: mosh/watch, minutes = 10. It lists the sessions, starts the echo, then logs every mosh packet event.
# 2  Phone on Wi-Fi with Cellular Data off: mosh/run. Then Wi-Fi off (LTE): mosh/run again. The second run tests the first run's address.
# 3  Within the 10 min: start a mosh session on Wi-Fi, Wi-Fi off, wait 40 s with Blink in front, Wi-Fi on. Note the times.
# 4  Same with a session started on LTE: Wi-Fi on, wait 40 s, Wi-Fi off.
# 5  Server: the summary at the end, or cat /tmp/mosh-watch-*.txt.
#
# Read: mosh/run "Here: NO" for the other network's address -> the session's address does not exist there: fix in docs/mosh.md.
#       mosh/run YES both ways, but the session freezes -> mosh-watch says why:
#         "phone hears nothing"            answers are lost on the way to the phone on that network
#         "no packets for 7 s" in front     the phone's packets do not reach the server
#         "server keeps sending to"         mosh or Blink problem, not the network
#         "no mosh-server listens"          the session is gone, start a new one
# Full table: docs/mosh.md
