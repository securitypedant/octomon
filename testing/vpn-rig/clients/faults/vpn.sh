#!/bin/sh
# vpn <fault> | disconnect
# Faults, each applied on a clean slate (the previous one is removed first):
#   none        nothing wrong
#   loss        15% packet loss on the link (tc netem)
#   latency     +250ms (±30ms) on everything (tc netem)
#   dns         port 53 dropped, everything else fine
#   web         TCP 80 and 443 rejected, ping and DNS fine
#   no-icmp     outbound ICMP dropped, TCP and DNS fine
#   no-internet nothing leaves the LAN (the gateway still answers)
#   captive     every HTTP request answered by a local "sign in" page, HTTPS dropped
# Rules live in chains of their own so that Docker's DNS redirect in the nat
# table is never touched.
set -eu
lan=$(ip -4 route show dev eth0 scope link | awk '{print $1}' | head -1)
me=$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
clear_all() {
    tc qdisc del dev eth0 root 2>/dev/null || true
    for t in filter nat; do
        iptables -t $t -D OUTPUT -j RIG 2>/dev/null || true
        iptables -t $t -F RIG 2>/dev/null || true
        iptables -t $t -X RIG 2>/dev/null || true
    done
    pkill -x busybox 2>/dev/null || true
}
chains() {
    iptables -t filter -N RIG; iptables -t filter -I OUTPUT -j RIG
    iptables -t nat -N RIG; iptables -t nat -I OUTPUT -j RIG
}
clear_all
case "$1" in
    none|disconnect) ;;
    loss) tc qdisc add dev eth0 root netem loss 15% ;;
    latency) tc qdisc add dev eth0 root netem delay 250ms 30ms ;;
    # Docker's resolver (127.0.0.11) forwards from outside this network
    # namespace, so it has to be cut off as well as port 53 on the wire.
    dns) chains; iptables -A RIG -p udp --dport 53 -j DROP; iptables -A RIG -p tcp --dport 53 -j DROP
        iptables -A RIG -d 127.0.0.11 -j DROP ;;
    web) chains; iptables -A RIG -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset ;;
    no-icmp) chains; iptables -A RIG -p icmp -j DROP ;;
    no-internet) chains; iptables -A RIG -o eth0 ! -d "$lan" -j DROP ;;
    captive) chains
        busybox httpd -p "$me:8080" -h /srv/portal
        iptables -t nat -A RIG -p tcp --dport 80 ! -d "$lan" -j DNAT --to-destination "$me:8080"
        iptables -A RIG -p tcp --dport 443 -j DROP ;;
    *) echo "usage: vpn none|loss|latency|dns|web|no-icmp|no-internet|captive | disconnect" >&2; exit 2 ;;
esac
