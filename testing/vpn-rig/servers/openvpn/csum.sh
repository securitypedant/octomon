#!/bin/sh
# OpenVPN --up hook: recompute TCP checksums in software on everything the
# server sends into the tunnel device ($1 is the device OpenVPN just made).
# Frames that reach this container from Docker Desktop's NAT cross a veth
# pair with the TCP checksum left unfilled; the kernel trusts them, OpenVPN
# copies them verbatim into the tunnel, and the client drops them as
# checksum errors. act_csum fills them in on egress.
dev=$1
tc qdisc add dev "$dev" root handle 1: prio
tc filter add dev "$dev" parent 1: protocol ip u32 match ip protocol 6 0xff action csum ip tcp
