#!/bin/sh

flush()
{
	ip a flush dev $1
	ip r flush dev $1
	echo 2 > /proc/sys/net/ipv4/conf/$1/arp_announce
}

set -x

echo 1 > /proc/sys/net/ipv4/ip_forward
ip netns del net
sleep 1

flush ix3a
flush ix3b
flush ix2a

ip netns add net
ip l s dev ix3a netns net
ip netns exec net ifconfig ix3a 192.168.30.13/24 up
ip netns exec net ip a a dev ix3a 16.0.0.1/32
ip netns exec net ip r a 48.0.0.0/8 dev ix3a src 16.0.0.1 via 192.168.30.11

ifconfig ix3b 192.168.31.13/24 up
ifconfig ix2a 192.168.20.12/24 up

ip r a 48.0.0.0/8 dev ix2a via 192.168.20.10
ip r a 16.0.0.0/8 dev ix3b via 192.168.31.11

iptables -L
iptables -P FORWARD ACCEPT
systemctl disable --now firewalld
systemctl disable --now ufw
