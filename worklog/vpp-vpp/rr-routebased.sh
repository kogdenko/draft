#!/bin/sh

flush()
{
        ip a flush dev $1
        ip r flush dev $1
}

set -x

flush ix1a
flush ix1b

ifconfig ix1a 192.168.30.11/24 up
ifconfig ix1b 192.168.31.11/24 up

ip r a 16.0.0.0/8 dev ix1a via 192.168.30.13

#iptable -L
#iptables -P FORWARD ACCEPT
#systemctl disable --now firewalld
#systemctl disable --now ufw
