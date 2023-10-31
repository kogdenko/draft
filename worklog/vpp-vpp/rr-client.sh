#!/bin/sh

flush()
{
	ip a flush dev $1
	ip r flush dev $1
}

flush ix0a

ifconfig ix0a 192.168.20.10/24 up
ip a a dev ix0a 48.0.0.1/32
ip r a 16.0.0.0/8 dev ix0a src 48.0.0.1 via 192.168.20.12
