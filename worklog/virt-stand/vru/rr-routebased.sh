#!/bin/sh

set -x

vppctl "ip table add 123"
vppctl "ip6 table add 123"

vppctl "set interface ip table GigabitEthernet0/9/0 123"

ifconfig ix1a 192.168.30.11/24 up
ifconfig ix1b 192.168.31.11/24 up

vppctl "ip route add table 123 16.0.0.0/8 via 192.168.30.13 GigabitEthernet0/9/0"

vppctl "set interface state GigabitEthernet0/9/0 up"
vppctl "set interface state GigabitEthernet0/a/0 up"

vppctl set interface rx-mode GigabitEthernet0/9/0 interrupt
vppctl set interface rx-mode GigabitEthernet0/a/0 interrupt
