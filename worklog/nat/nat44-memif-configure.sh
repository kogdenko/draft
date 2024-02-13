#!/bin/bash

#set -x

HWADDR="02:fe:83:ea:d6:08"
VPPCTL=vppctl_wrap
N_WORKERS=$(vppctl show threads | grep workers | wc -l)
N_TUNNELS=10000
N_SESSIONS=$((1000 + $N_TUNNELS*100))
cflag=0

vppctl_wrap()
{
	vppctl $@
	if [ $? -ne 0 ]; then
		echo $@
		exit 1
	fi
}

config_vrf()
{
	VRF=$1
	LOCALSID=$(ip-math-add 2a02:5501:0:20c5:: $VRF)
	POOL_ADDRESS=$(ip-math-add 10.30.0.0 $VRF)

	if [ $cflag -eq 0 ]; then
		$VPPCTL ip table add $VRF
		$VPPCTL ip6 table add $VRF

		$VPPCTL sr localsid address $LOCALSID behavior end.dt4 $VRF

		$VPPCTL ip route add table $VRF 0.0.0.0/0 via 10.10.10.2 memif0/0
		$VPPCTL sr steer l3 10.20.0.0/16 via bsid 2a02:5501:0:20c6::1 fib-table $VRF
	fi

	$VPPCTL nat44 add address $POOL_ADDRESS tenant-vrf $VRF

}


while getopts "c" arg; do
	case $arg in
	c)
		cflag=1 
		;;
	esac
done

if [ $cflag -eq 0 ]; then 
	$VPPCTL create interface memif hw-addr $HWADDR rx-queues $N_WORKERS tx-queues $N_WORKERS master
	$VPPCTL set interface state memif0/0 up
	$VPPCTL set interface ip address memif0/0 10.10.10.1/24
	$VPPCTL set interface ip address memif0/0 2a02:5501:0:20c4::1/64

	$VPPCTL set sr encaps source addr 2a02:5501:0:20c4::1

	$VPPCTL ip route add 0.0.0.0/0 via 10.10.10.2 memif0/0

	$VPPCTL sr policy add bsid 2a02:5501:0:20c6::1 next 2a02:5501:0:20c4::2 encap
else
	$VPPCTL nat44 plugin disable
fi

$VPPCTL nat44 plugin sessions $N_SESSIONS enable
$VPPCTL set interface nat44 in memif0/0 output-feature

$VPPCTL set nat timeout icmp 10000

for i in $(seq 1 $N_TUNNELS)
do
	config_vrf $i
done
