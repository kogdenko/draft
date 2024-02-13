#!/bin/bash

DPDK_PING="/home/ubuntu/kogdenko/dpdk-ping/dpdk-ping"

#DPDK_PING="echo"

N_TUNNELS=50000
N_TUNNELS=10000
SESSIONS_PER_TUNNEL=100

FIRST_CORE=25

SRV6_SRC="2a02:5501:0:20c4::2"
SRV6_DST="2a02:5501:0:20c5::1"

N_WORKERS=$(vppctl show threads | grep workers | wc -l)

TUNNELS_PER_WORKER=$(($N_TUNNELS/$N_WORKERS))
if [ $TUNNELS_PER_WORKER -eq 0 ]; then
	TUNNELS_PER_WORKER=1
fi

SRC_BEG=10.20.1.1
SRC_END_ID=$((SESSIONS_PER_TUNNEL - 1))
SRC_END=$(ip-math-add $SRC_BEG $SRC_END_ID)

DPDK_ARGS="--proc-type=primary --file-prefix=ping --vdev=net_memif,socket=/run/vpp/memif.sock,socket-abstract=no"
ARGS=" -- -p net_memif -B 40m -s $SRC_BEG-$SRC_END -d 10.40.1.1 -H 02:fe:83:ea:d6:08 -RE --srv6-src $SRV6_SRC -6 $SRV6_SRC"

config_job()
{
	QUEUE=$(($1 - 1))
	CORE=$(($FIRST_CORE + $QUEUE))
	BEG_TUNNEL_ID=$(($QUEUE*$TUNNELS_PER_WORKER))
	END_TUNNEL_ID=$(($BEG_TUNNEL_ID + $TUNNELS_PER_WORKER - 1))

	SRV6_DST_BEG=$(ip-math-add $SRV6_DST $BEG_TUNNEL_ID)
	SRV6_DST_END=$(ip-math-add $SRV6_DST $END_TUNNEL_ID)

	ARGS="$ARGS -l $CORE -q $QUEUE --srv6-dst $SRV6_DST_BEG-$SRV6_DST_END --"
}

for i in $(seq 1 $N_WORKERS)
do
	config_job $i
done

$DPDK_PING $DPDK_ARGS $ARGS

