# ./build-apps/pkt-gen/pkt-gen -c 8 -a 2 -i enp5s0f1 -f tx
# ./build-apps/pkt-gen/pkt-gen -c 8 -a 1 -i enp5s0f0 -f rx

nic()
{
	if ifconfig -a -s | grep $1 > /dev/null;
	then
		ifconfig $1 promisc up
		ethtool -L $1 combined 1
		ethtool -G $1 rx 2048 tx 2048
		sleep 1
		ethtool -A $1 rx off tx off
	fi
}

set -x

rmmod ixgbe
rmmod netmap
insmod ./netmap.ko
insmod ./ixgbe/ixgbe.ko

nic ix0a
nic ix0b

nic ix1a
nic ix1b

nic ix2a
nic ix2b

nic ix3a
nic ix3b
