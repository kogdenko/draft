# ./build-apps/pkt-gen/pkt-gen -c 8 -a 2 -i enp5s0f1 -f tx
# ./build-apps/pkt-gen/pkt-gen -c 8 -a 1 -i enp5s0f0 -f rx

nic()
{
	ifconfig $1 promisc up                                    
	ethtool -L $1 combined 1
	ethtool -G $1 rx 2048 tx 2048
}

rmmod ixgbe
insmod ./netmap.ko
insmod ./ixgbe/ixgbe.ko

nic ix0a
nic ix0b
nic ix1a
nic ix2b
nic ix2a
nic ix2b
nic ix3a
nic ix3b
