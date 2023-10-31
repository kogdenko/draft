echo 1 >  /proc/sys/net/ipv4/ip_forward
ip l a dev veth_gw type veth peer veth_net
ip netns a net
ip l s dev veth_net netns net
ifconfig veth_gw 10.1.0.1/16 up
ifconfig eth2 192.168.0.1/24 up
ip r a 10.2.0.0/16 via 192.168.0.2 dev eth2 proto static src 10.1.0.1
ip netns exec net ifconfig veth_net 10.1.0.10/24 up
ip netns exec net ip r a default dev veth_net via 10.1.0.1
