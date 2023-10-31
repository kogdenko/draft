#!/bin/sh
VPP=/root/vpp/bin/vpp
RIP=192.168.0.1               
LIP=192.168.0.2
LIP_MASK=16                                                                                    
LTS=10.2.0.1
LTS_MASK=16      
RTS=10.1.0.0
RTS_MASK=16                                                                                    
                                               
/bin/stop.sh     
                                               
cat <<EOF > /etc/swanctl/conf.d/swanctl.conf
connections {
                                               
   gw-gw {                     
      local_addrs  = $LIP                                                                      
      remote_addrs = $RIP

      local {                                                                                  
         auth = psk
      }                                                                                        
      remote {
         auth = psk
      }
      children {            
         net-net {
            local_ts  = $LTS/$LTS_MASK                                                         
            remote_ts = $RTS/$RTS_MASK
            updown = /usr/local/libexec/ipsec/_updown iptables
            rekey_time = 5400
            rekey_bytes = 500000000
            rekey_packets = 1000000
            esp_proposals = aes128gcm128-x25519 
         }
      }
      version = 1
      reauth_time = 10800
      proposals = aes128-sha256-x25519
   }
}

secrets {
   ike-1 {
      secret = 0sv+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL
   }
}
EOF

$VPP -c /root/vpp/startup.conf

while ! ifconfig -a -s | grep eth2 > /dev/null; 
do
        sleep 0.1
done
while ! ifconfig -a -s | grep eth3 > /dev/null; 
do
        sleep 0.1
done

ifconfig eth3 $LTS/$LTS_MASK up
ifconfig eth2 $LIP/$LIP_MASK up
ip r a $RTS/$RTS_MASK via $RIP dev eth2 proto static src $LTS
echo "VPP started..."

/root/vpp/build-root/build-vpp-native/external/sswan/src/charon/charon &

while ! nc -z -U /var/run/charon.vici </dev/null;
do
        sleep 0.1
done
echo "strongswan started..."

/root/vpp/build-root/build-vpp-native/external/sswan/src/swanctl/swanctl --load-all
