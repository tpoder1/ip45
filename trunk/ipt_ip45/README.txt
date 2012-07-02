
iptables -F -t mangle ; rmmod ipt_IP45 ; make && make install && insmod ./ipt_IP45.ko

iptables -t mangle  -I POSTROUTING  -o eth0 -p 155 -j IP45 --outer-addr=147.229.240.241 --inner-prefix=192.168.0.0/24
iptables -t mangle  -I PREROUTING  -i eth0 -p 155 -j IP45 --outer-addr=147.229.240.241 --inner-prefix=192.168.0.0/24


