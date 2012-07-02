

USE
====================================================

iptables -t mangle  -I POSTROUTING  -o eth0 -p 155 -j IP45 --outer-addr=147.229.240.241 --inner-prefix=192.168.0.0/24
iptables -t mangle  -I PREROUTING  -i eth0 -p 155 -j IP45 --outer-addr=147.229.240.241 --inner-prefix=192.168.0.0/24


MANUAL INSTALATION 
====================================================
make 
make install 
cp ipt_IP45.ko /lib/modules/$(uname -r)/


DKMS INSTALATION 
====================================================

dkms add -m ipt_IP45 -v 0.1
dkms build -m ipt_IP45 -v 0.1
dkms install -m ipt_IP45 -v 0.1

https://wiki.kubuntu.org/Kernel/Dev/DKMSPackaging

