
supported on kernel >= 2.6.28 

USE
====================================================

iptables -t mangle  -I POSTROUTING  -o eth0 --dport 45 -j ip45bgw --upstream-addr=78.102.66.182  --downstream-prefix=192.168.1.0/24
iptables -t mangle  -I PREROUTING  -i eth0 --dport 45 -j ip45bgw --upstream-addr=78.102.66.182  --downstream-prefix=192.168.1.0/24


MANUAL INSTALATION 
====================================================
make 
make install 


DKMS INSTALATION 
====================================================

dkms add -m ipt_ip45bgw -v 0.1
dkms build -m ipt_ip45bgw -v 0.1
dkms install -m ipt_ip45bgw -v 0.1

https://wiki.kubuntu.org/Kernel/Dev/DKMSPackaging


NOTE FOR COOPERATION WITH SNAT
====================================================
When the ipt_IP45 is run tigether with NAT the packets begonging 
to IP45 do not have to pass to the NAT table. It could be done 
by specyfing NAT rule with a condition to ignore IP45 packets.

Example:

iptables -t nat -A POSTROUTING -o eth1 ! --dport 45 -j SNAT --to-source 147.229.240.241


