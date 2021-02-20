#!/usr/bin/python

import os
import nfqueue
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *

iptablesr = "iptables -A INPUT -i eth0  -t filter -p tcp --dport 4443 -j NFQUEUE --queue-num 0"
iptablesr1 = "iptables -A FORWARD -i eth0  -t filter -p tcp --dport 4443 -j NFQUEUE --queue-num 0"

print("Adding iptable rules :")
print(iptablesr)
print(iptablesr1)

os.system("sysctl net.ipv4.ip_forward=1")
os.system(iptablesr)
#os.system(iptablesr1)

def callback(payload):
    # Here is where the magic happens.
    data = payload.get_data()
    pkt = IP(data)

    try:
        s = SSL(str(pkt))
        r = str(pkt[TCP].payload)
        s.do_dissect(r)
        #print("test_test " + str(pkt.dport))
        #print("test_test " + str(s[:2].content_type))
        #print("test_test " + str(s[:4].type))
        #s.show()
        if pkt.dport == 4443 and s[:2].content_type == 22 and s[:4].type == 1:
		# change random_bytes) if the packet is a client hello
                print("client hello found ")
                #print("random_bytes " + str(s[:5].random_bytes))
		s[:5].random_bytes = "\x1ex\x1a\x11'\x14@\xb8\xd5u\xe5\xf1\xb6\xb3L\n\xc6T\x8c\x01\xbdx\x06\x00\x95\xcbm"   
                #pkt.src = "192.168.40.148"
                #pkt.dst = "172.30.1.100"
                pkt[TCP].payload = str(s)
                pkt.show()
                
                del pkt[TCP].chksum
                del pkt.ihl
                del pkt.len
                del pkt.chksum
                pkt = Ether(bytes(pkt))

                #payload.set_payload(str(pkt))
                #payload.accept()
                payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
		print("forward after the modification")

		#payload.set_verdict(nfqueue.NF_ACCEPT)
		#payload.set_verdict(nfqueue.NF_DROP)
		
	else:
		# Let the rest go it's way
		payload.set_verdict(nfqueue.NF_ACCEPT)
			
    except:
        payload.set_verdict(nfqueue.NF_ACCEPT)
		
    # If you want to modify the packet, copy and modify it with scapy then do :
    #payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))


def main():
    # This is the intercept
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')


if __name__ == "__main__":
    main()
