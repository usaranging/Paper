#!/usr/bin/python

#ip link set [dev] promisc on
# ip link set [dev] promisc off
# sysctl net.ipv4.ip_forward=1
# zerowindow return ack : pkt.seq+pkt['IP'].len-40

import os
import nfqueue
from scapy.all import*


iptablesr = "iptables -A INPUT -i eth0  -t filter -p tcp --dport 4443 -j NFQUEUE --queue-num 0"
iptablesr1 = "iptables -A FORWARD -i eth0  -t filter -p tcp --dport 4443 -j NFQUEUE --queue-num 0"
iptablesr2 = "iptables -A OUTPUT -t filter -p tcp --sport 4443 -j DROP"

print("Adding iptable rules :")
print(iptablesr)
print(iptablesr1)
print(iptablesr2)

os.system("sysctl net.ipv4.ip_forward=1")
os.system(iptablesr)
os.system(iptablesr1)
os.system(iptablesr2)

def callback(payload):
    # Here is where the magic happens.
    data = payload.get_data()
    pkt = IP(data)
    pkt_tcp = TCP(data)
    print("Got a packet ! source ip : " + str(pkt.src))
    print("flags: " + str(pkt.flags))
    abc = pkt['TCP'].flags
    print("abc : "+ str(abc))

#   pkt['TCP'].flags == 16 means "ACK"
    if pkt.dport == 4443 and (pkt['TCP'].flags == 16 or pkt['TCP'].flags == 24):
        # request to send all packets coming from this IP
        ip=IP(src=pkt.dst,dst=pkt.src)
        respkt=TCP(sport=pkt.dport,dport=pkt.sport,seq=pkt.ack, ack=pkt.seq+pkt['IP'].len-40, flags="A", window=0)
        send(ip/respkt)
        print("Receive ACK, Send Zero window")

        time.sleep(5)
        respkt=TCP(sport=pkt.dport,dport=pkt.sport,seq=pkt.ack, ack=pkt.seq+pkt['IP'].len-40, flags="A", window=4106)
        send(ip/respkt)
        
        time.sleep(1000)

        payload.set_verdict(nfqueue.NF_DROP)

    else:
        # Let the rest go it's way
        payload.set_verdict(nfqueue.NF_ACCEPT)

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
#        os.system("sysctl net.ipv4.ip_forward=0")

if __name__ == "__main__":
    main()
