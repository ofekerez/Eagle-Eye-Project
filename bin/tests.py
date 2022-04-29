from scapy.all import *
packet = IP(dst='10.0.0.20') / TCP(dport=4444)
for i in range(10000):
    send(packet)