from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.smb import *


def filter_dns(packet: scapy.packet) -> bool:
    """The function receives a packet and returns whether or not it is a DNS packet."""
    return DNS in packet and packet[DNS].opcode == 0 and packet[DNSQR].qtype == 1


def print_query_name(dns_packet: scapy.packet):
    """The function receives a DNS packet and prints the query name requested in it."""
    print(dns_packet[DNSQR].qname.decode())


def sniff_http_packets():
    sniff(filter="port 80", prn=filter_HTTP, store=False)


def filter_HTTP(packet: scapy.packet):
    """The function receives an HTTP packet and prints out the HTTP request."""
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")
        if packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print('\n[*] Some useful Raw data:', {packet[Raw].load})


def filter_ICMP(packets):
    """The function receives list of packets and prints the IP of them."""
    for packet in packets:
        if str(packet.getlayer(ICMP).type) == "8":
            print("Ping Arrived from: ", packet[IP].src)


def filter_DHCP(DHCP_packets):
    """The function receives list of packets and prints the IP of them."""
    for packet in DHCP_packets:
        print("DHCP request Arrived from: ", packet[IP].src)


def filter_SSH(SSH_packets):
    """The function receives list of packets and prints the IP of them."""
    for packet in SSH_packets:
        print("SSH request Arrived from: ", packet[IP].src)


def filter_SMB(SMB_packets):
    """The function receives list of packets and prints the IP of the packets and the raw data of them."""
    for packet in SMB_packets:
        print(packet.getlayer(IP).src)
        if packet.haslayer(Raw):
            print(SMBSession_Setup_AndX_Request(packet.getlayer(Raw).load).NativeOS)


def filter_FTP(FTP_packets):
    """The function receives list of packets and prints the IP of the packets and the raw data of them."""
    for packet in FTP_packets:
        print("Source IP: ", packet[IP].src, "Data: ", packet[Raw].load)


def gen_sniff():
    """The function sniffs 10000 packets, sorts them by the protocols HTTP, ICMP, SMB, FTP, SSH, DNS, UDP and prints
    the most important data in them. """
    sorted_packets = [[] for _ in range(7)]
    packets = sniff(count=10000)
    for packet in packets:
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            sorted_packets[0].append(packet)
        elif packet.haslayer(ICMP):
            sorted_packets[1].append(packet)
        elif packet.haslayer(SMBSession_Setup_AndX_Request):
            sorted_packets[2].append(packet)
        elif packet.haslayer(TCP) and packet[TCP].dport == 21:
            sorted_packets[3].append(packet)
        elif packet.haslayer(TCP) and packet[TCP].dport == 22:
            sorted_packets[4].append(packet)
        elif packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
            sorted_packets[5].append(packet)
        elif packet.haslayer(UDP) and packet[UDP].dport == 67 or packet.haslayer(UDP) and packet[UDP].dport == 68:
            sorted_packets[6].append(packet)

    for packet in sorted_packets[0]:
        filter_HTTP(packet)
    filter_ICMP(sorted_packets[1])
    filter_SMB(sorted_packets[2])
    filter_FTP(sorted_packets[3])
    filter_SSH(sorted_packets[4])
    for packet in sorted_packets[5]:
        if filter_dns(packet):
            print_query_name(packet)
    filter_DHCP(sorted_packets[6])


def main():
    gen_sniff()


main()
