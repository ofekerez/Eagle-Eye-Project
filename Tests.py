from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import ICMP
from scapy.layers.smb import *


def filter_dns(packet):
    return DNS in packet and packet[DNS].opcode == 0 and packet[DNSQR].qtype == 1


def print_query_name(dns_packet):
    print(dns_packet[DNSQR].qname)


def sniff_http_packets():
    sniff(filter="port 80", prn=filter_HTTP, store=False)


def filter_HTTP(packet):
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


def filter_ICMP():
    packets = sniff(filter="icmp", timeout=15, count=15)
    for packet in packets:
        if str(packet.getlayer(ICMP).type) == "8":
            print("Ping Arrived from: ", packet[IP].src)


def filter_DHCP():
    DHCP_packets = sniff(filter='udp and port 68 and port 67', count=3)
    for packet in DHCP_packets:
        print("DHCP request Arrived from: ", packet[IP].src)


def filter_SSH():
    SSH_packets = sniff(filter='port 22', count=1)
    for packet in SSH_packets:
        print("SSH request Arrived from: ", packet[IP].src)


def filter_SMB():
    SMB_packets = sniff(filter='port 139 and port 445', count=2)
    for packet in SMB_packets:
        print(packet.getlayer(IP).src)
        if packet.haslayer(Raw):
            print(SMBSession_Setup_AndX_Request(packet.getlayer(Raw).load).NativeOS)


def filter_FTP():
    FTP_packets = sniff(filter='tcp port 21', count=1)
    for packet in FTP_packets:
        print("Source IP: ", packet[IP].src, "Data: ", packet[Raw].load)


def main():
    # filter_dns()
    # sniff_http_packets()
    # filter_ICMP()
    # filter_DHCP()
    # filter_SSH()
    # filter_FTP()
    # filter_SMB()
    pass


if __name__ == '__main__':
    main()
