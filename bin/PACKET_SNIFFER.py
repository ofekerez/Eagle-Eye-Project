from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.smb import *
import time

def filter_dns(packet: scapy.packet) -> bool:
    """The function receives a packet and returns whether or not it is a DNS packet."""
    return DNS in packet and packet[DNS].opcode == 0 and packet[DNSQR].qtype == 1


def print_query_name(dns_packet: scapy.packet):
    """The function receives a DNS packet and prints the query name requested in it."""
    return f"DNS request for the domain: {dns_packet[DNSQR].qname.decode()}"


def filterstringDNS(packets: list):
    st = ""
    for packet in packets:
        st += print_query_name(packet) + "\n"
    return st


def sniff_http_packets():
    sniff(filter="port 80", prn=filter_HTTP, store=False)


def filter_HTTP(packets: list):
    """The function receives an HTTP packet and prints out the HTTP request."""
    st = ""
    for packet in packets:
        if packet.haslayer(HTTPRequest):
            # if this packet is an HTTP Request
            # get the requested URL
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            # get the requester's IP Address
            ip = packet[IP].src
            # get the request method
            method = packet[HTTPRequest].Method.decode()
            st += f"\n[+] {ip} Requested {url} with {method}"
            if packet.haslayer(Raw) and method == "POST":
                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                # then show raw
                st += f'\n[*] Some useful Raw data: {packet[Raw].load}'
    return st


def filter_ICMP(packets):
    """The function receives list of packets and prints the IP of them."""
    st = ""
    for packet in packets:
        if str(packet.getlayer(ICMP).type) == "8":
            st += f"Ping Arrived from: {packet[IP].src}\n"
    return st


def filter_DHCP(DHCP_packets):
    """The function receives list of packets and prints the IP of them."""
    st = ""
    for packet in DHCP_packets:
        st += f"DHCP request Arrived from: {packet[IP].src}\n"
    return st


def filter_SSH(SSH_packets):
    """The function receives list of packets and prints the IP of them."""
    st = ""
    for packet in SSH_packets:
        st += f"SSH request Arrived from: {packet[IP].src}\n"
    return st


def filter_SMB(SMB_packets):
    """The function receives list of packets and prints the IP of the packets and the raw data of them."""
    st = ""
    for packet in SMB_packets:
        st += f"SMB request from IP: {packet.getlayer(IP).src}"
        if packet.haslayer(Raw):
            st += SMBSession_Setup_AndX_Request(packet.getlayer(Raw).load).NativeOS + "\n"
    return st


def filter_FTP(FTP_packets):
    """The function receives list of packets and prints the IP of the packets and the raw data of them."""
    st = ""
    for packet in FTP_packets:
        st += f"Source IP: {packet[IP].src}" + f"Data: {packet[Raw].load}\n"
    return st


def gen_sniff(num=1000):
    """The function sniffs 1000 packets by default, sorts them by the protocols HTTP, ICMP, SMB, FTP, SSH, DNS, DHCP and prints
    the most important data in them. """
    sorted_packets = [[] for _ in range(7)]
    print('Packet Sniffer has been activated!')
    packets = sniff(count=num)
    path = time.asctime()[4:8] + time.asctime()[8:10] + "-" + time.asctime()[
                                                                                    20:] + "-" + time.asctime()[
                                                                                                 11:19].replace(
        ':', '_')
    wrpcap(path, packets)
    print('Packet Sniffer has been Terminated!')
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
    return sorted_packets, path


def main():
    gen_sniff()


if __name__ == "__main__":
    main()
