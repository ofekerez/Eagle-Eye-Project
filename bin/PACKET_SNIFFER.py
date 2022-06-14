import time
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
    return f"DNS\n{dns_packet[Ether].src}\n{dns_packet[IP].src}\n{dns_packet[Ether].dst}\n{dns_packet[IP].dst}\n{dns_packet[DNSQR].qname.decode()}done"


def filterstringDNS(packets: list):
    st = ""
    for packet in packets:
        st += print_query_name(packet)
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
            if packet.haslayer(Raw) and method == "POST":
                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                # then show raw
                st += f"HTTP\n{packet[Ether].src}\n{ip}\n{packet[Ether].dst}\n{packet[IP].dst}\n{packet[Raw].load}\nURL:{url}\n METHOD:{method}done"
            else:
                st += f"HTTP\n{packet[Ether].src}\n{ip}\n{packet[Ether].dst}\n{packet[IP].dst}\nNone\nURL:{url}\n METHOD:{method}done"
    return st


def filter_ICMP(packets):
    """The function receives list of packets and prints the IP of them."""
    st = ""
    for packet in packets:
        if str(packet.getlayer(ICMP).type) == "8":
            st += f"ICMP\n{packet[Ether].src}\n{packet[IP].src}\n{packet[Ether].dst}\n{packet[IP].dst}\nNonedone"
    return st


def filter_DHCP(DHCP_packets):
    """The function receives list of packets and prints the IP of them."""
    st = ""
    for packet in DHCP_packets:
        st += f"DHCP\n{packet[Ether].src}\n{packet[IP].src}\n{packet[Ether].dst}\n{packet[IP].dst}\n"
        if packet.haslayer(Raw):
            st += 'Data: ' + packet[Raw].load
        else:
            st += 'None'
        st += 'done'
    return st


def filter_SSH(SSH_packets):
    """The function receives list of packets and prints the IP of them."""
    st = ""
    for packet in SSH_packets:
        st += f"SSH\n{packet[Ether].src}\n{packet[IP].src}\n{packet[Ether].dst}\n{packet[IP].dst}Nonedone"
    return st


def filter_SMB(SMB_packets):
    """The function receives list of packets and prints the IP of the packets and the raw data of them."""
    st = ""
    for packet in SMB_packets:
        st += f"SMB\n{packet[Ether].src}\n{packet[IP].src}\n{packet[Ether].dst}\n{packet[IP].dst}\n"
        if packet.haslayer(Raw):
            st += SMBSession_Setup_AndX_Request(packet.getlayer(Raw).load).NativeOS
        else:
            st += 'None'
        st += "done"
    return st


def filter_FTP(FTP_packets):
    """The function receives list of packets and prints the IP of the packets and the raw data of them."""
    st = ""
    for packet in FTP_packets:
        if packet.haslayer(Raw):
            st += f"FTP\n{packet[Ether].src}\n {packet[IP].src}\n {packet[Ether].dst}\n{packet[IP].dst}\n" + f"{packet[Raw].load}\ndone"
        else:
            st += f"FTP\n{packet[Ether].src}\n {packet[IP].src}\n {packet[Ether].dst}\n{packet[IP].dst}\n" + 'Nonedone'
    return st


def gen_sniff(num=1000):
    """The function sniffs 1000 packets by default, sorts them by the protocols HTTP, ICMP, SMB, FTP, SSH, DNS, DHCP and prints
    the most important data in them. """
    sorted_packets = [[] for _ in range(7)]
    print('Packet Sniffer has been activated!')
    packets = sniff(count=num)
    path = time.asctime()[4:8] + time.asctime()[8:10] + time.asctime()[
                                                        20:] + time.asctime()[
                                                               11:19].replace(
        ':', ' ')
    file = open(path + '.txt', 'w')
    print('Packet Sniffer has been Terminated!')
    for packet in packets:
        if packet.haslayer(IP):
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
    st = ''
    st += filter_HTTP(sorted_packets[0]) + filter_ICMP(sorted_packets[1]) + filter_SMB(
        sorted_packets[2])
    st += filter_FTP(sorted_packets[3]) + filter_SSH(sorted_packets[4]) + filterstringDNS(
        sorted_packets[5]) + filter_DHCP(sorted_packets[6])
    try:
        file.write(st)
    except Exception as e:
        print(e)
        pass
    file.close()

    return sorted_packets, path


def main():
    print(gen_sniff(1000))


if __name__ == "__main__":
    main()