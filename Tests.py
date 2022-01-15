from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.http import HTTPRequest


def filter_dns(packet):
    return DNS in packet and packet[DNS].opcode == 0 and packet[DNSQR].qtype == 1


def print_query_name(dns_packet):
    print(dns_packet[DNSQR].qname)


def filter_http_requests(packet):
    return packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method == b'GET' or packet.haslayer(HTTPRequest) and \
           packet[
               HTTPRequest].Method == b'POST'


def print_http(packet):
    result = packet.show(dump=True)
    paths = result.split("Path")
    if packet[HTTPRequest].Method == b"GET":
        for i in range(len(paths)):
            print("GET", paths[i][:paths[i].find('\n')].strip("###[ Ethernet ]###\n ="))
    else:
        for i in range(len(paths)):
            print("POST", paths[i][:paths[i].find('\n')].strip("###[ Ethernet ]###\n ="))

def main():
    try:
        sniff(count=10, lfilter=filter_http_requests, prn=print_http)
    except IndexError:
        pass
    # print('\nresult output:', get_data(packets))


if __name__ == '__main__':
    main()
