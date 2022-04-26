from scapy.all import *
from scapy.layers.inet import TCP, ICMP, IP, UDP


def check_ports(start_port, end_port):
    if start_port > end_port:
        start_port, end_port = end_port, start_port
    elif start_port == end_port:
        end_port += 1
    return start_port, end_port


def Connect_Scan(IP_address, start_port=1, end_port=65536):
    """TCP S flag stands for SYN request in the TCP 3 way handshake.
    TCP A flag stands for ACK response in the TCP 3 way handshake
    The code for SYN - ACK flag is 0x12."""
    open_ports = []
    start_port, end_port = check_ports(start_port, end_port)
    for port in range(start_port, end_port):
        packet = IP(dst=IP_address) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=0.5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} is open!")
            open_ports.append(port)
            ACK = IP(dst=IP_address) / TCP(dport=response.sport, flags='AR')
            sr(ACK, timeout=0.2, verbose=0)
    print("Scan is complete!")
    return open_ports


def Stealth_Scan(IP_address, start_port=1, end_port=65536):
    open_ports = []
    start_port, end_port = check_ports(start_port, end_port)
    for port in range(start_port, end_port):
        response = sr1(IP(dst=IP_address) / TCP(sport=port, dport=port, flags='S'), timeout=5, verbose=0)
        if not response:
            print(f"Port {port} is Filtered!")
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                sr(IP(dst=IP_address) / TCP(sport=port, dport=port, flags='R'), timeout=5, verbose=0)
                open_ports.append(port)
                print(f"Port {port} is Open!")
            elif response.getlayer(TCP).flags == 0x14:
                print(f"Port {port} is Closed!")
            elif response.haslayer(ICMP):
                if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) in [1,
                                                                                                    2,
                                                                                                    3,
                                                                                                    9,
                                                                                                    10,
                                                                                                    13]:
                    print(f"Port {port} is Filtered!")
    print("Scan is complete!")
    return open_ports


def UDP_Scan(dst_ip, start_port=1, end_port=65535):
    start_port, end_port = check_ports(start_port, end_port)
    open_ports = []
    for port in range(start_port, end_port):
        response = sr1(IP(dst=dst_ip) / UDP(dport=port), timeout=10, verbose=0)
        if not response:
            print(f"Port {port} is Filtered or Open!")
        elif response.haslayer(UDP):
            open_ports.append(port)
            print(f"Port {port} is Open!")
        elif response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3 and int(
                response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
            print(f"Port {port} is Filtered!")
        else:
            print(f"Port {port} is Closed!")
    return open_ports


def main():
    # SYN_Scan('10.0.0.18')
    Stealth_Scan('10.0.0.20', 20, 90)
    SYN_Scan('10.0.0.20', 1, 100)


if __name__ == "__main__":
    main()
