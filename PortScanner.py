from threading import Thread

from scapy.all import *
from scapy.layers.inet import ICMP, IP, UDP, TCP


def check_ports(start_port, end_port):
    if start_port > end_port:
        start_port, end_port = end_port, start_port
    elif start_port == end_port:
        end_port += 1
    return start_port, end_port


class PortScanner:
    def __init__(self, ip_address: str):
        self.target_ip_address = ip_address
        self.open_ports = []

    def UDP_Scan_Wrap(self, start_port=1, end_port=65536):
        start_port, end_port = check_ports(start_port, end_port)
        self.counter = 0
        #########
        from time import perf_counter
        start = perf_counter()
        #########
        for port in range(start_port, end_port):
            Thread(target=self.UDP_Scan, args=(port,)).start()
        #########
        end = perf_counter()
        print(end - start)
        #########
        return self.open_ports

    def UDP_Scan(self, port: int):
        response = sr1(IP(dst=self.target_ip_address) / UDP(dport=port), timeout=10, verbose=0)
        if response and response.haslayer(UDP) or response and response.haslayer(ICMP) and int(
                response.getlayer(ICMP).type) == 3 and int(
            response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
            self.open_ports.append(port)
        self.counter += 1
        if self.counter % 655 == 0:
            print(f"{self.counter / 65536:.2%} done")

    def SYN_Scan_Wrap(self, start_port=1, end_port=65536):
        start_port, end_port = check_ports(start_port, end_port)
        self.counter = 0
        #########
        from time import perf_counter
        start = perf_counter()
        #########
        for port in range(start_port, end_port):
            Thread(target=self.SYN_Scan, args=(port,)).start()
        #########
        end = perf_counter()
        print(end - start)
        #########
        return self.open_ports

    def SYN_Scan(self, port: int):
        packet = IP(dst=self.target_ip_address) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=0.5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            self.open_ports.append(port)
        self.counter += 1
        if self.counter % 655 == 0:
            print(f"{self.counter / 65536:.2%} done")

    def Stealth_Scan_Wrap(self, start_port=1, end_port=65536):
        start_port, end_port = check_ports(start_port, end_port)
        self.counter = 0
        #########
        from time import perf_counter
        start = perf_counter()
        #########
        for port in range(start_port, end_port):
            Thread(target=self.Stealth_Scan, args=(port,)).start()
        #########
        end = perf_counter()
        print(end - start)
        #########
        return self.open_ports

    def Stealth_Scan(self, port: int):
        response = sr1(IP(dst=self.target_ip_address) / TCP(sport=port, dport=port, flags='S'), timeout=5, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                sr(IP(dst=self.target_ip_address) / TCP(sport=port, dport=port, flags='R'), timeout=5, verbose=0)
                self.open_ports.append(port)
        self.counter += 1
        if self.counter % 655 == 0:
            print(f"{self.counter / 65536:.2%} done")


def main():
    port_scanner = PortScanner('10.0.0.20')
    print(port_scanner.SYN_Scan_Wrap(1,4445))
    print(port_scanner.Stealth_Scan_Wrap(1, 4445))
    print(port_scanner.open_ports)


if __name__ == '__main__':
    main()
