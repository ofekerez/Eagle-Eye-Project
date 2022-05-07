from scapy.all import *
from scapy.layers.inet import ICMP, IP, UDP, TCP
from helper_methods import get_processor_num


def divide_ports(start_port=1, end_port=65536) -> list:
    """Receives start port and end port and return a list of tuples where each element is a tuple
     specifying a range of ports to scan."""
    length = (end_port - start_port) // (get_processor_num() * 2)
    ind = 0
    l = []
    for port in range(1, get_processor_num() * 2 + 1, length * ind + 1):
        ending_port = length * (ind + 1)
        if ind == get_processor_num() * 2 - 1:
            ending_port = end_port
        l.append((start_port, ending_port))
        start_port += length
        ind += 1
    return l


def check_ports(start_port, end_port):
    if start_port > end_port:
        start_port, end_port = end_port, start_port
    elif start_port == end_port:
        end_port += 1
    if end_port > 65535:
        end_port = 65535
    return start_port, end_port


class PortScanner:
    def __init__(self, ip_address: str):
        self.target_ip_address = ip_address
        self.open_ports = []

    def UDP_Scan_Wrap(self, start_port=1, end_port=65535):
        start_port, end_port = check_ports(start_port, end_port)
        self.open_ports = []
        self.counter = 0
        li = divide_ports(start_port, end_port)
        threads = []
        for i in range(len(li)):
            t = Thread(target=self.UDP_Scan, args=(li[i],))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return sorted(self.open_ports)

    def UDP_Scan(self, ports: Tuple):
        for port in range(ports[0], ports[1] + 1):
            response = sr1(IP(dst=self.target_ip_address) / UDP(dport=port), timeout=10, verbose=0)
            if response and response.haslayer(UDP):
                self.open_ports.append(port)
            self.counter += 1
            if self.counter % 655 == 0:
                print(f"{self.counter / 65536:.2%} done")

    def SYN_Scan_Wrap(self, start_port=1, end_port=65535):
        start_port, end_port = check_ports(start_port, end_port)
        self.open_ports = []
        self.counter = 0
        threads = []
        li = divide_ports(start_port, end_port)  # For example [(1, 2000), (2001, 4000), (4001, 6000)]
        for i in range(len(li)):
            t = Thread(target=self.SYN_Scan, args=(li[i],))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return sorted(self.open_ports)

    def SYN_Scan(self, ports: Tuple):
        for port in range(ports[0], ports[1] + 1):
            try:
                packet = IP(dst=self.target_ip_address) / TCP(dport=port, flags='S')
                response = sr1(packet, timeout=0.5, verbose=0)
                if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    self.open_ports.append(port)
                self.counter += 1
                if self.counter % 655 == 0:
                    print(f"{self.counter / 65536:.2%} done")
            except Exception:
                continue

    def Stealth_Scan_Wrap(self, start_port=1, end_port=65535):
        self.open_ports = []
        start_port, end_port = check_ports(start_port, end_port)
        self.counter = 0
        li = divide_ports(start_port, end_port)
        threads = []
        for i in range(len(li)):
            t = Thread(target=self.Stealth_Scan, args=(li[i],))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return sorted(self.open_ports)

    def Stealth_Scan(self, ports: Tuple):
        for port in range(ports[0], ports[1] + 1):
            response = sr1(IP(dst=self.target_ip_address) / TCP(sport=port, dport=port, flags='S'), timeout=5,
                           verbose=0)
            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    sr(IP(dst=self.target_ip_address) / TCP(sport=port, dport=port, flags='R'), timeout=5, verbose=0)
                    self.open_ports.append(port)
            self.counter += 1
            if self.counter % 655 == 0:
                print(f"{self.counter / 65536:.2%} done")


def main():
    port_scanner = PortScanner('10.0.0.18')
    start_time = time.perf_counter()
    print(port_scanner.Stealth_Scan_Wrap())
    print("results:", port_scanner.SYN_Scan_Wrap())
    end_time = time.perf_counter()
    print(f"Time took to scan: {end_time - start_time}")


if __name__ == '__main__':
    main()
