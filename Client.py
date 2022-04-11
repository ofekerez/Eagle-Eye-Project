import socket
from threading import Thread


class Client(Thread):
    def __init__(self, port: int):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def get_ip_address(self):
        return self.socket.gethostbyname(socket.gethostname())

    def connect(self):
        self.socket.connect()

    def run(self):
        msg = self.socket.recv(1024).decode()
        if msg == 'SNF_SRT':
            import bin.PACKET_SNIFFER as snf
            sorted_packets = snf.gen_sniff()
            st = snf.filter_HTTP(sorted_packets[0]) + snf.filter_ICMP(sorted_packets[1]) + snf.filter_SMB(
                sorted_packets[2])
            st += snf.filter_FTP(sorted_packets[3]) + snf.filter_SSH(sorted_packets[4]) + snf.filterstringDNS(
                sorted_packets[5]) + snf.filter_DHCP(sorted_packets[6])
            self.socket.send('SNF_RES'.encode('ISO-8859-1', errors='ignore'))
            self.socket.send(st.encode('ISO-8859-1', errors='ignore'))
        elif msg == 'SYN_ACT':
            from bin.New_Port_Scanner import PortScanner
            open_ports = PortScanner(self.ip_address).SYN_Scan_Wrap()
            st = ''
            for open_port in open_ports:
                st += f"Port {open_port} is open!" + '\n'
            self.socket.send(st.encode('ISO-8859-1', errors='ignore'))



def main():
    client = Client()