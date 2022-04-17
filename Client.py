import socket
from threading import Thread
import random
import time


def get_ip_address():
    return socket.gethostbyname(socket.gethostname())


class Client(Thread):
    def __init__(self, ip_address: str, port: int):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.client_socket.connect((ip_address, port))
                print("Connected")
                break
            except Exception:
                sleep_for = random.randrange(1, 10)
                time.sleep(sleep_for)
                continue
        self.run()

    def run(self):
        while True:
            self.client_socket.send('1'.encode())
            msg = self.client_socket.recv(2048).decode()
            print(msg)
            if msg == 'EXIT':
                break
            elif msg == 'GET_IP':
                self.client_socket.send(get_ip_address().encode())
            elif msg == 'SNF_SRT':
                import bin.PACKET_SNIFFER as snf
                sorted_packets = snf.gen_sniff()
                st = ''
                st += snf.filter_HTTP(sorted_packets[0]) + snf.filter_ICMP(sorted_packets[1]) + snf.filter_SMB(
                    sorted_packets[2])
                st += snf.filter_FTP(sorted_packets[3]) + snf.filter_SSH(sorted_packets[4]) + snf.filterstringDNS(
                    sorted_packets[5]) + snf.filter_DHCP(sorted_packets[6])
                self.client_socket.send(str(len(st)).encode())
                self.client_socket.send(st.encode('ISO-8859-1', errors='ignore'))
            elif msg == 'SYN_ACT':
                from bin.New_Port_Scanner import PortScanner
                open_ports = PortScanner().SYN_Scan_Wrap()
                st = ''
                for open_port in open_ports:
                    st += f"Port {open_port} is open!" + '\n'
                self.client_socket.send('SCAN_RES'.encode())
                self.client_socket.send(str(len(st)).encode())
                self.client_socket.send(st.encode('ISO-8859-1', errors='ignore'))
            elif msg == 'Stealth_ACT':
                from bin.New_Port_Scanner import PortScanner
                open_ports = PortScanner().Stealth_Scan_Wrap()
                st = ''
                for open_port in open_ports:
                    st += f"Port {open_port} is open!" + '\n'
                self.client_socket.send('SCAN_RES'.encode())
                self.client_socket.send(str(len(st)).encode())
                self.client_socket.send(st.encode('ISO-8859-1', errors='ignore'))
            elif msg == 'UDP_ACT':
                from bin.New_Port_Scanner import PortScanner
                open_ports = PortScanner().UDP_Scan_Wrap()
                st = ''
                for open_port in open_ports:
                    st += f"Port {open_port} is open!" + '\n'
                self.client_socket.send('SCAN_RES'.encode())
                self.client_socket.send(str(len(st)).encode())
                self.client_socket.send(st.encode('ISO-8859-1', errors='ignore'))


def main():
    Client("10.0.0.19", 8200)


if __name__ == '__main__':
    main()
