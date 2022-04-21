import socket
from threading import Thread

import bin.PACKET_SNIFFER as snf
from PortScanner import PortScanner


def get_ip_address():
    return socket.gethostbyname(socket.gethostname())


class Server(Thread):
    def __init__(self):
        self.conn = socket.socket()
        print(get_ip_address())
        self.conn.bind(('10.0.0.18', 16549))
        self.conn.listen(1)
        print('[+] Listening for income TCP connection on port 8080')
        self.conn, addr = self.conn.accept()
        print('[+]We got a connection from', addr)
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
            elif msg == 'EXIT':
                self.__init__()


def main():
    server = Server()


if __name__ == '__main__':
    main()
