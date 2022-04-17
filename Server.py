import socket
from threading import Thread


def get_ip_address():
    return socket.gethostbyname(socket.gethostname())


class Server(Thread):
    def __init__(self, port: int):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.queue = []
        self.current_socket = None
        self.socket.bind(("0.0.0.0", self.port))
        self.socket.listen(1000)
        self.queue.append(self.socket.accept()[0])
        self.current_socket = self.queue.pop(0)
        self.handle_client()

    def Activate_Sniff(self):
        self.current_socket.send('SNF_SRT'.encode('ISO-8859-1', errors='ignore'))

    def handle_client(self):
        while True:
            data = self.current_socket.recv(2048).decode()
            if data.lower() == 'exit':
                self.current_socket.close()
                if self.queue:
                    self.current_socket = self.queue.pop(0)
                else:
                    self.queue.append(self.socket.accept()[0])
                    self.current_socket = self.queue.pop(0)
                break
            elif data == 'SNF_RES':
                length = int(self.current_socket.recv(1024).decode())
                results = self.current_socket.recv(length).decode('ISO-8859-1', errors='ignore')
                print(results)
            elif data == 'SCAN_RES':
                length = int(self.current_socket.recv(1024).decode())
                results = self.current_socket.recv(length).decode('ISO-8859-1', errors='ignore')
                print(results)

    def Activate_SYN_Scan(self):
        self.current_socket.send('SYN_ACT'.encode('ISO-8859-1', errors='ignore'))

    def Activate_Stealth_Scan(self):
        self.current_socket.send('Stealth_ACT'.encode('ISO-8859-1', errors='ignore'))

    def Activate_UDP_Scan(self):
        self.current_socket.send('UDP_ACT'.encode('ISO-8859-1', errors='ignore'))


def main():
    server = Server(8200)
    server.Activate_Sniff()


if __name__ == '__main__':
    main()
