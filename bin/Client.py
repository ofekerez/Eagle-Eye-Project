import socket
import time
from threading import Thread


class Client(Thread):
    def __init__(self, IP: str, Port: int):
        self.conn = socket.socket()
        self.target_IP = IP
        self.Port = Port
        print(f"Trying to connect to {self.target_IP} in port {self.Port}")
        self.counter = 0
        while True:
            if self.counter == 10:
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                exit()
            else:
                try:
                    self.conn.connect((IP, Port))
                    break
                except Exception:
                    time.sleep(2)
                    self.counter += 1
                    continue

    def activate_sniff(self):
        try:
            self.conn.send('7'.encode())  # length of SNF_SRT
            time.sleep(4)
            self.conn.send('SNF_SRT'.encode())
            length = self.conn.recv(1024).decode()
            while not length:
                length = self.conn.recv(1024).decode()
            time.sleep(0.1)
            results = self.conn.recv(int(length)).decode('ISO-8859-1', errors='ignore')
            path = time.asctime()[4:8] + time.asctime()[8:10] + "" + time.asctime()[
                                                                      20:] + "" + time.asctime()[
                                                                                   11:19].replace(
                ':', '')
            f = open(path+'.txt', 'wb')
            while True:
                bits = self.conn.recv(1024)
                if bits.endswith('DONE'.encode('ISO-8859-1', errors='ignore')):
                    f.write(bits[:-4])
                    f.close()
                    print('[+] Transfer completed')
                    break
                if 'File not found'.encode('ISO-8859-1', errors='ignore') in bits:
                    print("[-] File not found")
                    break
                f.write(bits)
            time.sleep(2)
            self.conn.send('4'.encode())
            time.sleep(4)
            self.conn.send('EXIT'.encode())
            return path, results
        except (ConnectionResetError, ConnectionAbortedError):
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.__init__(self.target_IP, self.Port)
            self.activate_sniff()

    def activate_SYN(self) -> str:
        try:
            self.conn.send('7'.encode())
            time.sleep(4)
            self.conn.send('SYN_SRT'.encode())
            length = self.conn.recv(1024).decode()
            results = self.conn.recv(int(length)).decode()
            print(results)
            self.conn.send('4'.encode())
            time.sleep(4)
            self.conn.send('EXIT'.encode())
            return results
        except (ConnectionResetError, ConnectionAbortedError):
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.__init__(self.target_IP, self.Port)
            self.activate_SYN()

    def activate_UDP(self):
        try:
            self.conn.send('7'.encode())
            time.sleep(4)
            self.conn.send('UDP_SRT'.encode())
            length = self.conn.recv(1024).decode()
            results = self.conn.recv(int(length)).decode()
            self.conn.send('4'.encode())
            time.sleep(4)
            self.conn.send('EXIT'.encode())
            return results
        except (ConnectionResetError, ConnectionAbortedError):
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.__init__(self.target_IP, self.Port)
            self.activate_UDP()

    def activate_Stealth(self):
        try:
            self.conn.send('11'.encode())  # length of STEALTH_SRT
            time.sleep(4)
            self.conn.send('STEALTH_SRT'.encode())
            length = self.conn.recv(1024).decode()
            results = self.conn.recv(int(length)).decode()
            self.conn.send('4'.encode())
            time.sleep(4)
            self.conn.send('EXIT'.encode())
            return results
        except (ConnectionResetError, ConnectionAbortedError):
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.__init__(self.target_IP, self.Port)
            self.activate_Stealth()

    def activate_reverse_shell(self):
        try:
            self.conn.send('7'.encode())
            time.sleep(4)
            self.conn.send('REV_ACT'.encode())
        except (ConnectionResetError, ConnectionAbortedError):
            self.conn.shutdown(socket.SHUT_RDWR)
            self.conn.close()
            self.__init__(self.target_IP, self.Port)
            self.activate_reverse_shell()

    def run(self) -> None:
        while True:
            time.sleep(5)




def main():
    client = Client('127.0.0.1', 16549)
    # client.activate_sniff()
    # client.activate_Stealth()
    # client.activate_SYN()
    # client.activate_UDP()


if __name__ == '__main__':
    main()
