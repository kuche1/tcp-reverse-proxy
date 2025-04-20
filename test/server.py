#! /usr/bin/env python3

import socket

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 6900))
s.listen()

while True:
    con, addr = s.accept()
    print(f'server: connection from: {addr}')

    while True:
        data = con.recv(1024).decode()
        try:
            con.sendall(f'got: {data}\n'.encode())
        except BrokenPipeError:
            print('BrokenPipeError')
            break

    con.close()
