#! /usr/bin/env python3

import socket
import time

s = socket.socket()
s.connect(('localhost', 6901))

time.sleep(1)
s.sendall(b'hiiiii')

time.sleep(1)
data = s.recv(1024)
print(f'got: {data}')

s.close()
