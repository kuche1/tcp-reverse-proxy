#! /usr/bin/env python3

# TODO
# add support for encrypted TCP dest
# limit bandwidth
# handle SIGTERM
# clean the ips on startup

import argparse
from socket import socket, SOL_SOCKET, SO_REUSEADDR, SHUT_RDWR, MSG_DONTWAIT
from threading import Thread, Lock
import time
from pathlib import Path
import shutil

RECV_LEN = 1024 # bytes
LOOP_SLEEP = 0 # even a sleep of "0" seconds is enough to reduce the CPU usage from 8% to 0.6%

FOLDER_IP_TRANSLATIONS = Path(__file__).parent / 'ip-translations'
FILE_NEXT_FAKE_IP = FOLDER_IP_TRANSLATIONS / 'next-available'

FIRST_FAKE_IP = '127.0.0.2'
EMERGENCY_FAKE_IP = '127.0.0.1'

def run_from_cmdline():
    parser = argparse.ArgumentParser('TCP reverse proxy')

    parser.add_argument('bind_host', type=str, help='host to bind to; leave empty for all')
    parser.add_argument('bind_port', type=int, help='port to bind to')

    # parser.add_argument('server_host', type=str, help='host of server') # host HAS TO BE localhost
    parser.add_argument('server_port', type=int, help='port of server')

    args = parser.parse_args()
    main((args.bind_host, args.bind_port), args.server_port)

def main(bind_addr, server_port):
    shutil.rmtree(FOLDER_IP_TRANSLATIONS, ignore_errors=True)

    FOLDER_IP_TRANSLATIONS.mkdir()
    FILE_NEXT_FAKE_IP.write_text(FIRST_FAKE_IP)

    fake_ip_lock = Lock()

    sock = socket()
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.bind(bind_addr)
    sock.listen()

    while True:
        con, con_addr = sock.accept()
        Thread(target=handle_client, args=(con, con_addr, server_port, fake_ip_lock)).start()
    
    sock.close()

def handle_client(client, client_addr, server_port, fake_ip_lock):
    client_ip, _client_port = client_addr

    print(f'{client_addr}: ---> connect')

    client_ip_faked = get_client_fake_ip(client_ip, fake_ip_lock)

    print(f'{client_addr}: -~-> faked ip {client_ip_faked}')

    server = socket()
    server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server.bind((client_ip_faked, 0))
    server.connect(('localhost', server_port))

    while True:

        try:
            data = client.recv(RECV_LEN, MSG_DONTWAIT)
        except BlockingIOError:
            pass
        else:
            if len(data) == 0: # disconnect
                break

            print(f'{client_addr}: [{len(data)} B] -~-> server')
            server.sendall(data)
            print(f'{client_addr}: [{len(data)} B] -v-> server')
        
        try:
            data = server.recv(RECV_LEN, MSG_DONTWAIT)
        except BlockingIOError:
            pass
        else:
            if len(data) == 0: # disconnect
                break

            print(f'{client_addr}: <-~- [{len(data)} B] server')
            client.sendall(data)
            print(f'{client_addr}: <-v- [{len(data)} B] server')

        time.sleep(LOOP_SLEEP)

    client.shutdown(SHUT_RDWR)
    client.close()

    server.shutdown(SHUT_RDWR)
    server.close()

    print(f'{client_addr}: -x-> disconnect')

def get_client_fake_ip(client_ip, lock):
    file_client = FOLDER_IP_TRANSLATIONS / client_ip

    if file_client.exists():

        return file_client.read_text()

    else:

        lock.acquire()

        try:
            
            current_fake_ip = FILE_NEXT_FAKE_IP.read_text()

            if current_fake_ip == EMERGENCY_FAKE_IP:
                # don't calc next fake ip
                return current_fake_ip

            a, b, c, d = current_fake_ip.split('.')
            a = int(a)
            b = int(b)
            c = int(c)
            d = int(d)

            d += 1
            if d > 255:
                d = 0

                c += 1
                if c > 255:
                    c = 0

                    b += 1
                    if b > 255:
                        b = 0

                        a += 1

            if a > 127:
                print(f'WARNING: out of IPs, setting emergency ip for next: {EMERGENCY_FAKE_IP}')
                next_fake_ip = EMERGENCY_FAKE_IP
            else:
                next_fake_ip = f'{a}.{b}.{c}.{d}'
                        
            FILE_NEXT_FAKE_IP.write_text(next_fake_ip)

            file_client.write_text(current_fake_ip)

            return current_fake_ip

        finally:

            lock.release()

def get_next_fake_ip(lock):
    lock.acquire()

    try:
        
        current_ip = FILE_NEXT_FAKE_IP.read_text()

        a, b, c, d = current_ip.split('.')
        a = int(a)
        b = int(b)
        c = int(c)
        d = int(d)

        d += 1
        if d > 255:
            d = 0

            c += 1
            if c > 255:
                c = 0

                b += 1
                if b > 255:
                    b = 0

                    a += 1

        if a > 127:
            print(f'WARNING: out of IPs, setting emergency ip for next: {EMERGENCY_FAKE_IP}')
            next_ip = EMERGENCY_FAKE_IP
        else:
            next_ip = f'{a}.{b}.{c}.{d}'
                    
        FILE_NEXT_FAKE_IP.write_text(next_ip)
        
        return current_ip

    finally:

        lock.release()

if __name__ == '__main__':
    run_from_cmdline()
