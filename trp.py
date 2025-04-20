#! /usr/bin/env python3

# TODO
# add support for encrypted TCP dest (wtf why is this working, need to run some tests)
# limit bandwidth
# handle SIGTERM
# fix (? is this still a problem ?): socket close happens super late
# add support for server that is encrypted

import argparse
from socket import socket, SOL_SOCKET, SO_REUSEADDR, SHUT_RDWR
from threading import Thread, Lock
from pathlib import Path
import shutil
import select
import ssl
import sys

RECV_LEN = 1024 * 1 # 1KiB

FOLDER_IP_TRANSLATIONS = Path(__file__).parent / 'ip-translations'
FILE_NEXT_FAKE_IP = FOLDER_IP_TRANSLATIONS / 'next-available'

FIRST_FAKE_IP = '127.0.0.2'
EMERGENCY_FAKE_IP = '127.0.0.1'

def run_from_cmdline():
    parser = argparse.ArgumentParser('TCP reverse proxy')

    parser.add_argument('bind_host', type=str, help='host to bind to; leave empty for all')
    parser.add_argument('bind_port', type=int, help='port to bind to')

    # parser.add_argument('server_host', type=str, help='host of server') # host HAS TO BE localhost, otherwise the 127.x.x.x trick will not work
    parser.add_argument('server_port',        type=int,                      help='port of server')
    parser.add_argument('--server-encrypted',           action='store_true', help='weather server uses plain or encrypted TCP')

    parser.add_argument('--encrypt',            action='store_true', help='weather to encrypt the connection between the client and the reverse proxy')
    parser.add_argument('--keyfile',  type=str,                      help='keyfile to use for encryption, example: privkey.pem')
    parser.add_argument('--certfile', type=str,                      help='certfile to use for encryption, example: cert.pem')

    args = parser.parse_args()

    if args.encrypt:
        if (args.keyfile is None) or (args.certfile is None):
            print(f'if you want encryption you need to specify both keyfile and certfile')
            sys.exit(1)

    main(
        (args.bind_host, args.bind_port),
        args.server_port, args.server_encrypted,
        args.encrypt, args.keyfile, args.certfile)

def main(
        bind_addr,
        server_port:int, server_encrypted:bool,
        encrypt:bool, keyfile:str|None, certfile:str|None
    ):

    shutil.rmtree(FOLDER_IP_TRANSLATIONS, ignore_errors=True)

    FOLDER_IP_TRANSLATIONS.mkdir()
    FILE_NEXT_FAKE_IP.write_text(FIRST_FAKE_IP)

    fake_ip_lock = Lock()

    sock = socket()

    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    if encrypt:
        # ssl_context = ssl.create_default_context()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) # Auto-negotiate the highest protocol version that both the client and server support, and configure the context server-side connections.

        ssl_context.load_cert_chain(
            certfile=certfile, # cert.pem / certificate.crt
            keyfile=keyfile, # privkey.pem / private.key
        )

        sock = ssl_context.wrap_socket(
            sock,
            server_side=True,
        )

        ## this code no longer works
        # sock = ssl.wrap_socket(
        #     sock,
        #     keyfile=keyfile,
        #     certfile=certfile,
        #     server_side=True,
        # )

    sock.bind(bind_addr)

    sock.listen()

    while True:

        try:
            con, con_addr = sock.accept() # TODO we could actually try to accept a regular connection, and if that doesn't work, we could try to wrap the socket then accept again
        except ssl.SSLError as err: # not sure what causes this but I've seen it
            print(f'could not accept: ssl.SSLError: {err}')
            continue
        except Exception as err: # just in case
            print(f'could not accept: Exception: {err}')
            continue

        Thread(target=handle_client, args=(con, con_addr, server_port, server_encrypted, fake_ip_lock)).start()
    
    sock.close()

def handle_client(client, client_addr, server_port:int, server_encrypted:bool, fake_ip_lock):
    try:
        handle_client_2(client, client_addr, server_port, server_encrypted, fake_ip_lock)
    finally:
        client.shutdown(SHUT_RDWR)
        client.close()

def handle_client_2(client, client_addr, server_port:int, server_encrypted:bool, fake_ip_lock):
    client_ip, _client_port = client_addr

    print(f'{client_addr}: ---> connected')

    client_ip_faked = get_client_fake_ip(client_ip, fake_ip_lock)

    print(f'{client_addr}: -~-> selected faked ip {client_ip_faked}')

    server = socket()

    server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    if server_encrypted:
        ssl_context = ssl.create_default_context()

        server = ssl_context.wrap_socket(
            server,
            server_side=False,
        )

    server.bind((client_ip_faked, 0))

    try:
        server.connect(('localhost', server_port))
    except ConnectionRefusedError:
        print(f'{client_addr}: -~xx server refused connection')
        return

    running = True

    while running:

        read_list = [client, server]
        write_list = [] # [client, server]
        except_list = [] # [client, server]
        readable, _writeble, _errored = select.select(read_list, write_list, except_list)
        # ideally we would check if the target socket is writable

        for sock in readable:
            data = sock.recv(RECV_LEN)

            if len(data) == 0:

                target = 'client' if sock == client else 'server'
                print(f'{client_addr}: connection closed by {target}')

                running = False
                break

            if sock == client:
                print(f'{client_addr}: ~-~> send {len(data)}[B] to server')
                server.sendall(data)
                print(f'{client_addr}: ~v~> send {len(data)}[B] to server')
            else:
                print(f'{client_addr}: <~-~ recv {len(data)}[B] from server')
                client.sendall(data)
                print(f'{client_addr}: <~v~ recv {len(data)}[B] from server')

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
