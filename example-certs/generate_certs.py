#! /usr/bin/env python3

from OpenSSL import crypto, SSL # sudo pacman -S python-pyopenssl # python3 -m pip install pyopenssl
import requests
from time import gmtime, mktime

CERT_FILE = "certificate.crt"
KEY_FILE = "private.key"
SIZE = 2048

def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, SIZE)

    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "a Dummy Company Ltd 4"
    cert.get_subject().OU = "a Dummy Company Ltd 4"
    cert.get_subject().CN = requests.get('https://api.ipify.org').content.decode('utf8') # socket.gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    
    dumped_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    f = open(CERT_FILE, "wb")
    f.write(dumped_cert)
    f.close()
    
    dumped_private = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    f= open(KEY_FILE, "wb")
    f.write(dumped_private)
    f.close()

create_self_signed_cert()
