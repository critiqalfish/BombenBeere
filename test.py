import os
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import hashlib
import pickle
from termcolor import colored
import re
from getpass import getpass

def encrypt(key, source, encode=True):

    # this function was made by @zwer on stack overflow

    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)

    return base64.b64encode(data).decode("utf-8") if encode else data

def decrypt(key, source, decode=True):

    # this function was made by @zwer on stack overflow

    if decode:
        source = base64.b64decode(source.encode("utf-8"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")

    return data[:-padding]

input_password_name = 'a'
input_username_or_email = 'b'
input_password = 'c'
credentials = f'{input_password_name}[:::]{input_username_or_email}[:::]{input_password}'

encoded = encrypt('key'.encode('utf-8'), credentials.encode('utf-8'))
print(encoded)

decoded = decrypt('key'.encode('utf-8'), encoded)
print(decoded.decode('utf-8').split('[:::]'))