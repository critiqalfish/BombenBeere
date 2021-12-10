import linustools
import hashlib

def hash(name, pw):
    salt = linustools.password.gen_password(10, False, False, False, custom=hashlib.sha3_256(name.encode('utf-8')).hexdigest())
    pw += '.' + salt
    hash = hashlib.sha3_512(pw.encode('utf-8')).hexdigest()
    return f'{name} : {salt} : {hash}'

def to_file(str):
    f = open('hashes.txt', 'a')
    f.write(str)
    f.close

to_file(hash(input('name: '), input('password: ')))