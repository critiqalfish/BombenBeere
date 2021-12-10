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

def menu(master_key=''):

    global master_password

    if master_key != '':

        f = open('passwords/master-password/master-password.pckl', 'rb')

        if hashlib.sha3_512(master_key.encode('utf-8')).hexdigest() == pickle.load(f):

            f.close()
            pass

        else:

            print(colored('[!] ERROR: an unknown password occured', 'yellow'))
    
    elif master_key == '':

        try:

            open('passwords/master-password/master-password.pckl', 'rb').close()

        except FileNotFoundError:

            create_master_password()

        else:

            master_password = login_master_password()

    print(colored('\nwhat do you want to do?\n', 'red'))
    print(colored('[1]', 'cyan'), end=' ')
    print(colored('lookup a password', 'magenta'))
    print(colored('[2]', 'cyan'), end=' ')
    print(colored('add a password', 'magenta'))
    print(colored('[3]', 'cyan'), end=' ')
    print(colored('delete a password', 'magenta'))
    print(colored('[4]', 'cyan'), end=' ')
    print(colored('erase everything', 'magenta'))
    print(colored('[5]', 'cyan'), end=' ')
    print(colored('exit program', 'magenta'))

    while True:

        try:

            print(colored('\n[?] ', 'cyan'), end='')
            choice = int(input(colored('choose: ', 'red')))
            break

        except ValueError:

            print(colored('\n[!] ERROR: choice does not exist', 'yellow'))

    if choice == 1:

        try:
            
            show_password(master_password)

        except:

            print(colored('[!] ERROR: an unknown error occured', 'yellow'))

    if choice == 2:

        try:

            add_password(master_password)

        except:

            print(colored('[!] ERROR: an unknown error occured', 'yellow'))

    if choice == 3:

        try:

            delete_password(master_password)

        except:

            print(colored('[!] ERROR: an unknown error occured', 'yellow'))

    if choice == 4:

        erase_everything()
        print(colored('\n[!] EXITED: deleted all passwords including the master-password\n', 'yellow'))
        exit()

    if choice == 5:

        print(colored('\n[!] EXITED: by user\n', 'yellow'))
        exit()

    if choice != 1 or choice != 2 or choice != 3 or choice != 4 or choice != 5:

        print(colored('\n[!] ERROR: choice does not exist\n', 'yellow'))
        exit()

def encrypt(key, source, encode=True):

    # this function was made by @zwer on stack overflow

    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    print(IV)
    print(padding)

    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):

    # this function was made by @zwer on stack overflow

    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")

    return data[:-padding]

def login_master_password():

    print(colored('\n[!] IMPORTANT: Log in with your master-password!', 'yellow'))

    while True:
        
        input_master_password = getpass(colored('\n[?] ', 'cyan') + colored('your master-password: ', 'red'))
        hash_master_password = hashlib.sha3_512(input_master_password.encode('utf-8')).hexdigest()
        f = open('passwords/master-password/master-password.pckl', 'rb')
        saved_master_password = pickle.load(f)
        f.close()

        if hash_master_password == saved_master_password:

            break

        else:

            print(colored('\n[!] ERROR: wrong master-password', 'yellow'))
    
    return input_master_password

def create_master_password():

    print(colored('\n[!] IMPORTANT: First, please create your master-password!', 'yellow'))
    print(colored('[!] IMPORTANT: Never loose your master-password, your saved passwords won\'t be recoverable without it!', 'yellow'))
    print(colored('[!] IMPORTANT: Please choose a master-password that has at least one uppercase letter, one lowercase letter, one number, one special character and a length of 10!\n', 'yellow'))

    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{10,64}$"
    pat = re.compile(reg)

    while True:

        input_master_password = getpass(colored('[?] ', 'cyan') + colored('your new master-password: ', 'red'))
        mat = re.search(pat, input_master_password)

        if mat:

            hash_master_password = hashlib.sha3_512(input_master_password.encode('utf-8')).hexdigest()
            f = open('passwords/master-password/master-password.pckl', 'wb')
            pickle.dump(hash_master_password, f)
            f.close()
            break

        else:
        
            print(colored('\n[!] IMPORTANT: Your password looks too weak! It should follow at least these criteria:', 'yellow'))
            print(colored('[!] CRTIERIA 1: at least one lowercase letter (a-z) and one uppercase letter (A-Z)', 'yellow'))
            print(colored('[!] CRTIERIA 2: at least one number (1234567890)', 'yellow'))
            print(colored('[!] CRTIERIA 3: at least one special character (@$!%*#?&)\n', 'yellow'))

    menu()

def show_password():

    pass

def add_password():

    pass

def delete_password():

    pass

def erase_everything():

    confirm = input(colored('\n[?] ', 'cyan') + colored('do you really want to erase everything (y/n): ', 'red'))

    if confirm == 'n' or confirm == 'N' or confirm == 'no' or confirm == 'No':

        menu(master_key=master_password)
    
    if confirm == 'y' or confirm == 'Y' or confirm == 'yes' or confirm == 'Yes':

        while True:

            input_master_password = getpass(colored('\n[?] ', 'cyan') + colored('confirm with your master-password: ', 'red'))
            f = open('passwords/master-password/master-password.pckl', 'rb')

            if hashlib.sha3_512(input_master_password.encode('utf-8')).hexdigest() == pickle.load(f):

                f.close()

                try:
                    
                    mpw_dir = os.getcwd() + '\\passwords\\master-password\\master-password.pckl'
                    os.remove(mpw_dir)

                except:

                    pass

                current_dir = os.getcwd() + '\\passwords'
                
                for f in os.listdir(current_dir):

                    if not f.endswith(".pckl"):

                        continue

                    os.remove(os.path.join(current_dir, f))
            
                break

            else:

                pass
        
'''
key = b'key'

file = open('data/var.pckl', 'rb')
data = pickle.load(file)
file.close()

print('encrypted: ' + data)
print('decrypted: ' + decrypt(key, data).decode('latin-1'))
'''

if __name__ == '__main__':

    print(colored('\n--------------------\nBombenBeere.py v0.1\n--------------------', 'red', attrs=['bold']))
    menu()