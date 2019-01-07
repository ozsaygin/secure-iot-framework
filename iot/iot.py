
import socket
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto import Random
from threading import Thread
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import uic

from hash_chain import hash_chain

HOST = "127.0.0.1"
PORT = 12345
MAX_BUFFER_SIZE = 4096
iot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connected = False
listening = False


def package_message(message) -> str: 
    '''
    param: message 
    '''
    digest =  HMAC.new(message.encode())
    message = message + str(digest.hexdigest())
    res = message.encode('utf8')
    return res

def start():
    try:
        iot.connect((HOST, PORT))
        connected = True
        message = 'AUTHENTICATION_REQUEST '
        res = package_message(message)
        iot.sendall(res)
        connected = True
        Thread(target=receive).start()

    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print(msg)
        sys.exit()


def receive():
        try:
            while True:
                buffer = iot.recv(MAX_BUFFER_SIZE).decode('utf8')
                print(buffer)
                message = buffer[:-32]
                digest = buffer[len(buffer)-32:]
                if HMAC.new(message.encode()).hexdigest() == digest: # a valid digest
                    command = message.split()[0] # e.g: 'CHALLENGE'
                    if (len(message.split()) > 1):
                        args = message.split()[1:]
                    if command == 'CHALLENGE':
                        # keygen
                        nonce = args[0]      
                        password = input('Please enter your password: ')
                        h = SHA256.new()
                        h.update(password.encode())
                        hashed_password = h.hexdigest()
                        key = hashed_password[:16]

                        # encryption
                        iv = Random.new().read(AES.block_size)
                        cipher = AES.new(self.key.encode(), AES.MODE_CBC, iv)
                        encrypted_message = cipher.encrypt(Padding.pad(self.nonce.encode(),128))
                        encrypted_message = iv + ' ' + encrypted_message
                        message = 'CHALLENGE_RESPONSE ' + str(encrypted_message)
                        res = package_message(message)
                        iot.sendall(res)
        except:
            import traceback
            traceback.print_exc()


start()
