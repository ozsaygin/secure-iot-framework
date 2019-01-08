
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
PORT = 11115
MAX_BUFFER_SIZE = 4096
iot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connected = False
listening = False


def package_message(message): 
    digest =  HMAC.new(message)
    message = message + digest.hexdigest().encode()
    return message


def start():
    try:
        iot.connect((HOST, PORT))
        connected = True
        message = 'AUTHENTICATION_REQUEST '
        res = package_message(message)
        iot.sendall(res)
        connected = True
        Thread(target=receive, args=()).start()

    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print(msg)
        sys.exit()


def receive():
    key = None
    hc = None

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
                if command == 'CR':
                    nonce = message[2:]     
                    password = input('Please enter your password and press Enter button')
                    h = SHA256.new()
                    h.update(password)
                    hashed_password = h.hexdigest()
                
                    key = hashed_password[:16]
                    iv = Random.new().read(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    encrypted_message = cipher.encrypt(Padding.pad(nonce,128, style='iso7816'))

                    print('Hash of password: ' + hashed_password)
                    print('Key: ' + key)
                    print('Nonce: ' + str(nonce))

                    message = b'CR' + iv + encrypted_message
                    res = package_message(message)
                    iot.sendall(res)

                elif command == 'GH':
                    iv = message[2:AES.block_size+2]
                    encrypted_seeds = message[AES.block_size+2:]
                    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
                    decrypted_seeds = Padding.pad(cipher.decrypt(encrypted_seeds), 128, style='iso7816')
                    seed1 = decrypted_seed[:16]
                    seed2 = decrypted_seed[16:]
                    print('seed 1: ' + str(seed1))
                    print('seed 2: ' + str(seed2))
                    hc = hash_chain(100, seed1, seed2)
                    print('Hash chains are generated succesfully...')

                
                
    except:
        import traceback
        traceback.print_exc()


start()
