
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

password = None
sc = None

def decryptAES(key, mess):
    iv = mess[:AES.block_size]
    encs =  mess[AES.block_size:]
    h = SHA256.new()
    h.update(key.encode())
    hashed_password = h.hexdigest()
    key = hashed_password[:16]
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    return Padding.unpad(cipher.decrypt(encs), 128, style='iso7816')

def encryptAES(mess, key):
    h = SHA256.new()
    print(key)
    h.update(key.encode())
    hashed_password = h.hexdigest()
    key = hashed_password[:16].encode()
    raw = Padding.pad(mess, 128, style='iso7816')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)

def package_message(key, message):
    if isinstance(key, str):
        key = key.encode()
    h = SHA256.new()
    h.update(key)
    hashed_password = h.hexdigest()
    key = hashed_password[:16].encode() 
    digest =  HMAC.new(key, message)
    message = message + digest.hexdigest().encode()
    return message


def start():
    try:
        iot.connect((HOST, PORT))
        global connected = True
        res = b'AR'
        iot.sendall(res)
        Thread(target=receive, args=()).start()

    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print(msg)
        sys.exit()


def receive():
    key = None
    hc = None

    try:
        while connected:
            buffer = iot.recv(MAX_BUFFER_SIZE).decode('utf8')
            if len(buffer) > 0:
                print('Message received: %s' % buffer)

            state = buffer[:2]

            if state == b'CR': # CHALLENGE RESPONSE
                nonce = buffer[2:]     
                global password = input('Please enter your password and hit Enter')
                print('Client\'s password: ' + str(password))
   
                encrypted_message = encryptAES(nonce, password)

                print('Nonce: ' + str(nonce))

                res = b'CR' + encrypted_message
                iot.sendall(res)

            elif command == b'GH':
                message = buffer[2:]
                    seeds = decryptAES(password, message)
                    global sc = symmtrc_cypr(seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                    print('Hash chains are generated succesfully...')

            elif state == b'AF':
                global password = input('Password is wrong or your ip is not registered. Please re-enter your password: ')
                encrypted_message = encryptAES(nonce, password)
                print('Nonce: ' + str(nonce))
                res = b'CR' + encrypted_message
                iot.sendall(res)

                    

                
                
    except:
        import traceback
        traceback.print_exc()


start()
