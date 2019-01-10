
import socket
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto import Random
from threading import Thread
import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import uic

from symmetric_cyphr import symmtrc_cypr

from hash_chain import hash_chain


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

 def get_mac():
        from uuid import getnode as get_mac
        mac = get_mac()
        mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        return mac

def start():
    try:
        GATEWAY_IP = input('Please enter server\'s ip address: ')
        PORT = input('Please enter server\'s port: ')
        iot.connect((GATEWAY_IP, PORT))
        res = b'AR' + get_mac().encode()
        iot.sendall(res)
        Thread(target=receive, args=()).start()

    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()) + msg)
        sys.exit()


def receive():
    key = None
    sc = None
    password = None
    connected = True

    try:
        while connected:
            buffer = iot.recv(MAX_BUFFER_SIZE)
            if len(buffer) > 0:
                print('Message received: %s' % buffer)

            state = buffer[:2]

            if state == b'CR': # CHALLENGE RESPONSE
                nonce = buffer[2:]     
                password = input('Please enter your password and hit Enter: ')
                print('Client\'s password: ' + str(password))
                encrypted_message = encryptAES(nonce, password)
                print('Nonce: ' + str(nonce))
                res = b'CR' + encrypted_message
                iot.sendall(res)
                print('Message sent: ' + res)

            elif state == b'GH':
                message = buffer[2:]
                seeds = decryptAES(password, message)
                print('Hash chains are generated succesfully...')
                sc = symmtrc_cypr(seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                print('-------')
                sc.reKey()

            elif state == b'AF':
                password = input('Password is wrong or your ip is not registered. Please re-enter your password: ')
                encrypted_message = encryptAES(nonce, password)
                print('Nonce: ' + str(nonce))
                res = b'CR' + encrypted_message
                iot.sendall(res)
            
            elif state == b'AN':
                print('Authentication time out..')
                res = b'AR'+ get_mac().encode()
                self.client.sendall(res)

            elif state == b'WP':
                print('Password is wrong or your ip is not registered.') 
                password = input('Enter your password: ')
                print('IOT\'s password: ' + str(password))
                encrypted_message = encryptAES(nonce, password)
                print('Nonce: ' + str(nonce))
                res = b'CR' + encrypted_message
                iot.sendall(res)

    except:
        import traceback
        traceback.print_exc()


start()
