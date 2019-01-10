# -*- coding: utf-8 -*-

import socket
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto import Random
from threading import Thread
from symmetric_cyphr import symmtrc_cypr

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import uic

from hash_chain import hash_chain


qtCreatorFile = "mainwindow.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

MAX_BUFFER_SIZE = 4096


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

def integrity_check(key, message):
    if isinstance(key, str):
        key = key.encode()
    h = SHA256.new()
    h.update(key)
    hashed_password = h.hexdigest()
    key = hashed_password[:16].encode()
    hmac = message[len(message)-32:]
    message = message[:-32]
    digest = HMAC.new(key, message).hexdigest()
    if digest.encode('utf-8') == hmac:
        return True
    else:
        return False


class App(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)

        # Global variables
        self.server_address = '127.0.0.1'
        self.server_port = 9999
        self.connected = False
        self.terminating = False
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.key = None
        self.nonce = None
        self.gateway_key = None
        self.sc = None
        self.password = None
        self.connected_iots = list()

        # Configuration
        self.enterButton.setDisabled(True)

        # Buttons
        self.connectButton.clicked.connect(self.connect_server)
        self.disconnectButton.clicked.connect(self.disconnect_server)
        self.enterButton.clicked.connect(self.enter_password)
        self.requestButton.clicked.connect(self.request_iot)

    # Action Buttons
    def close_event(self, event):
        reply = QtWidgets.QMessageBox.question(self, 'Message', 'Are you sure to quit?', QtWidgets.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore

    def log(self, message):
        self.eventLogTextEdit.append(message)

    def request_iot():
        iotid = self.iotLineEdit
        self.connect_iots.append(iotid)
        enc = self.sc.encrypt(iotid)
        msg = b'UR' + enc
        msg = package_message(self.sc.getKey(), msg) 
        client.sendall(msg)

    def connect_server(self):
        self.connectButton.setDisabled(True) # disable connect button

        # self.server_address = self.serverAddressLineEdit.text()
        # self.server_port = int(self.portNumberLineEdit.text())

        self.server_address = '127.0.0.1'
        self.server_port = 11114

        self.client.connect((self.server_address, self.server_port))
        self.connected = True

        self.log('Client is connecting to gateway (' + self.server_address + ':' + str(self.server_port) +  ')...')
        print('Client is connecting to gateway(%s:%d)' % (self.server_address, self.server_port))
        
        res = b'AR'
        self.log('Message sent for authentication: ' + str(res))
        print('Message sent for authentication: %s' % str(res))
        self.client.sendall(res)
        
        Thread(target = self.receive, args=()).start()

    def enter_password(self):
        self.password = self.passwordLineEdit.text()
        self.log('Client\'s password: ' + str(self.password))
   
        encrypted_message = encryptAES(self.nonce, self.password)

        self.log('Nonce: ' + str(self.nonce))

        res = b'CR' + encrypted_message
        self.client.sendall(res)
        
        self.enterButton.setDisabled(True)
        self.passwordLineEdit.setDisabled(True)
        

    def disconnect_server(self):
        message = 'DISCONNECT'
        res = package.message(message)
        self.client.sendall(res)
        self.client.close() 
        self.connectButton.setEnabled(True)
        self.disconnectButton.setDisabled(True)

    def receive(self):
        try:
            while self.connected:
                buffer = self.client.recv(MAX_BUFFER_SIZE)
                if len(buffer) > 0:
                    print('Message received: %s' % buffer)
                
                state = buffer[:2]

                if state == b'CR': # CHALLENGE RESPONSE
                    self.nonce = buffer[2:]     
                    print('Please enter your password and hit Enter')
                    self.enterButton.setEnabled(True)

                elif state == b'GH': # GENERATE HASHCHAINS e.g 'GH iv as68d56 iv af5fdb'
                    message = buffer[2:]
                    seeds = decryptAES(self.password, message)
                    self.sc = symmtrc_cypr(seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                    print('Hash chains are generated succesfully...')
                    print('Please enter a valid iot device ID below')

                elif state == b'AG':
                    print('Authentication granted')
                    
                elif state == b'AF':
                    self.enterButton.setEnabled(True)
                    self.passwordTextEdit.setEnabled(True)
                    self.log('Password is wrong or your ip is not registered. Try to re-enter your password...')
                
                elif state == b'NA':
                    self.enterButton.setEnabled(True)
                    self.passwordTextEdit.setEnabled(True)
                    self.log('Authentication time out..')
                    self.log('Enter your password to authenticate again')





                    

        except:
            import traceback
            traceback.print_exc()
