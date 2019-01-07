# -*- coding: utf-8 -*-

import socket
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto import Random
from threading import Thread

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5 import uic

from hash_chain import hash_chain

qtCreatorFile = "mainwindow.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

MAX_BUFFER_SIZE = 4096

def integrity_check(message, hmac):
    digest = HMAC.new(message).hexdigest()
    if digest.encode('utf-8') == hmac:
        return True
    else:
        return False

def package_message(message): 
    digest =  HMAC.new(message)
    message = message + digest.hexdigest().encode()
    return message


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

        # Configuration
        self.enterButton.setDisabled(True)

        # Buttons
        self.connectButton.clicked.connect(self.connect_server)
        self.disconnectButton.clicked.connect(self.disconnect_server)
        self.enterButton.clicked.connect(self.enter_password)

    # Action Buttons
    def close_event(self, event):
        '''

        '''
        reply = QtWidgets.QMessageBox.question(self, 'Message', 'Are you sure to quit?', QtWidgets.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore


    def log(self, message):
        self.eventLogTextEdit.append(message)

    def connect_server(self):
        self.connectButton.setDisabled(True) # disable connect button

        self.server_address = self.serverAddressLineEdit.text()
        self.server_port = int(self.portNumberLineEdit.text())
        self.client.connect((self.server_address, self.server_port))
        self.connected = True

        self.log('Client is connecting to gateway (' + self.server_address + ':' + str(self.server_port) +  ')...')
        print('Client is connecting to gateway(%s:%d)' % (self.server_address, self.server_port))
        
        message = b'AR'
        self.log('Message sent for authentication: ' + str(message))
        print('Message sent for authentication: %s' % str(message))
        res = package_message(message)
        self.client.sendall(res)
        
        Thread(target = self.receive, args=()).start()

    def enter_password(self):
        password = self.passwordLineEdit.text().encode()
        self.log('Client password: ' + str(password))
        h = SHA256.new()
        h.update(password)
        hashed_password = h.hexdigest()
       
        self.key = hashed_password[:16]
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(Padding.pad(self.nonce,128))

        self.log('Hash of password: ' + hashed_password)
        self.log('Key: ' + self.key)
        self.log('Nonce: ' + str(self.nonce))

        message = b'CR' + iv + encrypted_message
        res = package_message(message)
        self.client.sendall(res)
        
        self.enterButton.setDisabled(True)
        self.passwordLineEdit.setDisabled(True)
        
        # buffer = self.client.recv(MAX_BUFFER_SIZE).decode('utf8')
        # message = buffer[:-32]
        # digest = buffer[len(buffer)-32:]

        # seeds are 128 bits   
        # first 16 bits seed1, second 16 bits seed2

    def disconnect_server(self):
        message = 'DISCONNECT'
        res = package.message(message)
        self.client.sendall(res)
        self.client.close() 
        self.connectButton.setEnabled(True)
        self.disconnectButton.setDisabled(True)

    def get_ip():
        from requests import get
        ip = get('https://api.ipify.org').text
        return ip

    def check_integrity(message: str, hmac: str) -> bool:
        '''
        :return 
        :param
        :param 
        '''
        digest = HMAC.new(message.encode())
        return(digest == hmac)

    def receive(self):
        try:
            while self.connected:
                buffer = self.client.recv(MAX_BUFFER_SIZE)
                message = buffer[:-32]
                print('Message received: %s' % message)
                digest = buffer[len(buffer)-32:]
                state = buffer[:2]
                if integrity_check(message, digest): # a valid digest
                    if state == b'CR':
                        self.nonce = message[2:]     
                        print('Please enter your password and press Enter button')
                        self.enterButton.setEnabled(True)

                    elif state == b'GH': # e.g 'GH iv as68d56 iv af5fdb'
                        iv = args[0]
                        encrypted_seeds = args[1]
                        cipher = AES.new(self.key.encode(), AES.MODE_CBC, iv)
                        decrypted_message = Padding.pad(cipher.decrypt(self.key.encode()), 128)
                        seeds = decrypted_message.split()
                        self.hc = hash_chain(100, seeds[0], seeds[1])
        except:
            import traceback
            traceback.print_exc()
