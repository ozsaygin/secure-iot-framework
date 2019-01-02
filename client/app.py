# -*- coding: utf-8 -*-


import socket
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from threading import Thread

from PyQt5 import QtCore, QtGui, QtWidgets

qtCreatorFile = "mainwindow.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)

MAX_BUFFER_SIZE = 4096

class App(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.load_config()

        # Global variables
        self.server_address = '127.0.0.1'
        self.server_port = 9999
        self.connected = False
        self.terminating = False
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.password = ""

        # Buttons
        self.connectButton.clicked.connect(self.connect_server)
        self.disconnectButton.clicked.connect(self.disconnect_server)
        self.enterButton.clicked.connect()
    
        self.matplot_widget_box = QtWidgets.QVBoxLayout()
        self.button_group = QtWidgets.QButtonGroup()

    def connect_server(self):
        client.connect((self.server_address, self.server_port))
        cid = get_mac_address()
        message = 'AUTHENTICATIONREQUEST ' + cid
        
        res = package_message(message)
        self.client.sendall(res)
        self.connected = True
        Thread(target = receive, args=()).start()
    
    def disconnect_server(self):
        message = 'DISCONNECT'
        res = package.message(message)
        self.client.sendall(res)
        self.client.close() 
    
    def receive():
        connected = True
        try:
            while connected:
                buffer = client.recv(MAX_BUFFER_SIZE).decode('utf8')
                message = buffer[:-32]
                digest = buffer[len(buffer)-32:]
                if HMAC.new(message.encode).hexdigest() == digest:
                    command = message.split()[0] # e.g: 'AUTHENTICATIONREQUEST', 'CHALLENGERESPONSE'
                    if (len(message.split()) > 1):
                        args = message.split()[1:]
                    if command == 'CHALLENGE':
                        hashed_password = SHA256.new().update(password.encode()).hexdigest()
                        cipher = AES(hashed_password, AES.MODE_ECB)
                        encrypted_message = cipher.encrypt(Padding.pad(args[1].encode(), 128))
                        res = package_message(encrypted_message)
                        client.sendall(res)
                    if command == 'GENERATEHASHCHAINS':
                        # TODO: Generate hash chain by using tampered proof class
                        pass

                else: 
                    # TODO: Implement the case where checksum fails
                    pass


def package_message(message): 
    digest =  HMAC.new(message.encode())
    message = message + digest 
    res = message.encode('utf8')
    return res

def get_mac_address():
    from uuid import getnode as get_mac
    mac = get_mac()
    mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
    return mac


