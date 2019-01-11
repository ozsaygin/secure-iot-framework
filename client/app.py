# -*- coding: utf-8 -*-

import sys
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
    encs = mess[AES.block_size:]
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
    digest = HMAC.new(key, message)
    message = message + digest.hexdigest().encode()
    return message

def get_mac():
        from uuid import getnode as get_mac
        mac = get_mac()
        mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
        return mac

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
        self.client = None
        self.key = None
        self.nonce = None
        self.gateway_key = None
        self.sc = None
        self.password = None
        self.connected_iots = list()
        self.MAX_BUFFER_SIZE = 4096

        # Configuration
        self.enterButton.setDisabled(True)
        self.requestButton.setDisabled(True)
        self.disconnectButton.setDisabled(True)
        # Buttons
        self.connectButton.clicked.connect(self.connect_server)
        self.disconnectButton.clicked.connect(self.disconnect_server)
        self.enterButton.clicked.connect(self.enter_password)
        self.requestButton.clicked.connect(self.request_iot)
        

    # Action Buttons
    def close_event(self, event):
        reply = QtWidgets.QMessageBox.question(
            self, 'Message', 'Are you sure to quit?', QtWidgets.QMessageBox.Yes, QtGui.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

    def log(self, message):
        self.eventLogTextEdit.append(message)

    def request_iot(self):
        iotid = self.iotLineEdit.text()
        self.connected_iots.append(iotid)
        enc = self.sc.encrypt(iotid.encode())
        msg = b'UR' + enc
        msg = package_message(self.sc.getKey(), msg)
        self.client.sendall(msg)

    def connect_server(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connectButton.setDisabled(True)  # disable connect button

        self.server_address = self.serverAddressLineEdit.text()
        self.server_port = int(self.portNumberLineEdit.text())

        try:
            self.client.connect((self.server_address, self.server_port))
            self.connected = True

            self.log('Client is connecting to gateway (' +
                    self.server_address + ':' + str(self.server_port) + ')...')
            print('Client is connecting to gateway(%s:%d)' %
                (self.server_address, self.server_port))

            res = b'AR' + get_mac().encode()
            self.client.sendall(res)

            self.log('Message sent for authentication: ' + str(res))
            print('Message sent for authentication: %s' % str(res))

            # Buttons
            self.connectButton.setDisabled(True)
            self.disconnectButton.setEnabled(True)

            Thread(target=self.receive, args=()).start()
        except:
            print('bye')
            self.client.close()
            sys.exit()

    def enter_password(self):
        self.password = self.passwordLineEdit.text()

        print('Password: ' + str(self.password))
        self.log('Password: ' + str(self.password))

        encrypted_message = encryptAES(self.nonce, self.password)

        print('Nonce: ' + str(self.nonce))
        self.log('Nonce: ' + str(self.nonce))

        res = b'CR' + encrypted_message
        self.client.sendall(res)

        print('Message sent for authentication: ' + str(res))
        self.log('Message sent for authentication: ' + str(res))
        self.enterButton.setDisabled(True)
        self.requestButton.setEnabled(True)


    def disconnect_server(self):
        self.client.close()
        print('bye bye!')
        self.log('bye bye!')
        sys.exit()
        self.connected=False
        self.connectButton.setEnabled(True)
        self.requestButton.setDisabled(True)
        self.enterButton.setDisabled(True)
        self.disconnectButton.setDisabled(True)

    def receive(self):
        try:
            while self.connected:
                buffer=self.client.recv(self.MAX_BUFFER_SIZE)
                if len(buffer) > 0:
                    print('Message received: ' + str(buffer))
                    self.log('Message received: ' + str(buffer))

                state=buffer[:2]

                if state == b'CR':  # CHALLENGE RESPONSE
                    self.nonce=buffer[2:]
                    print('Please enter your password and hit Enter')
                    self.log('Please enter your password and hit Enter')
                    self.enterButton.setEnabled(True)

                elif state == b'GH':  # GENERATE HASHCHAINS e.g 'GH iv as68d56 iv af5fdb'
                    message=buffer[2:]
                    seeds=decryptAES(self.password, message)
                    print('Hash chains are generated succesfully...')
                    self.log('Hash chains are generated succesfully...')
                    self.sc=symmtrc_cypr(
                        seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                    print('-------')
                    self.log('-------')
                    self.sc.reKey()
                    print('Please enter a valid iot device ID below')
                    self.log('Please enter a valid iot device ID below')

                elif state == b'AP':  # AUTHANTICATION RESPONSE
                    if integrity_check(self.sc.getKey(), buffer):
                        print('Integrity check is successfull...')
                        self.log('Integrity check is successfull...')
                        if self.sc.decrypt(buffer[2:-32]) == b'AF':
                            print('Authorization failed')
                            self.log('Authorization failed')
                            self.requestButton.setEnabled(True)
                        elif self.sc.decrypt(buffer[2:-32]) == b'AG':
                            print('Authorization granted')
                            self.log('Authorization granted')

                elif state == b'AF':  # AUTHORIZATION FAILED
                    print('Something bad happened, please try again...')
                    self.log('Something bad happened, please try again...')
                    self.requestButton.setEnabled(True)

                elif state == b'AN':  # AUTHENTICATION NEEDED - KEY TIMED OUT
                    self.enterButton.setEnabled(True)

                    print('Authentication time out..')
                    self.log('Authentication time out..')
                    res=b'AR' + get_mac().encode()
                    self.client.sendall(res)
                elif state == b'NA':  # NO AUTHORIZATION
                    print('You have no authorization to access this device')
                    print('Please try to access to another device')

                    self.log('You have no authorization to access this device')
                    self.log('Please try to access to another device')
                    self.requestButton.setEnabled(True)

                elif state == b'WP':  # WRONG PASSWORD
                    self.requestButton.setDisabled(True)
                    self.log(
                        'Password is wrong or your ip is not registered. Try to re-enter your password...')
                    print(
                        'Password is wrong or your ip is not registered. Try to re-enter your password...')
                    self.enterButton.setEnabled(True)
        except:
            import traceback
            traceback.print_exc()
            self.client.close()
            print('bye bye!')
            self.log('bye bye!')
            sys.exit()
           
