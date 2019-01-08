#!/usr/local/bin/python3
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto import Random

import hmac
import socket
import sys
import random
from threading import Thread
from binascii import hexlify

import traceback

gateway_ip = "127.0.0.1"
socket_list = dict()
MAX_BUFFER_SIZE = 4096
listening = False
terminating = False
accepting = True

HOST="127.0.0.1"
PORT=11111

CLIENT_PASSWORD = "su12345"
GATEWAY_KEY = "su12345"
SERVER_PORT = ""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def encryptAES(mess, key):
    raw = Padding.pad(mess, 128)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)

def package_message(message): 
    digest =  HMAC.new(message)
    message = message + digest.hexdigest().encode()
    return message

def integrity_check(message, hmac):
    digest = HMAC.new(message).hexdigest()
    if digest.encode('utf-8') == hmac:
        return True
    else:
        return False

def receive(conn, ip, port):
    nonce = None
    while socket_list[ip][1]:
        try:
            print("")
            buffer=conn.recv(MAX_BUFFER_SIZE)
            siz=sys.getsizeof(buffer)
            if siz >= MAX_BUFFER_SIZE:
                print("The length of input is probably too long: {}".format(siz))
                socket_list[ip][2] = False
            else:
                #----------states---------#
                state = buffer[:2] #get state
                print("State: ", state)
                if state == b'AR':
                    print("Authentication Request recieved.")
                    hmac = buffer[len(buffer)-32:]
                    message = buffer[:-32]
                    if integrity_check(message, hmac):
                        print("Integrity check successful.")
                        #the request is going to be forwarded to Authentication Server expecting challenge
                        nonce = Random.new().read(16)
                        print("Generated NONCE: ", str(nonce))
                        conn.send(package_message(b'CR' + nonce))
                        print("CHALLENGE sent to ",ip , ".")
                    else: #integrity failed
                        conn.send("AF".encode("utf-8"))
                elif state == b'CR':
                    print("A challenge recieved.")
                    hmac = buffer[len(buffer)-32:]
                    message = buffer[:-32]
                    if integrity_check(message, hmac):
                        print("Integrity check successful.")
                        iv = message[2:AES.block_size+2]
                        print("iv zamanı ", iv)
                        encMes = message[AES.block_size+2:]
                        h = SHA256.new()
                        h.update(CLIENT_PASSWORD.encode())
                        hashed_password = h.hexdigest()
                        key = hashed_password[:16]
                        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
                        plain_message = Padding.unpad(cipher.decrypt(encMes), 128, style='iso7816')
                        print("Plain ", plain_message)
                        if nonce == plain_message:
                            print("Authentication succesful!")
                            s1 = Random.new().read(AES.block_size)
                            s2 = Random.new().read(AES.block_size)
                            encryptedSeeds = encryptAES(s1 + s2, key.encode())
                            conn.send(package_message(encryptedSeeds))
                        else:
                            print("Wrong password.")
                    else: #integrity failed
                        print("Integrity check failed!")
                        conn.send("AF".encode("utf-8"))
                else:
                    print("Unexpected Path!")
                    socket_list[ip][1] = False
                #----------states---------#
        except:
            traceback.print_exc()
            recieving = False 
            if not terminating:
                print('client has disconnected')
            conn.close()
            socket_list[ip][1] = False
    del socket_list[ip]
            
def start():
    try:
        #connect to auth_server
        if True:
            server.bind((HOST, PORT))
            print('Socket bind complete')
            server.listen( 10)
            print('Socket now listening')
            listening = True

            while True:
                conn, addr = server.accept()
                ip, port = str(addr[0]), str(addr[1])
                print('Accepting connection from ' + ip + ':' + port)
                socket_list[ip] = [conn, True]
                try:
                    Thread(target=receive, args=(conn, ip, port)).start()
                except:
                    print("Error in thread start!")
                    traceback.print_exc()
            server.close()

    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()))
        sys.exit()


start()
