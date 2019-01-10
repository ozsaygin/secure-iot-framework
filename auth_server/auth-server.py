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

SERVER_PORT = ""

auth_list = dict()
auth_list["127.0.0.1"] = [["127.0.0.1"], "su123456"]

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def encryptAES(mess, key):
    h = SHA256.new()
    h.update(key.encode())
    hashed_password = h.hexdigest()
    key = hashed_password[:16].encode()
    raw = Padding.pad(mess, 128, style='iso7816')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(raw)

def decryptAES(key, mess):
    iv = mess[:AES.block_size]
    encs =  mess[AES.block_size:]
    h = SHA256.new()
    h.update(key.encode())
    hashed_password = h.hexdigest()
    key = hashed_password[:16]
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    return Padding.unpad(cipher.decrypt(encs), 128, style='iso7816')

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

def receive(conn, ip, port):
    nonce = None
    GATEWAY_KEY = socket_list[ip][2]
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
                    nonce = Random.new().read(16)
                    print("Generated NONCE: ", str(nonce))
                    conn.send(b'CR' + nonce)
                    print("CHALLENGE sent to ",ip , ".")
                elif state == b'CR':
                    print("A challenge recieved.")
                    state, cip, encnonce = buffer.split(b'SPLIT')
                    cip = cip.decode('utf8')
                    print("passs", auth_list[cip][1])
                    plain_message = decryptAES(auth_list[cip][1], encnonce)
                    print("plaain", plain_message)
                    if nonce == plain_message:
                        print("Authentication succesful!")
                        # client packet
                        s1 = Random.new().read(AES.block_size)
                        s2 = Random.new().read(AES.block_size)
                        encryptedSeeds = encryptAES(s1 + s2, auth_list[cip][1])
                        conn.send(package_message(GATEWAY_KEY, encryptedSeeds))
                        # gateway packet
                        encryptedSeeds = encryptAES(s1 + s2, GATEWAY_KEY) 
                        conn.send(package_message(GATEWAY_KEY, encryptedSeeds))
                        print("Seeds p, q sent to Gateway.")
                    else:
                        conn.send(b'WP')
                        print("Wrong password.")
                elif state == b'UR':
                    if integrity_check(GATEWAY_KEY, buffer):
                        print("Itegrity check succesful.")
                        req = decryptAES(GATEWAY_KEY, buffer[2:-32])
                        iotip = req[:int(len(req)/2)]
                        cip = req[int(len(req)/2):]
                        if  iotip.decode('utf8') in auth_list[cip.decode('utf8')][0]:
                            print("Authorization granted.")
                            mess = encryptAES(b'AG', GATEWAY_KEY)
                            conn.send(package_message(GATEWAY_KEY, mess))
                        else:
                            print("Authorization failed.")
                            mess = encryptAES(b'NA', GATEWAY_KEY)
                            conn.send(package_message(GATEWAY_KEY, mess))
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
                socket_list[ip] = [conn, True, "su12345"]
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
