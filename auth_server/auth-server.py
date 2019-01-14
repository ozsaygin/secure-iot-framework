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
from time import time
import traceback

'''
import time

start = time.time()
print("hello")
end = time.time()
print(end - start)

'''
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
auth_list["A4:5E:60:D4:45:53"] = [["A4:5E:60:D4:45:53"], "ata123456"]
auth_list["EE:04:B8:FA:60:0D"] = [["EE:04:B8:FA:60:0D"], "iot123456"]
auth_list["70:C9:4E:FA:AB:EF"] = [["70:C9:4E:FA:AB:EF", "EE:04:B8:FA:60:0D"], "su123456"]
auth_list["F4:0F:24:33:4A:DC"] = [["F4:0F:24:33:4A:DC", "EE:04:B8:FA:60:0D"], "su1234567"]


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
    gatewayID = ip + ':' + port
    GATEWAY_KEY = socket_list[gatewayID][2]
    while socket_list[gatewayID][1]:
        try:
            print("")
            buffer=conn.recv(MAX_BUFFER_SIZE)
            siz=sys.getsizeof(buffer)
            if siz >= MAX_BUFFER_SIZE:
                print("The length of input is probably too long: {}".format(siz))
                socket_list[gatewayID][2] = False
            else:
                #----------states---------#
                state = buffer[:2] #get state
                print("State: ", state)
                if state == b'AR':
                    print("Authentication Request recieved.")
                    nonce = Random.new().read(16)
                    print("Generated NONCE: ", str(nonce))
                    conn.send(b'CR' + nonce)
                    print("CHALLENGE sent to ",gatewayID , ".")
                elif state == b'CR':
                    print("A challenge recieved.")
                    state, cip, encnonce = buffer.split(b'SPLIT')
                    cip = cip.decode('utf8')
                    plain_message = ""
                    problem = False
                    try:
                        plain_message = decryptAES(auth_list[cip][1], encnonce)
                    except:
                        problem = True
                        print("Wrong password.")
                    if nonce == plain_message and (not problem):
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
                        conn.send(package_message(GATEWAY_KEY, b'WP'))
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
                        conn.send('')
                        print("Integrity check failed.")
                else:
                    print("Unexpected Path!")
                    socket_list[gatewayID][1] = False
                #----------states---------#
        except:
            traceback.print_exc()
            if not terminating:
                print('client has disconnected')
            conn.close()
            socket_list[gatewayID][1] = False
    del socket_list[gatewayID]
            
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
                print("*********************************************")
                print("*********************************************")
                print('Accepting connection from ' + ip + ':' + port)
                print("*********************************************")
                print("*********************************************")
                socket_list[ip + ':' + port] = [conn, True, "su12345"]
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
