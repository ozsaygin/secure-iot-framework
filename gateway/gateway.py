#!/usr/local/bin/python3

from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto import Random

import socket
import sys
from threading import Thread
from binascii import hexlify
import traceback
from symmetric_cyphr import symmtrc_cypr

gateway_ip = "127.0.0.1"
socket_list = dict()
MAX_BUFFER_SIZE = 4096
listening = False
terminating = False

hc = None

GATEWAY_KEY = "su12345"

HOST="127.0.0.1"
PORT = 11114
SERVER_PORT = ""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
    digest =  HMAC.new(key, message)
    message = message + digest.hexdigest().encode()
    return message

def integrity_check(key, message):
    h = SHA256.new()
    h.update(key.encode())
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
                    #get challenge from auth server
                    print("Requesting challenge from AS.")
                    auth_socket.send(b'AR ' + ip.encode())
                    nonce = auth_socket.recv(MAX_BUFFER_SIZE)
                    conn.send(nonce)
                    print("CHALLENGE sent to ",ip , ".")
                elif state == b'CR':
                    print("Challenge response recieved for IP: ", ip)
                    print("Forwarding challenge to AS.")
                    auth_socket.send(buffer)
                    authRespC = auth_socket.recv(MAX_BUFFER_SIZE)
                    if integrity_check(GATEWAY_KEY, authRespC):
                        print("CHALLENGE_RESPONSE AS Integrity check successful.")
                        if authRespC[:2] != b'AF':
                            conn.send(b'GH' + authRespC[:-32])
                            authRespG = auth_socket.recv(MAX_BUFFER_SIZE)
                            if integrity_check(GATEWAY_KEY, authRespG):
                                seeds = decryptAES(GATEWAY_KEY, authRespG[:-32])
                                SC = symmtrc_cypr(seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                                socket_list[ip][2] = SC
                        else:
                            conn.send(b'AF')
                elif state == b'UR':
                    print("Authorization Request recieved.")
                    if integrity_check(socket_list[ip][3].getKey(), buffer):
                        print("Integrity check is successful.")
                        #send auth successful message
                    else:
                        print("Integrity check failed.")
                        #send no auth
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
        auth_socket.connect(("127.0.0.1", 11111))
        print("Connected to authentication server ip: 127.0.0.1, port: 11111.")
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
                socket_list[ip] = [conn, True, None]
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
server.close()