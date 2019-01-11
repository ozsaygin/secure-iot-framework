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
auth_list = dict()
MAX_BUFFER_SIZE = 4096
listening = False
terminating = False

hc = None

GATEWAY_KEY = "su12345"

HOST="0.0.0.0"
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

def encryptAES(mess, key):
    h = SHA256.new()
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

def receive(conn, ip, port):
    clientID = ip + ':' + port
    while socket_list[clientID][1]:
        try:
            print("")
            # print("impossibru ", socket_list[clientID][3])

            buffer=conn.recv(MAX_BUFFER_SIZE)
            siz=sys.getsizeof(buffer)
            if siz >= MAX_BUFFER_SIZE:
                print("The length of input is probably too long: {}".format(siz))
                socket_list[clientID][2] = False
            else:
                #----------states---------#
                state = buffer[:2] #get state
                print("State: ", state)
                if state == b'AR':
                    socket_list[clientID][4] = buffer[2:]
                    print("Authentication Request recieved.")
                    #get challenge from auth server
                    print("Requesting challenge from AS.")
                    auth_socket.send(b'AR ' + ip.encode())
                    nonce = auth_socket.recv(MAX_BUFFER_SIZE)
                    conn.send(nonce)
                    print("CHALLENGE sent to ",clientID , ".")
                elif state == b'CR':
                    print("Challenge response recieved for IP: ", clientID)
                    print("Forwarding challenge to AS.")
                    auth_socket.send(b'CRSPLIT' + socket_list[clientID][4] + b'SPLIT' + buffer[2:])
                    authRespC = auth_socket.recv(MAX_BUFFER_SIZE)
                    if integrity_check(GATEWAY_KEY, authRespC):
                        print("CHALLENGE_RESPONSE AS Integrity check successful.")
                        if authRespC[:2] != b'WP':
                            authRespG = auth_socket.recv(MAX_BUFFER_SIZE)
                            socket_list[clientID][3] = True
                            conn.send(b'GH' + authRespC[:-32])
                            if integrity_check(GATEWAY_KEY, authRespG):
                                seeds = decryptAES(GATEWAY_KEY, authRespG[:-32])
                                SC = symmtrc_cypr(seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                                socket_list[clientID][2] = SC
                        else:
                            print(clientID, "Client authorization request failed.")
                            conn.send(b'WP')
                    else:
                        print("Integrity failed.")
                        conn.send(b'AF')
                elif state == b'UR' and socket_list[clientID][3]:
                    print("Authorization Request recieved.")
                    cypr = socket_list[clientID][2]
                    if integrity_check(cypr.getKey(), buffer):
                        print("Integrity check is successful.")
                        iotid = cypr.decrypt(buffer[2:-32])
                        req = iotid + socket_list[clientID][4]
                        encreq = encryptAES(req, GATEWAY_KEY)
                        auth_socket.send(package_message(GATEWAY_KEY, b'UR' + encreq))
                        resp = auth_socket.recv(MAX_BUFFER_SIZE)
                        if integrity_check(GATEWAY_KEY, resp):
                            print("Integrity check is successful.")
                            resp = decryptAES(GATEWAY_KEY, resp[:-32])
                            if resp == b'AG':
                                print("Authorization granted!")
                                auth_list[clientID].append(iotid.decode('utf8'))
                            else:
                                print('Authorization failed.') 
                            encresp = cypr.encrypt(resp)
                            conn.send(package_message(cypr.getKey(), b'AP' + encresp))
                    else:
                        print("Integrity check failed.")
                        conn.send(b'FA')
                else:
                    print("Authorization needed.")
                    socket_list[clientID][1] = False
                    conn.send(b'AN')
                if socket_list[clientID][3]:
                    print("---------")
                    if not socket_list[clientID][2].reKey():
                        socket_list[clientID][3] = False
                        auth_list[clientID] = []
                        conn.send(b'AN')
        except:
            traceback.print_exc()
            if not terminating:
                print('client has disconnected')
            conn.close()
            socket_list[clientID][1] = False
    del socket_list[clientID]
    del auth_list[clientID]
            
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
                print("---------------------------------------------")
                print("---------------------------------------------")
                print('Accepting connection from ' + ip + ':' + port)
                print("---------------------------------------------")
                print("---------------------------------------------")
                socket_list[ip + ':' + port] = [conn, True, None, False, None]
                auth_list[ip + ':' + port] = []
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