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
    while socket_list[ip][1]:
        try:
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
                    print("Message: ", message)
                    if integrity_check(message, hmac):
                        print("AUTHENTICATION_REQUEST Integrity check successful.")
                        #get challenge from auth server
                        print("Requesting challenge from AS.")
                        auth_socket.send(package_message(b'AR ' + ip.encode()))
                        authResp = auth_socket.recv(MAX_BUFFER_SIZE)
                        authHMAC = authResp[len(authResp)-32:]
                        ASMessage = authResp[:-32]
                        if integrity_check(ASMessage, authHMAC):
                            print("AUTHENTICATION_REQUEST AS Integrity check successful.")
                            conn.send(authResp)
                            print("CHALLENGE sent to ",ip , ".")
                        else:
                            print("Integrity chech failed.")
                    else: #integrity failed
                        conn.send(b'AF'.encode("utf-8"))
                elif state == b'CR':
                    print("Challenge response recieved for IP: ", ip)
                    auth_socket.send(buffer)
                    authRespC = auth_socket.recv(MAX_BUFFER_SIZE)
                    authHMAC = authRespC[len(authRespC)-32:]
                    ASMessage = authRespC[:-32]
                    if integrity_check(ASMessage, authHMAC):
                        print("CHALLENGE_RESPONSE AS Integrity check successful.")
                        if authResp[:2] != b'AF':
                            conn.send(b'GH' + authRespC)
                            authRespG = auth_socket.recv(MAX_BUFFER_SIZE)
                            if integrity_check(authRespG[:-32], authRespG[len(authRespC)-32:]):
                                iv = authRespG[:AES.block_size]
                                encseeds =  authRespG[AES.block_size:-32]
                                h = SHA256.new()
                                h.update(GATEWAY_KEY.encode())
                                hashed_password = h.hexdigest()
                                key = hashed_password[:16]
                                cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
                                seeds = Padding.unpad(cipher.decrypt(encseeds), 128, style='iso7816')
                                SC = symmtrc_cypr(seeds[AES.block_size:2*AES.block_size], seeds[:AES.block_size])
                                socket_list[ip][2] = SC
                        else:
                            conn.send(package_message(b'AF'))
                    else:
                        print("Integrity chech failed.")
                # elif state == b'GH':
                #     message = buffer[:-32]
                #     gateway_msg = message[-32:]
                #     iv = gateway_msg[:16]
                #     enc_seeds = gateway_msg[16:]

                #     h = SHA256.new()
                #     h.update(GATEWAY_KEY.encode())
                #     hashed_password = h.hexdigest()
                #     key = hashed_password[:16]
                #     cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
                #     plain = Padding.unpad(client_cipher.decrypt(encMes), 128, style='iso7816')
                #     seed1 = plain[:16]
                #     seed2 = plain[16:]
                #     global hc
                    
                #     hc = hash_chain(100, seed1, seed2) 
                #     print('Hash chains are succesfully generated...')
                #     conn.sendall(package_message(buffer[:34]))
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