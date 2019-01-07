#!/usr/local/bin/python3

from Crypto.Hash import HMAC
import socket
import sys
from threading import Thread
from binascii import hexlify
import traceback

gateway_ip = "127.0.0.1"
socket_list = dict()
MAX_BUFFER_SIZE = 4096
listening = False
terminating = False

HOST="127.0.0.1"
PORT = 11115
SERVER_PORT = ""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# def accept():
#     accepting = True
#     while accepting:
#         try:
#             con, addr = server.accept()
#             socket_list.append(server.accept()[0])
#             conn=socket_list[len(socket_list)-1]
#             buffer = conn.recv(MAX_BUFFER_SIZE)
#             siz=sys.getsizeof(buffer)
#             if siz >= MAX_BUFFER_SIZE:
#                 print("The length of input is probably too long: {}".format(siz))
#             message = buffer.decode("utf8").rstrip() # decoded to UTF-8 string
#             Thread(target = receive, args = ()).start()
#         except:
#             accepting = False
#             import traceback
#             traceback.print_exc()
#             print("Listening socket stop working..")
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
                            print("AUTHENTICATION_REQUEST AUTS Integrity check successful.")
                            conn.send(authResp)
                            print("CHALLENGE sent to ",ip , ".")
                        else:
                            print("Integrity chech failed.")
                    else: #integrity failed
                        conn.send(b'AF'.encode("utf-8"))
                elif state == b'CR':
                    print("Challenge recieved for IP: ", ip)
                    auth_socket.send(buffer)
                    print("Challenge sent to AS.")
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
server.close()