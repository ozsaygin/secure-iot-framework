#!/usr/local/bin/python3

import hmac
import socket
import sys
from threading import Thread
from binascii import hexlify

gateway_ip = "127.0.0.1"
socket_list = list()
MAX_BUFFER_SIZE = 4096
listening = False
terminating = False
accepting = True

HOST="127.0.0.1"
PORT=12345

CLIENT_PASSWORD = "su12345"
CLIENT_MAC_ADDRESS = "a2:00:b4:2a:66:00"
SERVER_PORT = ""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def accept():
    while accepting:
        try:
            socket_list.append(server.accept()[0])
            conn=socket_list[len(socket_list)-1]
            buffer = conn.recv(MAX_BUFFER_SIZE)
            siz=sys.getsizeof(buffer)
            if siz >= MAX_BUFFER_SIZE:
                print("The length of input is probably too long: {}".format(siz))
            message = buffer.decode("utf8").rstrip() # decoded to UTF-8 string
            Thread(target = receive, args = ()).start()
        except:
            if terminating:
                accepting = false
            else 
                print("Listening socket stop working..")

def receive():
    receiving=True
    conn=sockets[len(sockets)-1]
    while receiving:
        try:
            buffer=conn.recv(MAX_BUFFER_SIZE)
            siz=sys.getsizeof(buffer)
            if siz >= MAX_BUFFER_SIZE:
                print("The length of input is probably too long: {}".format(siz))

            message=buffer.decode("utf8").rstrip()
        except: 
            if not terminating:
                print('client has disconnected')
            conn.close()
            socket_list.remove(conn)
            

def start():

    try:
        server.bind((HOST, PORT))
        print('Socket bind complete')
        soc.listen( 10)
        print('Socket now listening')
        Thread(target = accept, args = ()).start()
        listening = True

    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()) + msg)
        sys.exit()

start()
