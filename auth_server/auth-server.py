#!/usr/local/bin/python3
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util import Padding

import hmac
import socket
import sys
import random
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
GATEWAY_KEY = "su12345"
CLIENT_MAC_ADDRESS = "70:C9:4E:FA:AB:EF" # Lenova Thinkpad
SERVER_PORT = ""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def package_message(message): 
    digest =  HMAC.new(message.encode())
    message = message + digest 
    res = message.encode('utf8')
    return res
    
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
    receiving = True
    conn = sockets[len(sockets)-1]
    while receiving:
        try:
            buffer = conn.recv(MAX_BUFFER_SIZE)
            siz = sys.getsizeof(buffer)
            if siz >= MAX_BUFFER_SIZE:
                print("The length of input is probably too long: {}".format(siz))
            buffer = buffer.decode("utf8").rstrip()
            
            # validate message digest
            message = buffer[:-32]
            digest = buffer[len(buffer)-32:]

            if HMAC.new(message.encode).hexdigest() == digest: 
                command = message.split()[0] # e.g: 'AUTHENTICATIONREQUEST', 'CHALLENGERESPONSE'
                if (len(message.split()) > 1):
                    args = message.split()[1:]
                if command == 'AUTHENTICATIONREQUEST': # authentication request
                    if args[0] == CLIENT_MAC_ADDRESS:
                        # generate random 128-bit random nonce
                        nonce = random.getrandbits(128)
                        message = 'CHALLENGE ' + str(nonce) 
                        res = package_message(message)
                        conn.send(res)
                    else: # if client's mac address doesn't match, don't accept
                        message = 'NOTREGISTERED'
                        res = package_message(message)
                        conn.send(res)
                elif command == 'CHALLENGERESPONSE': # challenge response
                    # expected message: 'CHALLENGERESPONSE E(nonce | CID, H(P))'
                    client_hashed_pwd = SHA256.new().update(CLIENT_PASSWORD.encode()).hexdigest()
                    client_cipher = AES.new(client_hashed_pwd, AES.MODE_ECB)

                    gateway_hashed_pwd = SHA256.new().update(GATEWAY_PASSWORD.encode()).hexdigest()
                    gateway_cipher = AES.new(gateway_hashed_pwd, AES.MOD_ECB)

                    decrypted_msg = client_cipher.decrypt(Padding.unpad(arg[1].decode(), 128))
                    # decyrpy unpad
                    
                    if nonce == decrypted_msg:
                        # if message is validated, sends  E(S1 | S2 , H(P)) | E( S1 | S2 | CID, GK)
                        seed1 = str(random.getrandbits(128))
                        seed2 = str(random.getrandbits(128))
                        seeds = seed1 + seed2
                        client_message = client_cipher.encrypt(Padding.pad(seeds.encode(), 128))
                        gateway_message = gateway_cipher.encrypt(Padding.pad((seeds + cid).encode(), 128))
                        message = 'HASHCHAINSEEDS ' + client_message + gateway_message  
                        res = package_message(message)
                        conn.send(res) 

            else: # not a valid digest
                message = 'INVALIDHMAC'
                res = package_message(message)
                conn.send(message)
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
