from utils import message
from utils import crypto
import socket
import json
import time
import base64
import rsa
from des import DesKey
import hashlib
import os
import random

class Server(object):
    def __init__(self):
        path = os.getcwd()
        os.chdir('server')
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = "127.0.0.1"
        self.port = 8000
        self.serversocket.bind((self.host, self.port))
        self.serversocket.listen(1)
        self.cert = "CERT_SERVER"
        with open('privkeyServer', 'rb') as f:
            content = f.read()
        self.privkeyServer = rsa.PrivateKey.load_pkcs1(content)
    
    def connect(self):
        self.clientsocket, self.clientaddr = self.serversocket.accept()
    
    def disconnect(self):
        self.clientsocket.close()
    
    def start(self):
        print("**********HANDSHAKE BEGIN**********")
        handshakedone = False
        while not handshakedone:
            received_msg_raw = self.clientsocket.recv(1024).decode('utf-8')
            if received_msg_raw == None:
                continue
            received_msg = json.loads(received_msg_raw)
            type = received_msg["type"]
            if type == "CLIENT_HELLO":
                request_suite = received_msg["body"]["suite"]
                with open("serverSuite.json", "r") as f:
                    suites = json.load(f)
                if request_suite not in suites.keys():
                    print("suite not supported")
                    return
                else:
                    print("Suite:", suites[request_suite])
                self.client_random = str(received_msg["body"]["random"])
                self.hello()
                time.sleep(1)
                self.certificate()
                time.sleep(1)
                self.hellodone()
                step = message.MessageType.SERVER_HELLO_DONE

            elif step == message.MessageType.SERVER_HELLO_DONE and type == "CLIENT_KEY_EXCHANGE":
                c = base64.b64decode(received_msg["body"]["crypto"].encode())
                self.premaster_key = rsa.decrypt(c, self.privkeyServer)
                self.master_key = crypto.genMasterKey(self.client_random, self.server_random, self.premaster_key)
                print("Session key:", self.master_key)
                self.finish()
                handshakedone = True
        print("**********HANDSHAKE FINISH**********")
        self.communicate()



    def hello(self):
        random.seed(time.time())
        num = random.randint(1000, 9999)
        msg = message.ServerHello(body={"random": num}).dump()
        self.clientsocket.send(msg.encode('utf-8'))
        self.server_random = num

    def certificate(self):
        with open(self.cert, 'r') as f:
            content = json.load(f)
        msg = message.Certificate(body=content).dump()
        self.clientsocket.send(msg.encode('utf-8'))
    
    def hellodone(self):
        msg = message.ServerHelloDone().dump()
        self.clientsocket.send(msg.encode('utf-8'))

    def finish(self):
        msg = message.Finished().dump()
        self.clientsocket.send(msg.encode('utf-8'))

    def communicate(self):
        print("**********COMMUNICATION BEGIN**********")
        while True:
            received_msg_raw = self.clientsocket.recv(1024).decode('utf-8')
            if received_msg_raw == None:
                time.sleep(5)
            received_msg = json.loads(received_msg_raw)
            type = received_msg["type"]
            if type == "DATA":
                crypto = base64.b64decode(received_msg["body"]["crypto"].encode())
                deskey = DesKey(self.master_key)
                data = deskey.decrypt(crypto, padding=True).decode()
                print("data", data)
                mac = received_msg["body"]["mac"]
                if hashlib.md5(received_msg["body"]["crypto"].encode()).hexdigest() == mac:
                    print("status", "MAC Verification Succeed")
                else:
                    print("status", "MAC Verification Fail")

if __name__ == "__main__":
    server = Server()
    server.connect()
    server.start()
