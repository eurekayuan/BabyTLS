from utils import message
import socket
from utils import crypto
import json
import rsa
import base64
import time
from des import DesKey
import hashlib
import os
import random


SUITE = "default"
trusted = ["CERT_ROOT_CA"]

class Client(object):
    '''
    host: server IPv4 address

    port: server port for TCP connection

    trusted: trusted certificates
    '''

    def __init__(self):
        path = os.getcwd()
        os.chdir('client')
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = "127.0.0.1"
        self.port = 8000
    
    def connect(self):
        self.s.connect((self.host, self.port))
    
    def disconnect(self):
        self.s.close()
    
    def start(self):
        '''
        TLS handshake process

        Client and server should perform handshake after connection

        works in application layer
        '''
        print("**********HANDSHAKE BEGIN**********")
        self.hello()
        handshakedone = False
        while not handshakedone:
            raw = self.s.recv(1024).decode('utf-8')
            if raw == None:
                continue
            msg = json.loads(raw)
            type = msg["type"]
            if type == "SERVER_HELLO":
                print("hello from server")
                step = message.MessageType.SERVER_HELLO
                self.server_random = str(msg["body"]["random"])
            elif step == message.MessageType.SERVER_HELLO and type == "CERTIFICATE":
                cert = msg["body"]
                if self.verify(cert) == True:
                    step = message.MessageType.CERTIFICATE

                    # get public key from the certificate
                    self.pubkeyServer = rsa.PublicKey.load_pkcs1(base64.b64decode(cert["publicKey"].encode()))
                else:
                    print("verification fails, connection drops")
                    return
            elif step == message.MessageType.CERTIFICATE and type == "SERVER_HELLO_DONE":
                print(msg["body"])
                self.exchange()
                step = message.MessageType.CLIENT_KEY_EXCHANGE
            elif step == message.MessageType.CLIENT_KEY_EXCHANGE and type == "FINISHED":
                print(msg["body"])
                handshakedone = True
        print("**********HANDSHAKE FINISH**********")
        self.communicate("TLS is not so difficult!")

    def hello(self):
        with open("clientSuite.json", "r") as f:
            suites = json.load(f)
        random.seed(time.time())
        num = random.randint(1000, 9999)
        msg = message.ClientHello(body={"suite":SUITE, "random": num}).dump()
        self.s.send(msg.encode('utf-8'))
        self.client_random = num
    
    def verify(self, cert):
        return crypto.verify(cert, trusted)
    
    def exchange(self):
        self.premasterKey()
        c = rsa.encrypt(self.premaster_key, self.pubkeyServer)
        c_base64 = base64.b64encode(c).decode()
        msg = message.ClientKeyExchange(body={"crypto":c_base64}).dump()
        self.s.send(msg.encode('utf-8'))
        self.master_key = crypto.genMasterKey(self.client_random, self.server_random, self.premaster_key)
        print(self.master_key)
    
    def premasterKey(self):
        random.seed(time.time())
        num = random.randint(1000, 9999)
        self.premaster_key = str(num).encode()

    def communicate(self, data):
        print("**********COMMUNICATION BEGIN**********")
        self.send(data)
        while True:
            raw = self.s.recv(1024).decode('utf-8')
            if raw == None:
                time.sleep(5)
    
    def send(self, data):
        des_key = DesKey(self.master_key)
        edata = des_key.encrypt(data.encode(), padding=True)
        edata_base64 = base64.b64encode(edata).decode()
        mac = hashlib.md5(edata_base64.encode()).hexdigest()
        msg = message.Data(body={"crypto":edata_base64, "mac":mac}).dump()
        self.s.send(msg.encode('utf-8'))


if __name__ == "__main__":
    client = Client()
    client.connect()
    client.start()
    
