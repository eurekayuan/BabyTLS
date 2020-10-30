import attr
import json
from enum import Enum

class MessageType(Enum):
    CLIENT_HELLO = 0
    SERVER_HELLO = 1
    CERTIFICATE = 2
    SERVER_HELLO_DONE = 3
    CLIENT_KEY_EXCHANGE = 4
    FINISHED = 5
    DATA = 6

class Message(object):
    
    def dump(self):
        msg = {}
        msg["type"] = self.type.name
        msg["body"] = self.body
        return json.dumps(msg)

@attr.s
class ClientHello(Message):
    type = attr.ib(default=MessageType.CLIENT_HELLO)
    body = attr.ib(default="hello from client")

@attr.s
class ServerHello(Message):
    type = attr.ib(default=MessageType.SERVER_HELLO)
    body = attr.ib(default="hello from server")

@attr.s
class Certificate(Message):
    type = attr.ib(default=MessageType.CERTIFICATE)
    body = attr.ib(default="")
    
@attr.s
class ServerHelloDone(Message):
    type = attr.ib(default=MessageType.SERVER_HELLO_DONE)
    body = attr.ib(default="server hello done")

@attr.s
class ClientKeyExchange(Message):
    type = attr.ib(default=MessageType.CLIENT_KEY_EXCHANGE)
    body = attr.ib(default="")

@attr.s
class Finished(Message):
    type = attr.ib(default=MessageType.FINISHED)
    body = attr.ib(default="finished")

@attr.s
class Data(Message):
    type = attr.ib(default=MessageType.DATA)
    body = attr.ib(default="")

    

if __name__ == "__main__":
    c = Certificate(public_key="abc", signature="arnold")
    print(c.dump())
    