import rsa
import json
import base64
import hashlib

def createKey(pubkeyfile, privkeyfile):
    (pubkey, privkey) = rsa.newkeys(1024)
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.save_pkcs1())
    with open(privkeyfile, "wb") as f:
        f.write(privkey.save_pkcs1())


def createNormalCert(pubkeyfile_ca, privkeyfile_ca, pubkeyfile_server):
    with open(pubkeyfile_ca, 'rb') as f:
        content = f.read()
        pubkeyCA = rsa.PublicKey.load_pkcs1(content)
    with open(privkeyfile_ca, 'rb') as f:
        content = f.read()
        privkeyCA = rsa.PrivateKey.load_pkcs1(content)
    with open(pubkeyfile_server, 'rb') as f:
        content = f.read()
        pubkeyServer = rsa.PublicKey.load_pkcs1(content)

    msg = pubkeyServer.save_pkcs1()
    signature = rsa.sign(msg, privkeyCA, 'SHA-1')

    cert = {}
    cert["name"] = "CERT_SERVER"
    cert["issuer"] = "CERT_ROOT_CA"
    cert["publicKey"] = base64.b64encode(msg).decode()
    cert["signature"] = base64.b64encode(signature).decode()
    with open('CERT_SERVER', 'w') as f:
        json.dump(cert, f)

def createRootCert(pubkeyfile_ca, privkeyfile_ca):
    with open(pubkeyfile_ca, 'rb') as f:
        content = f.read()
        pubkeyCA = rsa.PublicKey.load_pkcs1(content)
    with open(privkeyfile_ca, 'rb') as f:
        content = f.read()
        privkeyCA = rsa.PrivateKey.load_pkcs1(content)

    msg = pubkeyCA.save_pkcs1()
    signature = rsa.sign(msg, privkeyCA, 'SHA-1')

    cert = {}
    cert["name"] = "CERT_ROOT_CA"
    cert["issuer"] = "CERT_ROOT_CA"
    cert["publicKey"] = base64.b64encode(msg).decode()
    cert["signature"] = base64.b64encode(signature).decode()
    with open('CERT_ROOT_CA', 'w') as f:
        json.dump(cert, f)

def verify(certificate, trusted):
    '''
    Recursively verifies a certificate until reaches a trusted root CA.
    If the root CA is not trusted, then returns false.
    '''
    print("verifying", certificate["name"])
    
    if certificate["name"] in trusted:
        print("verification succeed")
        return True
    elif certificate["name"] == certificate["issuer"]:
        print("verification fail")
        return False
    else:
        msg = base64.b64decode(certificate["publicKey"].encode())
        signature = base64.b64decode(certificate["signature"].encode())
        with open(certificate["issuer"], "r") as ci:
            issuer_certificate = json.load(ci)
        pubkeyCA = rsa.PublicKey.load_pkcs1(base64.b64decode(issuer_certificate["publicKey"].encode()))
        try:
            rsa.verify(msg, signature, pubkeyCA)
        except:
            print("verification fail")
            return False
        return verify(issuer_certificate, trusted)

def genMasterKey(client_rand, server_rand, premaster_key):
    s = str(client_rand).encode() + str(server_rand).encode() + premaster_key
    master_key = hashlib.md5(s).hexdigest()
    return master_key[:8].encode()