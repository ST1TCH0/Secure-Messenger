import base64
import json

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import io

from Crypto.Util.Padding import pad, unpad


class Encryptor:

    def __init__(self):
        self.mode = AES.MODE_ECB
        key = RSA.generate(2048)

        self.selfPublicKey = None
        self.selfPrivateKey = None
        self.selfPrivateKeyKey = None
        self.setPrivateKey(key.export_key())
        self.setSelfPublicKey(key.publickey().export_key())
        self.sessionKey = None
        self.cypher = None

    def getSelfPublicKey(self):
        return self.selfPublicKey

    def getPrivateKey(self):
        return self.selfPrivateKey

    def changeMode(self, mode):
        if mode == 'ECB':
            self.mode = AES.MODE_ECB
        else:
            self.mode = AES.MODE_CBC
        #self.cypher = AES.new(self.sessionKey, self.mode)



    def getSessionKey(self):
        return self.sessionKey

    def setSessionKey(self, key):
        self.sessionKey = key

    def setSelfPublicKey(self, key):
        self.selfPublicKey = key
        file_out = open("public.pem", "wb")
        file_out.write(self.selfPublicKey)
        file_out.close()

    def setPrivateKey(self, key):
        self.selfPrivateKey = key
        self.selfPrivateKeyKey = get_random_bytes(16)
        cyph = AES.new(self.selfPrivateKeyKey, AES.MODE_ECB)
        file_out = open("private.pem", "wb")

        raw = pad(self.selfPrivateKey, 16)
        data = base64.b64encode(cyph.encrypt(raw))

        file_out.write(cyph.encrypt(data))
        file_out.close()

    def createSessionKey(self, rsaKey):
        self.sessionKey = get_random_bytes(16)

        output = io.StringIO()
        output.write(rsaKey)
        f = open("key.pem", "w")
        f.write(rsaKey)
        f.close()
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(open("key.pem").read()))
        self.cypher = AES.new(self.sessionKey, self.mode)
        return cipher_rsa.encrypt(self.sessionKey)

    def decryptSessionKey(self, enKey):
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.selfPrivateKey))
        self.sessionKey = cipher_rsa.decrypt(enKey)
        self.cypher = AES.new(self.sessionKey, self.mode)

    def encryptBlock(self, data):
        raw = pad(data, 16)
        self.cypher = AES.new(self.sessionKey, AES.MODE_ECB)
        data = base64.b64encode(self.cypher.encrypt(raw))
        print(len(data))
       # print("Key: {}\n data: {}".format(self.sessionKey, data))
        return data

    def decryptBlock(self, data):
        enc = base64.b64decode(data)
        self.cypher = AES.new(self.sessionKey, AES.MODE_ECB)
        data = unpad(self.cypher.decrypt(enc), 16)
       # print("Key: {}\n data: {}".format(self.sessionKey, data))
        return data

    def encryptBlockType(self, data, type, iv):
        raw = pad(data, 16)
        if (type == "CBC"):
            self.cypher = AES.new(self.sessionKey, AES.MODE_CBC, iv)
        else:
            self.cypher = AES.new(self.sessionKey, AES.MODE_ECB)
        data = base64.b64encode(self.cypher.encrypt(raw))
       # print("Key: {}\n data: {}".format(self.sessionKey, data))
        return data

    def decryptBlockType(self, data, type, iv):
        enc = base64.b64decode(data)
        if (type == "CBC"):
            self.cypher = AES.new(self.sessionKey, AES.MODE_CBC, iv)
        else:
            self.cypher = AES.new(self.sessionKey, AES.MODE_ECB)
        data = unpad(self.cypher.decrypt(enc), 16)
        return data
