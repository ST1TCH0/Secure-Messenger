import base64

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import io

from Crypto.Util.Padding import pad, unpad


class Encryptor:

    def __init__(self):
        self.mode = AES.MODE_EAX
        key = RSA.generate(2048)

        self.selfPublicKey = None
        self.selfPrivateKey = None

        self.setPrivateKey(key.export_key())
        self.setSelfPublicKey(key.publickey().export_key())
        self.sessionKey = None

    def getSelfPublicKey(self):
        return self.selfPublicKey

    def getPrivateKey(self):
        return self.selfPrivateKey

    def getSessionKey(self):
        return self.sessionKey

    def setSelfPublicKey(self, key):
        self.selfPublicKey = key
        file_out = open("public.pem", "wb")
        file_out.write(self.selfPublicKey)
        file_out.close()

    def setPrivateKey(self, key):
        self.selfPrivateKey = key
        file_out = open("private.pem", "wb")
        file_out.write(self.selfPrivateKey)
        file_out.close()

    def createSessionKey(self, rsaKey):
        self.sessionKey = get_random_bytes(16)

        output = io.StringIO()
        output.write(rsaKey)
        f = open("key.pem", "w")
        f.write(rsaKey)
        f.close()
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(open("key.pem").read()))
        return cipher_rsa.encrypt(self.sessionKey)

    def decryptSessionKey(self, enKey):
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.selfPrivateKey))
        self.sessionKey = cipher_rsa.decrypt(enKey)

    def encryptBlock(self, data):
        raw = pad(data, 16)
        cipher_aes = AES.new(self.sessionKey, AES.MODE_ECB)
        data = base64.b64encode(cipher_aes.encrypt(raw))
       # print("Key: {}\n data: {}".format(self.sessionKey, data))
        return data

    def decryptBlock(self, data):
        enc = base64.b64decode(data)
        cipher_aes = AES.new(self.sessionKey, AES.MODE_ECB)
        data = unpad(cipher_aes.decrypt(enc), 16)
       # print("Key: {}\n data: {}".format(self.sessionKey, data))
        return data
