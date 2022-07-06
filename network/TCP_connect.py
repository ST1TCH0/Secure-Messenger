import base64
import datetime
import io
import socket
import string
import threading
import queue
import json
import time
import os

from Crypto.Random import random, get_random_bytes
from cryptom.Encryption import Encryptor


class Connector:

    def __init__(self, __window, __progress):

        self.__portToBind = 54321
        self.__portToConnect = 54322
        self.__encryptor = Encryptor()

        self_ip = socket.gethostbyname(socket.gethostname())
        self.__socketSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socketReceiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socketReceiver.settimeout(2)
        self.__socketReceiver.bind(("0.0.0.0", self.__portToConnect))
        self.__socketReceiver.listen(5)
        self.__socketReceiver.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            1388)
        self.__receiver = Receiver(self.__socketReceiver, self.__encryptor, __window, __progress)
        self.__sender = Sender(self.__socketSender, self.__encryptor, __window, __progress)
        self.__receiver.start()

        self.selfPublicKey = None
        self.targetPublicKey = None

    def __del__(self):
        return

    def createSender(self, ip):
        if self.__socketSender:
            self.__socketSender.close()

        self.__socketSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socketSender.bind(("0.0.0.0", self.__portToBind))
        self.__socketSender.connect((ip, self.__portToConnect))

        self.__sender.setSock(self.__socketSender)
        self.__socketSender.send(self.__encryptor.getSelfPublicKey())

    def getEncryptor(self):
        return self.__encryptor

    def changeMode(self, mode):
        self.__encryptor.changeMode(mode)

    def getSender(self):
        return self.__sender

    def getReciever(self):
        return self.__receiver

    def getSocketSender(self):
        return self.__socketSender

    def getSocketReciever(self):
        return self.__socketReceiver


class Receiver(threading.Thread):

    def __init__(self, socketReciver, __encryptor, __window, __progress):

        threading.Thread.__init__(self)
        self.__encryptor = __encryptor
        self.__target_address = None
        self.__socketReceiver = socketReciver
        self.__running = True
        self.__messages_to_show = queue.LifoQueue()
        self.__fileToSend = None
        self.__fileToSendPar = None
        self.__conn = None
        self.__downloadsPath = None
        self.__sessionKey = None
        self.__conFlag = False
        self.enKey = None
        self.connected = False
        self.progress = 0


    def __del__(self):
        self.kill()
        return

    def setDownloadsPath(self, path):
        self.__downloadsPath = path

    def setConFlag(self, flag):
        self.__conFlag = flag

    def setConn(self, conn):
        self.__conn = conn

    def run(self):
        msg = None
        while self.__running:
            try:
                if self.__conn is None:
                    self.__conn, self.__target_address = self.__socketReceiver.accept()
                    print(self.__target_address)
                    msg = self.__conn.recv(2048)
                    if not self.connected:
                        if self.__conFlag:
                            self.__encryptor.decryptSessionKey(msg)
                            print("session key decrypted")
                        else:
                            self.enKey = self.__encryptor.createSessionKey(msg.decode())
                            print("session key encrypted")
                        self.connected = True
                        msg = None
                        self.__target_address = None
                msg = self.__conn.recv(2048)
            except socket.error:
                print("Socket recieving error")
                self.__encryptor.setSessionKey(None)
                self.__conn = None
                self.connected = False
            if msg and self.__encryptor.getSessionKey():
                msg = self.__encryptor.decryptBlock(msg).decode()
                try:
                    test = json.loads(msg)
                    print("JSON test acc")
                    if type(test) == int:
                        continue
                    if test["ext"]:
                        print("received marker:")
                        print(test)
                        temp = open("temp", "wb")
                        buff = self.__conn.recv(2048)
                        while buff != b"DONE":
                            if buff:
                                temp.write(buff)
                            buff = self.__conn.recv(2048)
                        temp = open("temp", "rb")
                        buff = temp.read(test["blocks"])
                        print("received DONE")

                        f = open(self.__downloadsPath + os.path.basename(test["name"]) + test["ext"], "wb")
                        while buff:
                            f.write(self.__encryptor.decryptBlockType(buff, test['cypher'], test['iv'].encode()))
                            buff = temp.read(test["blocks"])
                        f.close()
                        print("downloaded DONE")
                except ValueError as e:
                    print("JSON test failed {}".format(e))
                    msg = msg + '\n'
                    print(msg)
                    self.__messages_to_show.put(msg)
                    continue

    def getMsgToShow(self):
        if self.__messages_to_show.empty():
            return None
        return self.__messages_to_show.get_nowait()

    def getAddress(self):
        return self.__target_address

    def setAddress(self, address):
        self.__target_address = address

    def getProgress(self):
        return self.progress

    def kill(self):
        self.__running = False

    def getConn(self):
        return self.__conn


class Sender:

    def __init__(self, ___socketSender, __encryptor, __window, __progress):
        self.__encryptor = __encryptor
        self.__conn = None
        self.__target_address = None
        self.__socketSender = ___socketSender
        self.__messages_to_show = queue.LifoQueue()
        self.progress = __progress
        self.window = __window
        self.cyphtype = "ECB"

    def __del__(self):
        return

    def setTargetAddress(self, address):
        self.__target_address = address

    def addProgress(self, state):
        self.progress['value'] = state
        self.window.update()

    def setSock(self, _sock):
        self.__socketSender = _sock

    def setCyphType(self, type):
        self.cyphtype = type

    def sendMessage(self, msg):
        print(msg)
        ans = self.__encryptor.encryptBlock(msg.encode())
        print(ans)
        self.__socketSender.send(ans)

    def sendFile(self, file):
        file_name, file_extension = os.path.splitext(file)
        file_size = os.path.getsize(file)

        f = open(file, 'rb')
        buff = f.read(8 * 1024)

        letters = string.ascii_lowercase

        iv = ''.join(random.choice(letters) for i in range(16))

        blocksize = len(self.__encryptor.encryptBlockType(buff, self.cyphtype, iv.encode()))

        filePar = json.dumps({
            "name": file_name,
            "ext": file_extension,
            "blocks": blocksize,
            "size": file_size,
            "cypher": self.cyphtype,
            "iv": iv
        })
        msg = filePar.encode()
        msg = self.__encryptor.encryptBlock(msg)
        self.__socketSender.send(msg)

        print("Sending...")
        pr = int(0)
        while buff:
            pr += int(8 * 1024 / file_size * 100)
            self.addProgress(pr)
            self.__socketSender.send(self.__encryptor.encryptBlockType(buff, self.cyphtype, iv.encode()))
            buff = f.read(8 * 1024)

        time.sleep(10)

        self.__socketSender.send(b"DONE")
        print("Sending DONE")
        f.close()
