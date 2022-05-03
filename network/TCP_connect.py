import datetime
import io
import socket
import threading
import queue
import json
import time
import os

from cryptom.Encryption import Encryptor


class Connector:

    def __init__(self):

        self.__portToBind = 54321
        self.__portToConnect = 54322
        self.__encryptor = Encryptor()

        self_ip = socket.gethostbyname(socket.gethostname())
        self.__socketSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socketReceiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socketReceiver.bind(("25.69.215.100", self.__portToConnect))
        self.__socketReceiver.listen(5)
        self.__socketReceiver.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_RCVBUF,
            1388)
        self.__receiver = Receiver(self.__socketReceiver, self.__encryptor)
        self.__sender = Sender(self.__socketSender, self.__encryptor)
        self.__receiver.start()

        self.selfPublicKey = None
        self.targetPublicKey = None



    def __del__(self):
        self.__receiver.kill()
        return

    def createSender(self, ip):
        if self.__socketSender:
            self.__socketSender.close()

        self.__socketSender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socketSender.bind(("25.69.215.100", self.__portToBind))
        self.__socketSender.connect((ip, self.__portToConnect))

        self.__sender.setSock(self.__socketSender)
        self.__socketSender.send(self.__encryptor.getSelfPublicKey())

    def getEncryptor(self):
        return self.__encryptor

    def getSender(self):
        return self.__sender

    def getReciever(self):
        return self.__receiver

    def getSocketSender(self):
        return self.__socketSender

    def getSocketReciever(self):
        return self.__socketReceiver


class Receiver(threading.Thread):

    def __init__(self, socketReciver, __encryptor):

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

    def __del__(self):
        self.kill()
        return

    def setDownloadsPath(self, path):
        self.__downloadsPath = path

    def setConFlag(self, flag):
        self.__conFlag = flag

    def run(self):
        msg = None
        while self.__running:
            if self.__conn is None:
                self.__conn, self.__target_address = self.__socketReceiver.accept()
                print(self.__target_address)
            try:
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
            except socket.error:
                print("Socket recieving error")
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
                        buff = temp.read(43712)
                        print("received DONE")

                        f = open(self.__downloadsPath + os.path.basename(test["name"]) + test["ext"], "wb")
                        while buff:
                            f.write(self.__encryptor.decryptBlock(buff))
                            buff = temp.read(43712)
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

    def kill(self):
        self.__running = False

    def getConn(self):
        return self.__conn


class Sender:

    def __init__(self, ___socketSender, __encryptor):
        self.__encryptor = __encryptor
        self.__conn = None
        self.__target_address = None
        self.__socketSender = ___socketSender
        self.__messages_to_show = queue.LifoQueue()

    def __del__(self):
        return

    def setTargetAddress(self, address):
        self.__target_address = address

    def setSock(self, _sock):
        self.__socketSender = _sock

    def sendMessage(self, msg):
        print(msg)
        ans = self.__encryptor.encryptBlock(msg.encode())
        print(ans)
        self.__socketSender.send(ans)

    def sendFile(self, file):
        file_name, file_extension = os.path.splitext(file)
        filePar = json.dumps({
            "name": file_name,
            "ext": file_extension
        })
        msg = filePar.encode()
        msg = self.__encryptor.encryptBlock(msg)
        self.__socketSender.send(msg)

        f = open(file, 'rb')
        buff = f.read(8 * 1024)
        print("Sending...")
        while buff:
            self.__socketSender.send(self.__encryptor.encryptBlock(buff))
            buff = f.read(8 * 1024)

        time.sleep(3)

        self.__socketSender.send(b"DONE")
        print("Sending DONE")
        f.close()
