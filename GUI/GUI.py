from socket import *
from tkinter import *

from Crypto.Random import get_random_bytes

from network.TCP_connect import *
from tkinter import messagebox
from tkinter import filedialog as fd
from utils.Utils import getHW


class AppGUI:

    def __init__(self):

        self.__is_quit = False
        self.__is_msg_quit = False
        self.__to_send = False
        self.__fileToAttach = None
        self.__fileToAttachPar = None
        self.__target_address = None
        self.__connect_flag = None
        screen_height, screen_width = getHW()

        btn_w = int(screen_width / 100)
        btn_h = int(screen_height / 500)
        entry_w = int(screen_width / 25)

        self.__connector = Connector()
        __defaultDownloadPath = "E:/Downloads/"

        #
        # GUI construction begin
        #

        self.window = Tk()
        self.window.title("Secure Messenger")
        #self.window.configure(background="gray")

        self.window.geometry(str(int(screen_width)) + 'x' + str(int(screen_height)) + '-0+0')

        Label(self.window, text="Target IP:").grid(row=0, column=0, sticky='E')
        self.entryIP = Entry(self.window, width=entry_w)
        self.entryIP.insert(0, "25.70.194.69")
        self.entryIP.grid(row=0, column=1)

        self.fileN = StringVar()
        Label(self.window, text="Selected file: ").grid(row=1, column=0, sticky='E')
        Label(self.window, textvariable=self.fileN).grid(row=1, column=1, sticky='E')

        Label(self.window, text="Message:").grid(row=3, column=0, sticky='E')
        self.entryMsg = Entry(self.window, width=entry_w)
        self.entryMsg.grid(row=3, column=1)

        Button(self.window, text="Connect", command=self.guiConnect, height=btn_h, width=btn_w).grid(row=0, column=3, padx=2, pady=3, sticky='W')
        Button(self.window, text="Browse", command=self.attachFile, height=btn_h, width=btn_w).grid(row=1, column=3, padx=2, pady=3, sticky='W')
        Button(self.window, text="Send", command=self.guiSend, height=btn_h, width=btn_w).grid(row=3, column=3, padx=2, pady=3, rowspan=2)
        Label(self.window, text="Path for downloaded files").grid(row=4, column=0)
        sv = StringVar()
        sv.trace("w", lambda name, index, mode, sv=sv: self.entryDlCallback(sv))
        self.entryDlPath = Entry(self.window, width=entry_w, textvariable=sv)
        self.entryDlPath.grid(row=4, column=1)
        self.entryDlPath.insert(END, __defaultDownloadPath)
        Button(self.window, text="Quit", command=self.quitApp, height=btn_h, width=btn_w).grid(row=0, column=4, padx=20, pady=3, sticky='E')

        Label(self.window, text="Chat:").grid(row=5, column=0, sticky='SW', padx=3)
        self.textField = Text(self.window, height=10, width=25)
        self.textField.grid(row=6, column=0, columnspan=2, rowspan=2, padx=5, pady=3)
        #self.textField.configure(state="disabled")

        self.consoleField = Text(self.window, height=30, width=30)
        self.consoleField.grid(column=6, sticky='E')
        #self.consoleField.configure(state="disabled")

        self.info = StringVar()
        Label(self.window, textvariable=self.info).grid(row=5, column=3, sticky='NW')

        #
        # GUI construction end
        #

        #
        # Main maintenance loop
        #

        while not self.__is_quit:
            if self.__connector:
                receiver = self.__connector.getReciever()
                if receiver.getAddress() and not self.__connect_flag:
                    self.__target_address = receiver.getAddress()[0]
                    receiver.setAddress(None)
                    self.incomingConnection()
                msg = receiver.getMsgToShow()
                if msg:
                    msg = msg + '\n'
                    self.textField.insert(END, msg)
            if self.window:
                self.window.update()

    def __del__(self):
        self.window.destroy()
        return

    def entryDlCallback(self, sv):
        self.__connector.getReciever().setDownloadsPath(sv.get())

    def attachFile(self):
        self.__fileToAttach = fd.askopenfilename(
            title='Select file',
            initialdir='/')

        if len(self.__fileToAttach) > 20:
            name = ('..' + self.__fileToAttach[len(self.__fileToAttach) - 20:])
        else:
            name = self.__fileToAttach

        self.fileN.set(name)

    def quitApp(self):
        self.__is_quit = True
        self.__del__()

    def guiConnect(self):
        ip = self.entryIP.get()
        print("Connecting to " + ip)
        self.__connector.createSender(ip)
        self.__connect_flag = True
        self.__connector.getReciever().setConFlag(True)

    def incomingConnection(self):
        res = messagebox.askquestion("Incoming connection", "Accept incoming connection from {}?".format(self.__target_address))
        if res == 'yes':
            self.__connector.getSocketSender().connect((self.__target_address, 54322))
            self.info.set("connected to {}".format(self.__target_address))
            while not self.__connector.getReciever().enKey:
                self.window.update()
            print("sss")
            self.__connector.getSocketSender().send(self.__connector.getReciever().enKey)
            self.__connector.getReciever().connected = True

        elif res == 'no':
            receiver = self.__connector.getReciever()
            receiver.getConn().close()
            receiver.setAddress(None)
        else:
            messagebox.showwarning('error', 'Something went wrong!')

    def guiSend(self):
        if self.entryMsg.get():
            self.__connector.getSender().sendMessage(self.entryMsg.get())
            self.entryMsg.delete(0, END)
        if self.__fileToAttach:
            self.__connector.getSender().sendFile(self.__fileToAttach)
            self.__fileToAttach = None
            self.fileN.set("")
