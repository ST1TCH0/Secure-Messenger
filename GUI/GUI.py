from socket import *
from tkinter import *
from tkinter.ttk import Progressbar

from Crypto.Random import get_random_bytes

from network.TCP_connect import *
from tkinter import messagebox
from tkinter import filedialog as fd
from utils.Utils import getHW


class AppGUI:

    def __init__(self):
        self.cryptomode = None
        self.__is_quit = False
        self.__is_msg_quit = False
        self.__to_send = False
        self.__fileToAttach = None
        self.__fileToAttachPar = None
        self.__target_address = None
        self.__connect_flag = None

        screen_height, screen_width = getHW()

        btn_w = int(10)
        btn_h = int(1)
        entry_w = int(30)


        __defaultDownloadPath = "E:/Downloads/"

        #
        # GUI construction begin
        #

        self.window = Tk()
        self.window.title("Secure Messenger")
        #self.window.configure(background="gray")

        #self.window.geometry(str(int(screen_width)) + 'x' + str(int(screen_height)) + '-0+0')

        Label(self.window, text="Target IP:").grid(row=0, column=0, sticky='E')
        self.entryIP = Entry(self.window, width=entry_w)
        self.entryIP.insert(0, "192.168.0.32")
        self.entryIP.grid(row=0, column=1)

        self.fileN = StringVar()
        Label(self.window, text="Selected file: ").grid(row=1, column=0, sticky='E')
        Label(self.window, textvariable=self.fileN).grid(row=1, column=1, sticky='E')

        Label(self.window, text="Message:").grid(row=3, column=0, sticky='E')
        self.entryMsg = Entry(self.window, width=entry_w)
        self.entryMsg.grid(row=3, column=1)

        pb = Progressbar(self.window, orient=HORIZONTAL, length=150, mode='determinate')
        pb.grid(row=6, column=3, padx=2, pady=10, sticky='NW', columnspan=2)

        self.connectButton = Button(self.window, text="Connect", command=self.guiConnect, height=btn_h, width=btn_w)
        self.connectButton.grid(row=0, column=3, padx=2, pady=3, sticky='W')
        Button(self.window, text="Browse", command=self.attachFile, height=btn_h, width=btn_w).grid(row=1, column=3, padx=2, pady=3, sticky='W')
        self.sendButton = Button(self.window, text="Send", command=self.guiSend, height=2*btn_h, width=btn_w)
        self.sendButton.grid(row=3, column=3, padx=2, pady=3, rowspan=2, sticky='W')
        Label(self.window, text="Path for downloaded files").grid(row=4, column=0)

        self.__connector = Connector(self.window, pb)

        sv = StringVar()
        sv.trace("w", lambda name, index, mode, sv=sv: self.entryDlCallback(sv))

        self.entryDlPath = Entry(self.window, width=entry_w, textvariable=sv)
        self.entryDlPath.grid(row=4, column=1)
        self.entryDlPath.insert(END, __defaultDownloadPath)
        Button(self.window, text="Quit", command=self.quitApp, height=btn_h, width=btn_w).grid(row=0, column=4, padx=20, pady=3, sticky='E')

        Label(self.window, text="Chat:").grid(row=5, column=0, sticky='SW', padx=3)
        self.textField = Text(self.window, height=10, width=35)
        self.textField.grid(row=6, column=0, columnspan=2, rowspan=2, padx=5, pady=10, sticky='E')
        self.textField.configure(state='disabled')

       # self.consoleField = Text(self.window, height=30, width=30)
        #self.consoleField.grid(column=6, sticky='E')
        #self.consoleField.configure(state="disabled")


        self.selected = StringVar(self.window, 'ECB')
        Radiobutton(self.window, text='CBC', value='CBC', variable=self.selected).grid(row=3, column=4, padx=2, pady=3, sticky='NW')
        Radiobutton(self.window, text='ECB', value='ECB', variable=self.selected).grid(row=4, column=4, padx=2, pady=3, sticky='NW')

        self.info = StringVar()
        Label(self.window, textvariable=self.info).grid(row=5, column=3, sticky='NW', columnspan=2)


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
                    for i in range(35 - len(msg)):
                        msg = (msg + ' ')
                    self.textField.configure(state='normal')
                    self.textField.insert(END, msg)
                    self.textField.configure(state='disabled')

                if self.selected.get() != self.cryptomode:
                    self.cryptomode = self.selected.get()
                    self.__connector.changeMode(self.cryptomode)
                    self.__connector.getSender().setCyphType(self.selected.get())
                    print("mode")
                if not self.__connector.getReciever().getConn():
                    self.sendButton['state'] = DISABLED
                else:
                    self.sendButton['state'] = NORMAL

                pb['value']=receiver.getProgress()

                if receiver.getConn():
                    self.info.set("Connected to {}".format(self.__target_address))
                    self.connectButton['text'] = "Disconnect"
                else:
                    self.info.set("Disconnected")
            if self.window:
                self.window.update()
        self.__connector.getReciever().kill();

    def __del__(self):
        self.window.destroy()
        return

    def entryDlCallback(self, sv):
        self.__connector.getReciever().setDownloadsPath(sv.get())

    def attachFile(self):
        self.__fileToAttach = fd.askopenfilename(
            #filetypes=[("Allowed extensions", ".txt .png .pdf .avi")],
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
        if self.connectButton['text'] == "Connect":
            ip = self.entryIP.get()
            print("Connecting to " + ip)
            self.__target_address = ip
            self.__connector.createSender(ip)
            self.__connect_flag = True
            self.__connector.getReciever().setConFlag(True)
        else:
            print("yo")

            self.__connector.getSocketSender().close()


    def incomingConnection(self):
        res = messagebox.askquestion("Incoming connection", "Accept incoming connection from {}?".format(self.__target_address))
        if res == 'yes':
            self.__connector.getSocketSender().connect((self.__target_address, 54322))
            self.info.set("Connected to {}".format(self.__target_address))
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
            msg = self.entryMsg.get()
            self.__connector.getSender().sendMessage(msg)
            if msg != "":
                for i in range(35-len(msg)):
                    msg = (' ' + msg)
                self.textField.configure(state='normal')
                self.textField.insert(END, msg)
                self.textField.configure(state='disabled')
            self.entryMsg.delete(0, END)
        if self.__fileToAttach:
            self.__connector.getSender().sendFile(self.__fileToAttach)
            self.__fileToAttach = None
            self.fileN.set("")
