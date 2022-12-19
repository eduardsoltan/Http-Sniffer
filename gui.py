import tkinter as tk
from tkinter import ttk
import test as t
import threading
import time
import os

oldVersionHttp = []


def getHeaderValue1(headers, headerValue):
    splitHeaders = headers.split("\r\n")

    val = ""
    for header in splitHeaders:
        if headerValue in header:
            val = header[len(headerValue) + 1:]
    return val.strip()


def openFile(e):
    global treeview

    values = treeview.item(treeview.focus(), 'values')

    if len(values) == 0:
        return
    
    if 'image' in values[1]:
        str1 = "fim -a " + values[0]
    else:
        str1 = "gedit " + values[0]
    os.system(str1)

def insertRequest():
    global oldVersionHttp
    threading.Timer(1, insertRequest).start()

    if len(oldVersionHttp) == len(t.httpPackets):
        return
    
    for httpPacket in range(len(oldVersionHttp), len(t.httpPackets), 1):
        if t.httpPackets[httpPacket] in oldVersionHttp:
            return

        oldVersionHttp.append(t.httpPackets[httpPacket])
        splitHeaders = t.httpPackets[httpPacket][0].split("\r\n")
        row_index = treeview.insert(parent = "", index = tk.END, text = splitHeaders[0])

        contentType = getHeaderValue1(t.httpPackets[httpPacket][0], 'Content-Type')
        for header in splitHeaders:
            treeview.insert(parent = row_index, index= tk.END, text=header)
        
        if len(t.httpPackets[httpPacket][1]) > 0:
            previewCont = treeview.insert(parent = row_index, index = tk.END, text = "Preview Content", values = (t.httpPackets[httpPacket][1], contentType))

def newScreenLook():
    global treeview
    treeview = ttk.Treeview(root)
    columns = ('filename', "type")
    
    treeview.configure(columns = columns, displaycolumns = ())
    treeview.heading("#0", text = "Http Requests")


    treeview.bind("<Double-1>", openFile)

    treeview.pack(fill=tk.BOTH, expand=True)

class thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
 
    def run(self):
        global httpVerbs

        httpVerbs = [bytes(a, 'utf-8') for a in httpVerbs]
        t.main(httpVerbs)

root = tk.Tk()
root.title("Http Sniffer")

content = tk.Frame(root, padx=50, pady=50)

def resizeScreen():
    content.grid_forget()
    thread1 = thread() 

    thread1.start()
    root.geometry("600x600")
    newScreenLook()
    insertRequest()

httpVerbs = []

def buttonClick(verb, column, value):
    global httpVerbs
    if value == 0:
        if verb not in httpVerbs:
            httpVerbs.append(verb)

        put_button = tk.Button(content, text=verb, bg="red", width = 15, command = lambda: buttonClick(verb, column, 1))
        put_button.grid(row = 2, column = column, pady = 10)
    elif value == 1:
        if verb in httpVerbs:
            httpVerbs.remove(verb)

        put_button = tk.Button(content, text=verb, bg="green", width = 15, command = lambda: buttonClick(verb, column, 0))
        put_button.grid(row = 2, column = column, pady = 10)


lable = tk.Label(content, text = "Let's sniff some Http Traffic")
input_field = tk.Entry(content, width = 75)
get_button = tk.Button(content, text="GET", bg = "green", width = 15, command = lambda: buttonClick("GET", 0, 0))
post_button = tk.Button(content, text="POST", bg = "green", width = 15, command = lambda: buttonClick("POST", 1,  0))
put_button = tk.Button(content, text="PUT", bg = "green", width = 15, command = lambda: buttonClick("PUT", 2, 0))
delete_button = tk.Button(content, text="DELETE", bg = "green",  width = 15, command = lambda: buttonClick("DELTE", 3, 0))
sniff_button = tk.Button(content, text = "Sniff", width = 15, command=resizeScreen)

content.grid(row = 0, column = 0)
lable.grid(row = 0, column = 0, columnspan = 4, pady = 10)
input_field.grid(row = 1, column = 0, columnspan = 4,pady = 10)
get_button.grid(row = 2, column = 0, pady = 10)
post_button.grid(row = 2, column = 1, pady = 10)
put_button.grid(row = 2, column = 2, pady = 10)
delete_button.grid(row = 2, column = 3, pady = 10)
sniff_button.grid(row = 3, column = 1, columnspan = 2)

root.mainloop()