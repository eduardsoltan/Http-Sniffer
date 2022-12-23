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
    """
    Opens a package content in platform dependent application
    """

    global treeview

    values = treeview.item(treeview.focus(), 'values')

    if len(values) == 0:
        return
    
    if 'image' in values[1]:
        str1 = "fim -a " + values[0]
    else:
        str1 = "gedit " + values[0]
    os.system(str1)

class dispacherThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        """
        A function that runs periodically taking ready http packages from a global data strucuture and outputting it on the user interface
        """
        global oldVersionHttp
        while True:
            t.event.wait()
            #threading.Timer(1, insertRequest).start()

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
            
            t.event.clear()
def newScreenLook():
    """
    A function that creates new look screen where http packeges will be displayed
    """

    global treeview
    treeview = ttk.Treeview(root)
    columns = ('filename', "type")
    
    treeview.configure(columns = columns, displaycolumns = ())
    treeview.heading("#0", text = "Http Requests")

    treeview.bind("<Double-1>", openFile)

    treeview.pack(fill=tk.BOTH, expand=True)

class thread(threading.Thread):
    """
    Thread will be stared once the sniff button will be pressed. And will implement the main logic of catching in reconstructing internet traffic.
    """

    def __init__(self):
        threading.Thread.__init__(self)
 
    def run(self):
        global httpVerbs
        global input_field

        filterValues = [input_field.get(), httpVerbs]
        t.main(filterValues)

root = tk.Tk()
root.title("Http Sniffer")

content = tk.Frame(root, padx=50, pady=50)

def resizeScreen():
    content.grid_forget()
    thread1 = thread() 

    thread1.start()
    thread3 = dispacherThread()
    thread3.start()

    root.geometry("600x600")
    newScreenLook()
    #insertRequest()

httpVerbs = []
input_field = tk.Entry(content, width = 75)


def buttonClick(verb, column, value):
    """
        Implements logic for selecting http methods for sniffing 
    """

    global httpVerbs
    global content

    if value == 0:
        if verb not in httpVerbs:
            httpVerbs.append(verb)

        put_button = tk.Button(content, text=verb, bg="red", width = 15, command = lambda: buttonClick(verb, column, 1))
        put_button.grid(row = 2, column = column, pady = 10, sticky = "nsew")
    elif value == 1:
        if verb in httpVerbs:
            httpVerbs.remove(verb)

        put_button = tk.Button(content, text=verb, bg="green", width = 15, command = lambda: buttonClick(verb, column, 0))
        put_button.grid(row = 2, column = column, pady = 10, sticky = "nsew")


def createInitailScreen():
    """
        Initial screen user interface
    """

    global root
    global content
    global input_field

    root.grid_rowconfigure(0, weight = 1)
    root.grid_columnconfigure(0, weight = 1)
    content.grid_columnconfigure(0, weight = 1)
    content.grid_columnconfigure(1, weight = 1)
    content.grid_columnconfigure(2, weight = 1)
    content.grid_columnconfigure(3, weight = 1)


    lable = tk.Label(content, text = "Let's sniff some Http Traffic")
    get_button = tk.Button(content, text="GET", bg = "green", width = 15, command = lambda: buttonClick("GET", 0, 0))
    post_button = tk.Button(content, text="POST", bg = "green", width = 15, command = lambda: buttonClick("POST", 1,  0))
    put_button = tk.Button(content, text="PUT", bg = "green", width = 15, command = lambda: buttonClick("PUT", 2, 0))
    delete_button = tk.Button(content, text="DELETE", bg = "green", width = 15, command = lambda: buttonClick("DELTE", 3, 0))
    sniff_button = tk.Button(content, text = "Sniff", width = 15, command=resizeScreen)

    content.grid(row = 0, column = 0, sticky = "nsew")
    lable.grid(row = 0, column = 0, columnspan = 4, pady = 10, sticky = "nsew")
    input_field.grid(row = 1, column = 0, columnspan = 4,pady = 10, sticky = "nsew")
    get_button.grid(row = 2, column = 0, pady = 10, sticky = "nsew")
    post_button.grid(row = 2, column = 1, pady = 10, sticky = "nsew")
    put_button.grid(row = 2, column = 2, pady = 10, sticky = "nsew")
    delete_button.grid(row = 2, column = 3, pady = 10, sticky = "nsew")
    sniff_button.grid(row = 3, column = 1, columnspan = 2, sticky = "nsew")

createInitailScreen()
root.mainloop()