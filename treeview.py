import tkinter as tk
from tkinter import ttk

root = tk.Tk()

treeview = ttk.Treeview(root)
treeview.pack(fill=tk.BOTH, expand=True)

columns = ('year', 'name', 'month')
treeview.configure(columns=columns)

treeview.heading('year', text = "Year")
treeview.heading('name', text = "Name")
treeview.heading('month', text = "Month")
treeview.heading("#0", text = "hey")

sedan_row = treeview.insert(parent="", index=0, text = "Sedan")

treeview.insert(parent = sedan_row, index=tk.END, values=("Lada", "Sedan", "Baclajan"))

print(sedan_row)
root.mainloop()