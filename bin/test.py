import tkinter as tk
from tkinter import filedialog

def UploadAction(event=None):
    file = filedialog.askopenfilename(parent=root, title='Choose a file', initialdir="/home/")
    #print('Selected:', filename)
    if file != None:
        pathImp = file
        print (pathImp)
root = tk.Tk()
button = tk.Button(root, text='Open', command=UploadAction)
button.pack()

root.mainloop()


