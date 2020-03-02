#!/usr/bin/env python3
# encoding: utf-8
from tkinter import filedialog
from code import lambdas
def conf_ini(initiator, filters, dici):
    for key in filters.keys():
        for words in initiator:
            if key in words:
                pos = initiator.index(key)
                dici.append((initiator[pos:pos+int(filters.get(words))]))
                break
    return dici
def test(data):
    data = iter(data)
    while True:
        filtro = next(data)
        pos = next(data)
        yield filtro, pos
       
def UploadAction(event=None):
            file = filedialog.askopenfilename( title='Choose a file', initialdir="/home/")
            #print('Selected:', filename)
            if file != None:
                pathImp = file
                print (pathImp)
                userLog = lambdas.readDebugs(pathImp) # is constant for now!!!
                return userLog
