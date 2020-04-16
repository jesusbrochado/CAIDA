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

def checkNotFound(log):
    try:
        if not (log is None):
            return log.group(1)
        else:
            return "Not found"
    except Exception as e:
        if (e == 'NoneType'):
            return "Not Found"

def checkNotFoundArray(array):
    try:
        if(len(array) != 0):
            return array
        else:
            return "Not found"
    except Exception as e:
        if (e == 'NoneType'):
            return "Not Found"
            
def UploadAction(event=None):
    filename = filedialog.askopenfilename()
    print('Selected:', filename)