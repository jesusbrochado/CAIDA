#!/usr/bin/env python3
# encoding: utf-8
import csv
readDebugs = lambda file : open(file, "r").read()
csvToDict = lambda file: dict(csv.reader(open("../pub/debugs/"+file, "r")))
cprint = lambda row: print(' '.join([str(elem) for elem in row]))
