#!/usr/bin/env python3
# encoding: utf-8
import csv
readDebugs = lambda file : open("/home/chernoobyle/Música/CAIDA/pub/debugs/"+file, "r").read().split()
csvToDict = lambda file: dict(csv.reader(open("/home/chernoobyle/Música/CAIDA/pub/debugs/"+file, "r")))
cprint = lambda row: print(' '.join([str(elem) for elem in row]))

