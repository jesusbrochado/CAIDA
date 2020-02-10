#!/usr/bin/env python3
# encoding: utf-8
#Imports
from code import lambdas
from code import functions
#Declarations
initiator = lambdas.readDebugs('initiator.txt')
filters = lambdas.csvToDict('filters.csv')
dici = [['\n'+'Your initial configuration is :'+'\n']]
functions.conf_ini(initiator,filters,dici)
for row in dici:
    lambdas.cprint(row)


