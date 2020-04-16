#!/usr/bin/env python3
# encoding: utf-8
#Imports
import tkinter as tk
from tkinter import ttk, Entry
from code import functions, lambdas
import infoExtractor
from infoExtractor import fase1, fase2, misc
filePath = '../pub/debugs/userlog2.txt'
userLog = lambdas.readDebugs(filePath)

class Application(ttk.Frame):
        def __init__(self, main_window):
            super().__init__(main_window)
            #Windows presets
            main_window.title("CAIDA")
            main_window.columnconfigure(0, weight=1)
            main_window.rowconfigure(0, weight=1)
            main_window.minsize(width=1080, height=650)
            
            #Frame top
            frTop = tk.Frame(self,bg="#f4f7ff",width=120, height=80)
            frTop.grid(row=0, column=0, sticky="nsew",columnspan=3)
            frTop.grid_rowconfigure(0, weight=1)
           
            enImport = tk.Entry(frTop,font=("Georgia", 12))
            enImport.grid(row=0, column=0, sticky="ew", ipady=5, padx=10, ipadx=10)
            frTop.grid_columnconfigure(0, weight=8)
            
            btnImport = tk.Button(frTop, bg="#ffffff", text="Importar", command=functions.UploadAction,font=("Georgia", 12))
            btnImport.grid(row=0, column=1, sticky="ew", ipady=3, padx=10)
            frTop.grid_columnconfigure(1, weight=1)
            
            btnExec = tk.Button(frTop, bg="#ffffff", text="Execute", command=self.run, font=("Georgia", 12))
            btnExec.grid(row=0, column=2, sticky="ew", ipady=3, padx=10)
            frTop.grid_columnconfigure(2, weight=1)
            
            #Frame center left
            self.frCenterLeft = tk.Frame(self,bg="#f4f7ff")
            self.frCenterLeft.grid(row=1, column=0, sticky="nsew")
            self.frCenterLeft.grid_columnconfigure(0, minsize=340, weight=1)
            self.frCenterLeft.grid_propagate(False)

            
            self.lblTitle1 = tk.Label(self.frCenterLeft,bg="#73e8fa", text="Phase 1 Initial Configuration", font=("Georgia", 12))
            self.lblTitle1.grid(row=1, column=0, sticky="nsew", ipady=3, padx=10)
            self.lblTitle1.grid_rowconfigure(1, weight=1)
            self.frCenterLeft.grid_rowconfigure(1, weight=1)

            
            self.lblPhase1 = tk.Label(self.frCenterLeft,bg="#ffffff", text="aqui va la configuracion inicial fase 1", font=("Georgia", 12) )
            self.lblPhase1.grid(row=2, column=0, sticky="nsew", ipady=3, padx=10)
            self.lblPhase1.grid_rowconfigure(2, weight=5)
            self.frCenterLeft.grid_rowconfigure(2, weight=20)


            #Frame center center
            self.frCenter = tk.Frame(self,bg="#f4f7ff")
            self.frCenter.grid(row=1, column=1, sticky="nsew")
            self.frCenter.grid_columnconfigure(1, minsize=340, weight=1)
            self.frCenter.grid_propagate(False)
           
            self.lblTitle0 = tk.Label(self.frCenter,bg="#73e8fa", text="Miscellaneous", font=("Georgia", 12))
            self.lblTitle0.grid(row=1, column=1, sticky="nsew", ipady=3, padx=10)
            self.lblTitle0.grid_rowconfigure(1, weight=1)
            self.frCenter.grid_rowconfigure(1, weight=1)

            
            self.lblPhase0 = tk.Label(self.frCenter,bg="#ffffff", text="miscellaneous things", font=("Georgia", 12))
            self.lblPhase0.grid(row=2, column=1, sticky="nsew", ipady=3, padx=10)
            self.lblPhase0.grid_rowconfigure(2, weight=5)
            self.frCenter.grid_rowconfigure(2, weight=20)


            #Frame center right
            self.frCenterRight = tk.Frame(self,bg="#f4f7ff")
            self.frCenterRight.grid(row=1, column=2, sticky="nsew")
            self.frCenterRight.grid_columnconfigure(2, minsize=340, weight=1)
            self.frCenterRight.grid_propagate(False)
           
            self.lblTitle2 = tk.Label(self.frCenterRight,bg="#73e8fa", text="Phase 2 Initial Configuration", font=("Georgia", 12))
            self.lblTitle2.grid(row=1, column=2, sticky="nsew", ipady=3, padx=10)
            self.lblTitle2.grid_rowconfigure(1, weight=1)
            self.frCenterRight.grid_rowconfigure(1, weight=1)

            self.lblPhase2 = tk.Label(self.frCenterRight,bg="#ffffff", text="aqui va la configuracion inicial fase 3", font=("Georgia", 12))
            self.lblPhase2.grid(row=2, column=2, sticky="nsew", ipady=3, padx=10)
            self.lblPhase2.grid_rowconfigure(2, weight=5)
            self.frCenterRight.grid_rowconfigure(2, weight=20)

            
            #Frame Bot
            
            self.frBot = tk.Frame(self,bg="#f4f7ff")
            self.frBot.grid(row=2, column=0, sticky="nsew",columnspan=3)
            self.frBot.grid_columnconfigure(1, weight=2)
            
            self.lblConf = tk.Label(self.frBot,bg="#ffffff", text="Some Message here", font=("Georgia", 12))            
            self.lblConf.grid(row=2, column=1, sticky="nsew", padx=10, pady=10)
            self.lblConf.grid_rowconfigure(1, weight=5)
            self.frBot.grid_rowconfigure(2, weight=8)

            
            #Frame Footer
            frBotBot = tk.Frame(self,bg="#f4f7ff")
            frBotBot.grid(row=3, column=0, sticky="nsew",columnspan=3)
            frBotBot.grid_rowconfigure(3, weight=1)
            frBotBot.grid_columnconfigure(1, weight=1)
            
            lblMssge = tk.Label(frBotBot,bg="#ffffff", text="Informacion sobre el status de la ejecucion ...",font=("Georgia", 10))
            lblMssge.grid(row=3, column=1, sticky="ew")
            lblMssge.grid_rowconfigure(3, weight=1)

            self.grid(sticky="nsew")
            
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=2)
            self.rowconfigure(1, weight=20)
            self.columnconfigure(1, weight=1)
            self.rowconfigure(2, weight=7)
            self.columnconfigure(2, weight=1)

            
        def run(self):
            #Print phase1, phase2 and misc in Gui
            self.lblPhase1['text'] = '\n'.join('{} {}'.format(k, d) for k, d in fase1.items())
            self.lblPhase0['text'] = '\n'.join('{} {}'.format(k, d) for k, d in misc.items())
            self.lblPhase2['text'] = '\n'.join('{} {}'.format(k, d) for k, d in fase2.items())



main_window = tk.Tk()
app = Application(main_window)
app.mainloop()