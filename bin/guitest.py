#!/usr/bin/env python3
# encoding: utf-8
#Imports
import tkinter as tk
from tkinter import ttk, Entry
from code import functions, lambdas
import cai
from cai import iconfig
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
            frCenterLeft = tk.Frame(self,bg="#f4f7ff")
            frCenterLeft.grid(row=1, column=0, sticky="nsew")
            frCenterLeft.grid_columnconfigure(0, weight=1)
            
            lblTitle1 = tk.Label(frCenterLeft,bg="#73e8fa", text="Phase 1 Initial Configuration", font=("Georgia", 12))
            lblTitle1.grid(row=1, column=0, sticky="nsew", ipady=3, padx=10)
            lblTitle1.grid_rowconfigure(1, weight=1)
            frCenterLeft.grid_rowconfigure(1, weight=1)

            
            lblPhase1 = tk.Label(frCenterLeft,bg="#ffffff", text="aqui va la configuracion inicial fase 1", font=("Georgia", 12) )
            lblPhase1.grid(row=2, column=0, sticky="nsew", ipady=3, padx=10)
            lblPhase1.grid_rowconfigure(2, weight=5)
            frCenterLeft.grid_rowconfigure(2, weight=20)

            #Frame center center
            frCenter = tk.Frame(self,bg="#f4f7ff")
            frCenter.grid(row=1, column=1, sticky="nsew")
            frCenter.grid_columnconfigure(1, weight=1)
            
            lblTitle0 = tk.Label(frCenter,bg="#73e8fa", text="Phase 2 Initial Configuration", font=("Georgia", 12))
            lblTitle0.grid(row=1, column=1, sticky="nsew", ipady=3, padx=10)
            lblTitle0.grid_rowconfigure(1, weight=1)
            frCenter.grid_rowconfigure(1, weight=1)

            
            lblPhase0 = tk.Label(frCenter,bg="#ffffff", text="aqui va la configuracion inicial fase 2", font=("Georgia", 12))
            lblPhase0.grid(row=2, column=1, sticky="nsew", ipady=3, padx=10)
            lblPhase0.grid_rowconfigure(2, weight=5)
            frCenter.grid_rowconfigure(2, weight=20)


            #Frame center right
            frCenterRight = tk.Frame(self,bg="#f4f7ff")
            frCenterRight.grid(row=1, column=2, sticky="nsew")
            frCenterRight.grid_columnconfigure(2, weight=1)
            
            lblTitle2 = tk.Label(frCenterRight,bg="#73e8fa", text="Phase 3 Initial Configuration", font=("Georgia", 12))
            lblTitle2.grid(row=1, column=2, sticky="nsew", ipady=3, padx=10)
            lblTitle2.grid_rowconfigure(1, weight=1)
            frCenterRight.grid_rowconfigure(1, weight=1)

            
            lblPhase2 = tk.Label(frCenterRight,bg="#ffffff", text="aqui va la configuracion inicial fase 3", font=("Georgia", 12))
            lblPhase2.grid(row=2, column=2, sticky="nsew", ipady=3, padx=10)
            lblPhase2.grid_rowconfigure(2, weight=5)
            frCenterRight.grid_rowconfigure(2, weight=20)
            
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
            #call the `main` function defined in the other file
            #cai.main(userLog)
            print(iconfig)
            for row in iconfig:
                self.lblConf['text'] = row


main_window = tk.Tk()
app = Application(main_window)
app.mainloop()
