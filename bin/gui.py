#!/usr/bin/env python3
# encoding: utf-8
#Imports
import tkinter as tk
from tkinter import ttk, Entry
from code import functions
class Application(ttk.Frame):
        def __init__(self, main_window):
            super().__init__(main_window)
            #Windows presets
            main_window.title("CAIDA")
            main_window.columnconfigure(0, weight=1)
            main_window.rowconfigure(0, weight=1)
            main_window.geometry('{}x{}'.format(720, 480))
            
            #Frame top
            frTop = tk.Frame(self,bg="#f0ff00")
            frTop.grid(row=0, column=0, sticky="nsew",columnspan=3)
            frTop.grid_rowconfigure(0, weight=1)
          
            enImport = tk.Entry(frTop)
            enImport.grid(row=0, column=0, sticky="ew", ipady=5, padx=10)
            frTop.grid_columnconfigure(0, weight=8)
            
            btnImport = tk.Button(frTop, bg="#96989A", text="Importar", command=functions.UploadAction)
            btnImport.grid(row=0, column=1, sticky="ew", ipady=3, padx=10)
            frTop.grid_columnconfigure(1, weight=1)
            
            btnExec = tk.Button(frTop, bg="#96989A", text="Execute", command=functions.UploadAction)
            btnExec.grid(row=0, column=2, sticky="ew", ipady=3, padx=10)
            frTop.grid_columnconfigure(2, weight=1)
            
            #Frame center left
            frCenterLeft = tk.Frame(self,bg="#000000")
            frCenterLeft.grid(row=1, column=0, sticky="nsew")
            frCenterLeft.grid_columnconfigure(0, weight=1)
            
            lblTitle1 = tk.Label(frCenterLeft,bg="#fdfefe", text="Phase 1 Initial Configuration")
            lblTitle1.grid(row=1, column=0, sticky="nsew", ipady=3, padx=10, pady=10)
            lblTitle1.grid_rowconfigure(1, weight=1)
            frCenterLeft.grid_rowconfigure(1, weight=1)

            
            lblPhase1 = tk.Label(frCenterLeft,bg="#96989A", text="aqui va la configuracion inicial fase 1" )
            lblPhase1.grid(row=2, column=0, sticky="nsew", ipady=3, padx=10)
            lblPhase1.grid_rowconfigure(2, weight=5)
            frCenterLeft.grid_rowconfigure(2, weight=8)

            #Frame center center
            frCenter = tk.Frame(self,bg="#c0a2fd")
            frCenter.grid(row=1, column=1, sticky="nsew")
            frCenter.grid_columnconfigure(1, weight=1)
            
            lblTitle0 = tk.Label(frCenter,bg="#fdfefe", text="Phase 2 Initial Configuration")
            lblTitle0.grid(row=1, column=1, sticky="nsew", ipady=3, padx=10, pady=10)
            lblTitle0.grid_rowconfigure(1, weight=1)
            frCenter.grid_rowconfigure(1, weight=1)

            
            lblPhase0 = tk.Label(frCenter,bg="#96989A", text="aqui va la configuracion inicial fase 2" )
            lblPhase0.grid(row=2, column=1, sticky="nsew", ipady=3, padx=10)
            lblPhase0.grid_rowconfigure(2, weight=5)
            frCenter.grid_rowconfigure(2, weight=8)


            #Frame center right
            frCenterRight = tk.Frame(self,bg="#000000")
            frCenterRight.grid(row=1, column=2, sticky="nsew")
            frCenterRight.grid_columnconfigure(2, weight=1)
            
            lblTitle2 = tk.Label(frCenterRight,bg="#fdfefe", text="Phase 3 Initial Configuration")
            lblTitle2.grid(row=1, column=2, sticky="nsew", ipady=3, padx=10, pady=10)
            lblTitle2.grid_rowconfigure(1, weight=1)
            frCenterRight.grid_rowconfigure(1, weight=1)

            
            lblPhase2 = tk.Label(frCenterRight,bg="#96989A", text="aqui va la configuracion inicial fase 3" )
            lblPhase2.grid(row=2, column=2, sticky="nsew", ipady=3, padx=10)
            lblPhase2.grid_rowconfigure(2, weight=5)
            frCenterRight.grid_rowconfigure(2, weight=8)
            
            #Frame Bot
            frBot = tk.Frame(self,bg="#fda2c0")
            frBot.grid(row=2, column=0, sticky="nsew",columnspan=3)
            frBot.grid_columnconfigure(1, weight=1)
            
            lblConf = tk.Label(frBot,bg="#00ffd8", text="Some Message here")
            lblConf.grid(row=2, column=1, sticky="nsew", padx=10, pady=10)
            lblConf.grid_rowconfigure(1, weight=5)
            frBot.grid_rowconfigure(2, weight=8)

            
            #Frame Bot Bot
            frBotBot = tk.Frame(self,bg="#f0ff00")
            frBotBot.grid(row=3, column=0, sticky="nsew",columnspan=3)
            frBotBot.grid_rowconfigure(3, weight=1)
            frBotBot.grid_columnconfigure(1, weight=1)
            
            lblConf = tk.Label(frBotBot,bg="#fdfefe", text="Some Message here")
            lblConf.grid(row=3, column=1, sticky="ew", padx=10)
            lblConf.grid_rowconfigure(3, weight=1)

            self.grid(sticky="nsew")
            
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=2)
            self.rowconfigure(1, weight=20)
            self.columnconfigure(1, weight=1)
            self.rowconfigure(2, weight=7)
            self.columnconfigure(2, weight=1)

            

            

main_window = tk.Tk()
app = Application(main_window)
app.mainloop()
