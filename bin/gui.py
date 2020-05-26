#!/usr/bin/env python3
# encoding: utf-8
#Imports
import tkinter as tk
from tkinter import ttk, Entry, filedialog
#from code import functions, lambdas
import functions, lambdas
import infoExtractor
from checkCase import CheckCase
from infoExtractor import extractor
from tkinter import LEFT

class Application(ttk.Frame):
        def __init__(self, main_window):
            super().__init__(main_window)
            #Windows presets
            main_window.title("CAIDA")
            main_window.columnconfigure(0, weight=1)
            main_window.rowconfigure(0, weight=1)
            main_window.minsize(width=1200, height=650)
            main_window['bg']='green'

            
            res = [{}, {}, {}]
            self.fase1 = res[0]
            self.fase2 = res[1]
            self.misc = res[2]

            
            
            
            #Frame top
            frTop = tk.Frame(self,bg="#f4f7ff",width=120, height=80)
            frTop.grid(row=0, column=0, sticky="nsew",columnspan=3)
            frTop.grid_rowconfigure(0, weight=1)
           
            enImport = tk.Entry(frTop,font=("Georgia", 12))
            enImport.grid(row=0, column=0, sticky="ew", ipady=5, padx=10, ipadx=10)
            frTop.grid_columnconfigure(0, weight=8)
            
            btnImport = tk.Button(frTop, bg="#ffffff", text="Save", command=self.exportTxt,font=("Georgia", 12))
            btnImport.grid(row=0, column=1, sticky="ew", ipady=3, padx=10)
            frTop.grid_columnconfigure(1, weight=1)
            
            btnExec = tk.Button(frTop, bg="#ffffff", text="Execute", command=self.run, font=("Georgia", 12))
            btnExec.grid(row=0, column=2, sticky="ew", ipady=3, padx=10)
            frTop.grid_columnconfigure(2, weight=1)
            
            #Frame center left
            
            self.frCenterLeft = tk.Frame(self,bg="#f4f7ff")
            self.frCenterLeft.grid(row=1, column=0, sticky="nesw")
            self.frCenterLeft.grid_rowconfigure(0, weight=1)
            self.frCenterLeft.grid_columnconfigure(0, weight=1)


            self.frCenterLeft.grid_propagate(False)

            self.cvCenterLeft = tk.Canvas(self.frCenterLeft, bg="white")
            self.cvCenterLeft.grid(row=1, column=0, sticky="nsew", padx=(10,0))
            self.cvCenterLeft.grid_rowconfigure(1, weight=1)

            self.sbCenterLeft = tk.Scrollbar(self.frCenterLeft, orient="vertical", command=self.cvCenterLeft.yview, bg="#f4f7ff")
            self.sbCenterLeft.grid(row=1, column=1, sticky="ns", padx=(0,10))
            self.cvCenterLeft.configure(yscrollcommand=self.sbCenterLeft.set)
            

            self.frCenterLeftContent = tk.Frame(self.cvCenterLeft, bg="white")
            self.cvCenterLeft.create_window((0,0), window=self.frCenterLeftContent, anchor="nw")

            self.lblTitle1 = tk.Label(self.frCenterLeft,bg="#73e8fa", text="Phase 1", font=("Georgia", 12))
            self.lblTitle1.grid(row=0, column=0, sticky="nsew", ipady=3, padx=(10,0))
            self.frCenterLeft.grid_rowconfigure(1, weight=5)

            self.lblPhase1 = tk.Label(self.frCenterLeftContent, bg="white", font=("Georgia", 12), justify=LEFT)
            self.lblPhase1.grid(row=1, column=0, sticky="nsew", ipady=3)


            #Frame center center

            self.frCenter = tk.Frame(self,bg="#f4f7ff")
            self.frCenter.grid(row=1, column=1, sticky="nesw")
            self.frCenter.grid_rowconfigure(0, weight=1)
            self.frCenter.grid_columnconfigure(0, weight=1)


            self.frCenter.grid_propagate(False)

            self.cvCenter = tk.Canvas(self.frCenter, bg="white")
            self.cvCenter.grid(row=1, column=0, sticky="nsew")
            self.cvCenter.grid_rowconfigure(1, weight=1)

            self.sbCenter = tk.Scrollbar(self.frCenter, orient="vertical", command=self.cvCenter.yview, bg="#f4f7ff")
            self.sbCenter.grid(row=1, column=1, sticky="ns", padx=(0,10))
            self.cvCenter.configure(yscrollcommand=self.sbCenter.set)
            

            self.frCenterContent = tk.Frame(self.cvCenter, bg="white")
            self.cvCenter.create_window((0,0), window=self.frCenterContent, anchor="nw")

            self.lblTitle2 = tk.Label(self.frCenter,bg="#73e8fa", text="Phase 2", font=("Georgia", 12))
            self.lblTitle2.grid(row=0, column=0, sticky="nsew", ipady=3)
            self.frCenter.grid_rowconfigure(1, weight=5)

            self.lblPhase2 = tk.Label(self.frCenterContent, bg="white", font=("Georgia", 12), justify=LEFT)
            self.lblPhase2.grid(row=1, column=0, sticky="nsew", ipady=3)


            #Frame center right
            self.frCenterRight = tk.Frame(self,bg="#f4f7ff")
            self.frCenterRight.grid(row=1, column=2, sticky="nesw")
            self.frCenterRight.grid_rowconfigure(0, weight=1)
            self.frCenterRight.grid_columnconfigure(0, weight=1)

            self.frCenterRight.config(highlightbackground="white")

            self.frCenterRight.grid_propagate(False)

            self.cvCenterRight = tk.Canvas(self.frCenterRight, bg="white")
            self.cvCenterRight.grid(row=1, column=0, sticky="nsew")
            self.cvCenterRight.grid_rowconfigure(1, weight=1)

            self.sbCenterRight = tk.Scrollbar(self.frCenterRight, orient="vertical", command=self.cvCenterRight.yview, bg="#f4f7ff")
            self.sbCenterRight.grid(row=1, column=1, sticky="ns", padx=(0,10))
            self.cvCenterRight.configure(yscrollcommand=self.sbCenterRight.set)
            

            self.frCenterRightContent = tk.Frame(self.cvCenterRight, bg="white")
            self.cvCenterRight.create_window((0,0), window=self.frCenterRightContent, anchor="nw")

            self.lblTitle0 = tk.Label(self.frCenterRight,bg="#73e8fa", text="Misc", font=("Georgia", 12))
            self.lblTitle0.grid(row=0, column=0, sticky="nsew", ipady=3)
            self.frCenterRight.grid_rowconfigure(1, weight=5)

            self.lblPhase0 = tk.Label(self.frCenterRightContent, bg="white", font=("Georgia", 12), justify=LEFT)
            self.lblPhase0.grid(row=1, column=1, sticky="nsew", ipady=3)
          
            
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
            
            lblMssge = tk.Label(frBotBot,bg="#ffffff", text="Place holder",font=("Georgia", 10))
            lblMssge.grid(row=3, column=1, sticky="ew")
            lblMssge.grid_rowconfigure(3, weight=1)

            self.grid(sticky="nsew")
            
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=5)
            self.rowconfigure(1, weight=20)
            self.columnconfigure(1, weight=1)
            self.rowconfigure(2, weight=7)
            self.columnconfigure(2, weight=1)

        def exportTxt(self):
            ftypes = [('Postscript files', '.txt'), ('All files', '*')]
            filePath = filedialog.asksaveasfilename(initialfile = 'caida-output',filetypes=ftypes, defaultextension='.txt')
            f= open(filePath,"w+")

            f.write("======================================== \n==== Phase 1 \n========================================\n")
            f.write('\n'.join('{} {}'.format(k, d) for k, d in self.fase1.items()))
            f.write("\n\n======================================== \n==== Phase 2 \n========================================\n")
            f.write('\n'.join('{} {}'.format(k, d) for k, d in self.misc.items()))
            f.write("\n\n======================================== \n==== Misc \n========================================\n")
            f.write('\n'.join('{} {}'.format(k, d) for k, d in self.fase2.items()))
            f.close()

        def run(self):
            filePath = filedialog.askopenfilename()
            mess = CheckCase(filePath).extractInfo()
            res = extractor(filePath)
            self.fase1 = res[0]
            self.fase2 = res[1]
            self.misc = res[2]
            


            #Print phase1, phase2 and misc in Gui
            self.lblPhase1['text'] = '\n'.join('{} {}'.format(k, d) for k, d in self.fase1.items())
            self.lblPhase0['text'] = '\n'.join('{} {}'.format(k, d) for k, d in self.misc.items())
            self.lblPhase2['text'] = '\n'.join('{} {}'.format(k, d) for k, d in self.fase2.items())
            self.lblConf['text'] = mess

main_window = tk.Tk()
app = Application(main_window)
app.mainloop()