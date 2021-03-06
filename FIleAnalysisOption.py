from tkinter import *
from tkinter import filedialog
import os

from Analyzer import Analyzer


class PageAnalyzeFile(LabelFrame):

    def __init__(self, parent, controller):
        LabelFrame.__init__(self, parent, text="File selection")
        self.controller = controller
        self.file_path = ''

        button = Button(self, text="Go to the start page",
                           command=lambda: controller.show_frame("StartPage"))
        button.pack()

        self.frame_import_file = Frame(self)
        self.frame_import_file.pack()

        self.btn_import = Button(self.frame_import_file, text="Choose file", command=self.import_clicked)
        self.btn_import.grid(row=0, column=0, rowspan=2, sticky=W, padx=(5,5))

        self.sv_file_name = StringVar()
        self.sv_file_name.set('<file_name>')
        self.lbl_file_name = Label(self.frame_import_file, textvariable=self.sv_file_name)
        self.lbl_file_name.grid(row=0, column=1)

        button = Button(self, text="Run analysis", command=self.run_analyzer)
        button.pack()

    def import_clicked(self):
        file_path = filedialog.askopenfilename(initialdir=".", title="Select .PCAP file",
                                              filetypes=((".PCAP file", "*.pcap"),
                                                         ("all files", "*.*")))
        if not file_path:  # dialog canceled
            return
        self.file_path = file_path
        _, file_name = os.path.split(self.file_path)
        self.sv_file_name.set(file_name)

    def run_analyzer(self):
        analyzer = Analyzer(self.file_path)
        alerts_summary, alerts_df = analyzer.run()
        self.controller.draw_alerts_summary(alerts_summary, alerts_df)

