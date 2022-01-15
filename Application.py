from tkinter import *
from tkinter import font as tkfont
from tkinter import filedialog
import os

from FIleAnalysisOption import PageAnalyzeFile
from Analyzer import Analyzer
from FramePcapAnalysis import FramePcapAnalysis


class Application(Tk):
    def __init__(self):
        super().__init__()
        self.title("BSI")
        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold", slant="italic")


        self.create_widgets()
        # self.geometry("800x600")

        # the same width
        # self.columnconfigure((0, 1, 2), weight=1, uniform='col')
        # self.columnconfigure(0, weight=1, uniform='col')
        # self.columnconfigure(1, weight=1, uniform='col')
        # self.columnconfigure(2, weight=1, uniform='col')

    def create_widgets(self):

        self.frameAppType = Frame(self, width=300)
        self.frameAppType.grid(row=0, column=0)

        container = Frame(self.frameAppType)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, PageAnalyzeFile, PageLiveAnalysis):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame

            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartPage")

        self.framePcapAnalysis = FramePcapAnalysis(self)
        self.framePcapAnalysis.grid(row=0, column=1, sticky="news")

    def show_frame(self, page_name):
        '''Show a frame for the given page name'''
        frame = self.frames[page_name]
        frame.tkraise()

    def draw_alerts_summary(self, alerts_summary):
        self.framePcapAnalysis.refresh_plots(alerts_summary)


class StartPage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        # label = Label(self, text="This is the start page", font=controller.title_font)
        # label.pack(side="top", fill="x", pady=10)

        button1 = Button(self, text="Analyze .PCAP file",
                            command=lambda: controller.show_frame("PageAnalyzeFile"))
        button2 = Button(self, text="Live analysis",
                            command=lambda: controller.show_frame("PageLiveAnalysis"))
        button1.pack()
        button2.pack()


class PageLiveAnalysis(LabelFrame):

    def __init__(self, parent, controller):
        # super().__init__(parent, text="Live analysis")
        LabelFrame.__init__(self, parent, text="Live analysis")
        self.controller = controller
        # label = Label(self, text="This is page 2", font=controller.title_font)
        # label.pack(side="top", fill="x", pady=10)
        button = Button(self, text="Go to the start page",
                           command=lambda: controller.show_frame("StartPage"))
        button.pack()