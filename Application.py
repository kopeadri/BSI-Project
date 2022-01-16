from tkinter import *
from tkinter import font as tkfont
import matplotlib
matplotlib.use("TkAgg")

from FIleAnalysisOption import PageAnalyzeFile
from FramePcapAnalysis import FramePcapAnalysis
from RealTimeAnalysisOption import PageLiveAnalysis


class Application(Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analyzer")
        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold", slant="italic")

        self.create_widgets()

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

    def draw_alerts_summary(self, alerts_summary, alerts_df):
        self.framePcapAnalysis.refresh_plots(alerts_summary, alerts_df)


class StartPage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller

        button1 = Button(self, text="Analyze .PCAP file",
                            command=lambda: controller.show_frame("PageAnalyzeFile"))
        button2 = Button(self, text="Live analysis",
                            command=lambda: controller.show_frame("PageLiveAnalysis"))
        button1.pack()
        button2.pack()


