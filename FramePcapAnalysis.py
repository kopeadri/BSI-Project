from tkinter import *
from tkinter import LabelFrame
from tkinter import ttk
import matplotlib
import pandas as pd

matplotlib.use("TkAgg")
from matplotlib import pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends._backend_tk import NavigationToolbar2Tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

LARGE_FONT= ("Verdana", 12)

class FramePcapAnalysis(LabelFrame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master, text=".PCAP Analysis", width=100, height=700, *args, **kwargs)


        self.categories = {}
        self.signature = {}
        self.severity = {}
        self.alerts_df = pd.DataFrame()


        container = Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)


        self.frames = {}

        for F in (StartPage, PageCategoryPieChart, PageSeverityPieChart, PageSummary):  # tu trzeba dodac każde nowe okienko
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(StartPage)


    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

    def refresh_plots(self, alerts_summary, alerts_df):
        self.categories = alerts_summary['categories']
        self.signature = alerts_summary['signature']
        self.severity = alerts_summary['severity']
        self.alerts_df = alerts_df
        for f in self.frames:
            self.frames[f].redraw()



class StartPage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        label = Label(self, text="Start Page", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        button3 = Button(self, text="See Alerts per Category",
                         command=lambda: controller.show_frame(PageCategoryPieChart))
        button3.pack()

        button4 = Button(self, text="See Alerts per Severity",
                         command=lambda: controller.show_frame(PageSeverityPieChart))
        button4.pack()

        button5 = Button(self, text="See Alerts Summary",
                             command=lambda: controller.show_frame(PageSummary))
        button5.pack()

    def redraw(self):
        pass

class PageCategoryPieChart(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        label = Label(self, text="Alerts per Category", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        self.controller = controller

        button1 = Button(self, text="Back to Home", command=lambda: controller.show_frame(StartPage))
        button1.pack()

        button2 = Button(self, text="See Alerts per Severity",
                         command=lambda: controller.show_frame(PageSeverityPieChart))
        button2.pack()

        button3 = Button(self, text="See Alerts Summary",
                             command=lambda: controller.show_frame(PageSummary))
        button3.pack()

        # self.labels = list(controller.categories.keys()) #categories
        # self.sizes = list(controller.categories.values()) #categories_counts

        self.fig = Figure(dpi=100) #figsize=(width, height)
        self.plot_axes_categories = self.fig.add_subplot(111)

        # self.fig.tight_layout()

        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=BOTTOM, fill=BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(self.canvas, self)  # na dole wykresu
        toolbar.update()
        self.canvas._tkcanvas.pack(side=TOP, fill=BOTH, expand=True)

        self.redraw()

    def redraw(self):
        # f, a = plt.subplots()
        # a.pie(self.sizes, labels=self.labels, autopct='%1.1f%%', shadow=False, startangle=90)
        # a.axis('equal')

        self.labels = list(self.controller.categories.keys())#categories
        self.sizes = list(self.controller.categories.values())#categories_counts
        self.plot_axes_categories.pie(self.sizes, labels=self.labels, autopct='%1.1f%%', shadow=False, startangle=90)

        self.canvas.draw()

    def tkraise(self, aboveThis=None):
        # Get a reference to StartPage
        # start_page = self.controller.frames['StartPage']

        # Get the selected item from start_page
        # self.label.configure(text=start_page.getvalue())
        self.redraw()
        # Call the real .tkraise
        super().tkraise(aboveThis)


class PageSeverityPieChart(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        label = Label(self, text="Alerts per Severity", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        self.controller = controller

        button1 = Button(self, text="Back to Home", command=lambda: controller.show_frame(StartPage))
        button1.pack()

        button2 = Button(self, text="See Alerts per Category",
                         command=lambda: controller.show_frame(PageCategoryPieChart))
        button2.pack()

        button3 = Button(self, text="See Alerts Summary",
                             command=lambda: controller.show_frame(PageSummary))
        button3.pack()

        # labels = severities
        # sizes = severities_counts

        labels = list(controller.severity.keys())#categories
        sizes = list(controller.severity.values())#categories_counts

        # f, a = plt.subplots()
        # a.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=False, startangle=90)
        # a.axis('equal')
        #


        self.fig = Figure(dpi=100) #figsize=(width, height)
        self.plot_axes = self.fig.add_subplot(111)

        # self.fig.tight_layout()

        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=BOTTOM, fill=BOTH, expand=True)

        #
        # canvas = FigureCanvasTkAgg(f, self)
        # canvas.draw()
        # canvas.get_tk_widget().pack(side=BOTTOM, fill=BOTH, expand=True)

        toolbar = NavigationToolbar2Tk(self.canvas, self)  # na dole wykresu
        toolbar.update()
        self.canvas._tkcanvas.pack(side=TOP, fill=BOTH, expand=True)

        self.redraw() # needed?

    def redraw(self):
        # f, a = plt.subplots()
        # a.pie(self.sizes, labels=self.labels, autopct='%1.1f%%', shadow=False, startangle=90)
        # a.axis('equal')

        self.labels = list(self.controller.severity.keys())#categories
        self.sizes = list(self.controller.severity.values())#categories_counts
        self.plot_axes.pie(self.sizes, labels=self.labels, autopct='%1.1f%%', shadow=False, startangle=90)

        self.canvas.draw() #?

class PageSummary(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        label = Label(self, text="Summary of Alerts", font=LARGE_FONT)
        label.pack(pady=10, padx=10)

        self.controller = controller

        button1 = Button(self, text="Back to Home", command=lambda: controller.show_frame(StartPage))
        button1.pack()

        button2 = Button(self, text="See Alerts per Category",
                         command=lambda: controller.show_frame(PageCategoryPieChart))
        button2.pack()

        button3 = Button(self, text="See Alerts per Severity",
                         command=lambda: controller.show_frame(PageSeverityPieChart))
        button3.pack()

        # columns = ['Category', 'Signatures','Severity']

        ## Treeview Widget
        self.tv1 = ttk.Treeview(self)

        treescrolly = Scrollbar(self, orient="vertical",
                                   command=self.tv1.yview)  # command means update the yaxis view of the widget
        treescrollx = Scrollbar(self, orient="horizontal",
                                   command=self.tv1.xview)  # command means update the xaxis view of the widget
        self.tv1.configure(xscrollcommand=treescrollx.set,
                      yscrollcommand=treescrolly.set)  # assign the scrollbars to the Treeview Widget
        treescrollx.pack(side="bottom", fill="x")  # make the scrollbar fill the x axis of the Treeview widget
        treescrolly.pack(side="right", fill="y")  # make the scrollbar fill the y axis of the Treeview widget

        # print(self.controller.alerts_df.columns.values)
        # if 'alert.metadata.created_at' not in self.controller.alerts_df.columns.values:
        #     return
        self.columns = ['alert.metadata.created_at', 'alert.category',  'alert.severity', 'http.hostname', 'http.url']

        # data_sec = self.controller.alerts_df
        # data_alerts_only = self.controller.alerts_df.loc[self.controller.alerts_df['alert.metadata.created_at'].notnull(), ['alert.metadata.created_at', 'alert.category',
        #                                                       'alert.severity', 'http.hostname', 'http.url']]
        # print(data_alerts_only)
        # df = data_alerts_only
        #
        self.tv1.delete(*self.tv1.get_children())
        self.tv1["columns"] = self.columns #list(df.columns)

        for column in self.columns:
            self.tv1.heading(column, text=column)  # let the column heading = column name

        self.tv1.pack(side=TOP, fill=BOTH, expand=True)


    def redraw(self):
        print(self.controller.alerts_df.columns.values)
        if 'alert.category' not in self.controller.alerts_df:  # alerts are flattened here
            return
        df_rows = self.controller.alerts_df[self.columns].to_numpy().tolist()
        self.tv1.delete(*self.tv1.get_children())
        for row in df_rows:
            self.tv1.insert("", "end", values=row)


