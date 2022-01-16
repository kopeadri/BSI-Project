from tkinter import *
import threading
from RealTimeAnalyzer import RealTimeAnalyzer
from matplotlib.figure import Figure
from matplotlib import pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class PageLiveAnalysis(LabelFrame):

    def __init__(self, parent, controller):
        LabelFrame.__init__(self, parent, text="Live analysis")
        self.controller = controller

        button = Button(self, text="Go to the start page",
                        command=lambda: controller.show_frame("StartPage"))
        button.pack()

        frame_interface = Frame(self)
        frame_interface.pack(side=TOP)

        lbl_interface = Label(frame_interface, text="Network Interface: ")
        lbl_interface.pack(side=LEFT)
        self.sv_interface = StringVar()
        self.sv_interface.set("Wi-Fi")
        ent_interface = Entry(frame_interface, textvariable=self.sv_interface)
        ent_interface.pack(side=LEFT)

        self.sv_run_stop = StringVar()
        self.sv_run_stop.set("Run analysis")
        btn_run = Button(self, textvariable=self.sv_run_stop, command=self.run_analyzer)  # threading.Thread(target=self.run_analyzer).start
        btn_run.pack()

        self.fig = Figure(dpi=100) #figsize=(width, height)
        self.plot_axes = self.fig.add_subplot(111)
        self.reset_plot()

        # self.fig, self.plot_axes = plt.subplots(111)
        # self.plot_axes = plt.subplots(111)

        # plt.rcParams["keymap.quit"] = "cmd+w", "q"
        # plt.ion()  # Interactive Mode
        # plt.show()
        # plt.ylabel("Bytes")  # Labels
        # plt.xlabel("Number of packets")
        # plt.title("Real time Network Traffic")
        # plt.tight_layout()
        # plt.pause(0.5)

        # self.fig.tight_layout()

        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=BOTTOM, fill=BOTH, expand=True)


    def reset_plot(self):
        self.plot_axes.cla()
        self.plot_axes.set_title("Real time Network Traffic")
        self.plot_axes.set_xlabel("Number of packets")
        self.plot_axes.set_ylabel("Bytes")
        # self.plot_axes.set_xticks(range(1,51,5))

    def run_analyzer(self):
        btn_run_stop_text = self.sv_run_stop.get()
        if btn_run_stop_text == "Run analysis":
            plt.ion()
            self.sv_run_stop.set("Stop")
            self.reset_plot()
            self.analyzer = RealTimeAnalyzer(self.sv_interface.get(), 0, self.plot_axes, self.canvas, self.controller)
            # alerts_summary, alerts_df = self.analyzer.monitor_network()
            threading.Thread(target=self.analyzer.monitor_network).start()
        else:
            plt.ioff()
            self.analyzer.stop()
            self.sv_run_stop.set("Run analysis")



        # analyzer = Analyzer(self.file_path)

        # self.controller.draw_alerts_summary(alerts_summary, alerts_df)


