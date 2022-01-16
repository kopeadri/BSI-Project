from SuricateAnalyzer import SuricateAnalyzer
from scapy.all import *
import Analyzer


class RealTimeAnalyzer:
    def __init__(self, interface, n_packets, plot_axes, canvas, controller):
        self.controller = controller
        self.interface = interface
        self.n_packets = n_packets
        self.result_dir = "\Results\Real-time"
        self.suricate_analyzer = SuricateAnalyzer('temp.pcap', 'real-time', Analyzer.get_suricata_install_dir())
        self.plot_axes = plot_axes
        self.is_running = False
        self.canvas = canvas

    def check_interface(self):
        try:
            print("--Trying to listen on {}".format(self.interface))
            sniff(iface=self.interface, count=1)
            print("--Success!")
        except:
            print("--Failed!\nError: Unable to sniff packets, try again using sudo.")
            quit()

    def monitor_network(self):
        self.check_interface()

        if self.n_packets:
            print("Capturing {} packets on interface {} ".format(self.n_packets, self.interface))
        else:
            print("Capturing unlimited packets on interface {} \n--Press CTRL-C to exit".format(self.interface))

        yData = []  # Empty list to hold bytes
        i = 0

        self.is_running = True
        # Listen until stop pressed
        while self.is_running:
            for pkt in sniff(iface=self.interface, count=1):  # Listen for 1 packet
                try:
                    if 'IP' in pkt:
                        yData.append(pkt['IP'].len)

                        if i > 51:  # show only latest 100 packets
                            del yData[0]
                            # plt.clf()
                            self.plot_axes.cla()
                            self.plot_axes.set_title("Real time Network Traffic")
                            self.plot_axes.set_xlabel("Number of packets")
                            self.plot_axes.set_ylabel("Bytes")

                        self.plot_axes.plot(yData)
                        self.canvas.draw()

                        wrpcap('temp.pcap', pkt, append=True)  # to perform suricate analyze
                        if i % 50 == 0:
                            threading.Thread(target=self.call_suricata).start()  # to not block main thread
                            open('temp.pcap', 'w').close()  # clears file
                        wrpcap('all_packets.pcap', pkt, append=True)  # to store all packets

                        i += 1

                        if self.n_packets:
                            if i >= self.n_packets:
                                quit()

                except KeyboardInterrupt:
                    print("Captured {} packets on interface {} ".format(i, self.interface))
                    quit()

    def call_suricata(self):
        alerts_summary, alerts_df = self.suricate_analyzer.analyze()
        self.controller.draw_alerts_summary(alerts_summary, alerts_df)

    def stop(self):
        self.is_running = False


