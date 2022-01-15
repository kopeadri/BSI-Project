from scapy.all import *
import matplotlib.pyplot as plt
from scapy.layers.dot11 import RadioTap
import os
import time

class StatisticAnalyzer:
    def __init__(self, file_path, capture_packets):
        self.pcap_file_path = file_path
        self.capture_packets = capture_packets
        self.result_dir = "."  # na wszelki

    def analyze(self):

        # x-axis temporal resolution used during graphing.
        timestep = 1  # float(sys.argv[2])

        # reading packets from a pcap file
        packets = rdpcap(self.pcap_file_path)

        start_time = packets[0].time
        end_time = packets[-1].time

        objects = ["packet_count", "bits", "unique_macs", "beacon_frames", "probe_responses", "acks", "block_acks",
                   "block_ack_requests",
                   "request_to_send", "clear_to_send"]

        list_length = int((end_time - start_time) // timestep + 1)
        statistics = [dict(zip(objects, [0 for _ in objects]))
                      for _ in range(list_length)]

        mac_tracker = [set() for _ in statistics]

        print("Parsing packets...")
        err_cnt=0
        for packet in packets:
            index = int((packet.time - start_time) // timestep)
            statistics[index]["packet_count"] += 1
            try:
                statistics[index]["bits"] += packet.len
            except AttributeError:
                err = f"{AttributeError}len"
                err_cnt += 1

            # We use packet.version to check if packet was corrupts
            if RadioTap in packet and packet.version == 0:
                mac_tracker[index].add(packet.addr2)

                # Management type
                if packet.type == 0:
                    if packet.subtype == 5:
                        statistics[index]["probe_responses"] += 1
                    if packet.subtype == 8:
                        statistics[index]["beacon_frames"] += 1

                # Control type
                if packet.type == 1:
                    if packet.subtype == 8:
                        statistics[index]["block_ack_requests"] += 1
                    if packet.subtype == 9:
                        statistics[index]["block_acks"] += 1
                    if packet.subtype == 12:
                        statistics[index]["request_to_send"] += 1
                    if packet.subtype == 12:
                        statistics[index]["clear_to_send"] += 1
                    if packet.subtype == 13:
                        statistics[index]["acks"] += 1

        print("Writing graphs...")

        for i, mac_counts in enumerate(statistics):
            mac_counts["unique_macs"] = len(mac_tracker[i])

        for obj in objects:
            # Non-cumulative
            plt.title(obj)
            plt.xlabel("time (seconds)")
            plt.ylabel(obj + " per second")
            plt.plot([i * timestep for i, _ in enumerate(statistics)], [y[obj] for y in statistics])
            plt.savefig(f"{self.result_dir}\\{obj}_histogram.png")
            plt.clf()

            # Cumulative
            plt.title(obj)
            plt.xlabel("time (cumulative seconds)")
            plt.ylabel(obj + " per second cumulative")
            histogram = [y[obj] for y in statistics]
            cumulative = [None for _ in histogram]
            s = 0
            for i, x in enumerate(histogram):
                s += x
                cumulative[i] = s
            plt.plot([i * timestep for i, _ in enumerate(statistics)], cumulative)
            plt.savefig(f"{self.result_dir}\\{obj}_cumulative.png")
            plt.clf()

    def capture_pcap_if_needed(self):
        if self.capture_packets == 0:
            return

        captured_packets = sniff(count=self.capture_packets)
        # if not self.pcap_file_path:  # if file_path not provided create default path
        timestr = time.strftime("%Y%m%d%H%M%S")
        self.pcap_file_path = os.path.join("Resources", "captured_" + timestr + ".pcap")

        # write packets in a pcap file
        wrpcap(self.pcap_file_path, captured_packets)

    def get_pcap_file_path(self):
        return self.pcap_file_path

    def set_result_dir(self, result_dir):
        self.result_dir = result_dir
