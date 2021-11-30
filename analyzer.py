import argparse
from scapy.all import *
import matplotlib.pyplot as plt
from scapy.layers.dot11 import RadioTap
import subprocess
import sys
import os



def file_path(path):
    if os.path.isfile(os.path.normpath(path)):
        return os.path.normpath(path)
    else:
        raise argparse.ArgumentTypeError(f"readable_file:{path} is not a valid path")


def parse_arguments(args):
    arg_parser = argparse.ArgumentParser(description='PCAPs analyzer')
    arg_parser.add_argument('-f', '--file', metavar='FILE', type=file_path, default=None,
                            help='If used, the PCAP file from the given path is analyzed.')
    arg_parser.add_argument('-c', '--capture-packets', metavar='CAPTURE_PACKETS', type=int, default=0,
                            help='If used, the given number of packets will be captured and analyzed.')
    return arg_parser.parse_args(args)


def print_args(args):
    for arg in vars(args):
        print(arg, ":", getattr(args, arg))


def set_parameters(args):
    file_path = args.file
    capture_packets = args.capture_packets
    return file_path, capture_packets


def read_pcap(file_path):
    pcap_file_path = file_path
    pcap_file_name = os.path.split(pcap_file_path)[1][:-5]

    # x-axis temporal resolution used during graphing.
    timestep = 1  # float(sys.argv[2])

    # reading packets from a pcap file
    packets = rdpcap(pcap_file_path)

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

    for packet in packets:
        index = int((packet.time - start_time) // timestep)
        statistics[index]["packet_count"] += 1
        statistics[index]["bits"] += packet.len
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

    # t = str(int(time.time()))[3:]
    # subdir = "{}_{}".format(pcap_file, t)
    results_folder = "Results\\Statistics\\" + pcap_file_name
    if not os.path.isdir(results_folder):
        os.mkdir(results_folder)

    for obj in objects:
        # Non-cumulative
        plt.title(obj)
        plt.xlabel("time (seconds)")
        plt.ylabel(obj + " per second")
        plt.plot([i * timestep for i, _ in enumerate(statistics)], [y[obj] for y in statistics])
        plt.savefig("{}\\{}_histogram.png".format(results_folder, obj))
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
        plt.savefig("{}\\{}_cumulative.png".format(results_folder, obj))
        plt.clf()


def analyze_capture_packets(packets_count):
    captured_packets = sniff(count=packets_count)
    # write packets in a pcap
    file_path = 'Resources\Pcap2.pcap' # "Resources\captured_packets.pcap"
    wrpcap(file_path, captured_packets)
    read_pcap(file_path)


if __name__ == "__main__":
    args = parse_arguments(
        # ['--help'])
        ['-f', 'Resources\Pcap2.pcap'])
    # ['-c', '5'])

    print_args(args)
    file_path, capture_packets = set_parameters(args)

    file_name = os.path.basename(file_path)
    file_name_wo_ext = os.path.splitext(file_name)[0]
    file_log_dir = ".\\Suricata\\" + file_name_wo_ext + "_log"

    if not os.path.exists(file_log_dir):
        os.mkdir(file_log_dir)
    print(file_name, file_name_wo_ext, file_log_dir)

    # if file_path:
    #     read_pcap(file_path)
    # elif capture_packets:
    #     analyze_capture_packets(capture_packets)

    command = [r"D:\Programy\Suricata\suricata.exe", "-c", r"D:\Programy\Suricata\suricata.yaml",
                                                     "-l", file_log_dir,
                                                    "-v", "-r", file_path]
    #result = subprocess.run([".\\Suricata\\suricata_run.bat"])
    result = subprocess.run(command)










