import argparse
from collections import Counter

from scapy.all import *
import matplotlib.pyplot as plt
from scapy.layers.dot11 import RadioTap
import subprocess
import sys
import os
import json
import time


def file_path(path):
    if os.path.isfile(os.path.normpath(path)):
        return os.path.normpath(path)
    else:
        raise argparse.ArgumentTypeError(f"readable_file:{path} is not a valid path")


def positive_int(value):
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
    return ivalue


def parse_arguments(args):
    arg_parser = argparse.ArgumentParser(description='PCAPs analyzer')
    arg_parser.add_argument('-f', '--file', metavar='FILE', type=file_path, default=None,
                            help='If used, the PCAP file from the given path is analyzed. If provided together with CAPTURE_PACKETS argument, FILE is destination location for captured PCAP.')
    arg_parser.add_argument('-c', '--capture-packets', metavar='CAPTURE_PACKETS', type=positive_int, default=0,
                            help='If used, the given number of packets will be captured, saved and analyzed. Default location for captured PCAP is ./Resources/captured_TIMESTAMP.pcap.')
    return arg_parser.parse_args(args)


def print_args(args):
    for arg in vars(args):
        print(arg, ":", getattr(args, arg))


def set_parameters(args):
    file_path = args.file
    capture_packets = args.capture_packets
    return file_path, capture_packets


def statistic_analysis(file_path, results_dir):
    pcap_file_path = file_path
    # pcap_file_name = os.path.split(pcap_file_path)[1][:-5]

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
    # results_folder = "Results\\Statistics\\" + pcap_file_name
    # if not os.path.isdir(results_folder):
    #     os.mkdir(results_folder)

    for obj in objects:
        # Non-cumulative
        plt.title(obj)
        plt.xlabel("time (seconds)")
        plt.ylabel(obj + " per second")
        plt.plot([i * timestep for i, _ in enumerate(statistics)], [y[obj] for y in statistics])
        plt.savefig("{}\\{}_histogram.png".format(results_dir, obj))
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
        plt.savefig("{}\\{}_cumulative.png".format(results_dir, obj))
        plt.clf()


def make_pcap(file_path, packets_count):
    captured_packets = sniff(count=packets_count)
    if not file_path:  # if file_path not provided create default path
        timestr = time.strftime("%Y%m%d%H%M%S")
        file_path = os.path.join("Resources", "captured_" + timestr + ".pcap")

    # write packets in a pcap file
    wrpcap(file_path, captured_packets)
    return file_path

def suricata_analysis(file_path, results_dir):
    command = [r"D:\Programy\Suricata\suricata.exe", "-c", r"D:\Programy\Suricata\suricata.yaml",
               "-l", results_dir,
               "-v", "-r", file_path]
    result = subprocess.run(command)

    eve_json_path = os.path.join(results_dir, 'eve.json')

    parse_suricate_json(eve_json_path)

def parse_suricate_json(eve_json_path):
    # # src ip:src port -> dst ip:dst port [pkt_count]
    # with open(eve_json_path) as f:
    #     for line in f:
    #         event = json.loads(line)
    #         if event['event_type'] == 'flow':
    #             print("%s:%d --> %s:%d [pkts %d]" % (event['src_ip'], event['src_port'], event['dest_ip'], event['dest_port'], event['flow']['pkts_toserver']))\
    #
    # # application protocol or layer 3 protocol if not available to the display
    # with open(eve_json_path) as f:
    #     for line in f:
    #         event = json.loads(line)
    #         if event['event_type'] == 'flow':
    #             if 'app_proto' in event:
    #                 app_proto = event['app_proto']
    #             else:
    #                 app_proto = event['proto']
    #             print("%s:%d - %s -> %s:%d [pkts %d]" % (event['src_ip'], event['src_port'], app_proto, event['dest_ip'], event['dest_port'], event['flow']['pkts_toserver']))
    #
    #

    cnt_categories = Counter()
    cnt_signature = Counter()
    cnt_severity = Counter()

    with open(eve_json_path) as f:
        for line in f:
            event = json.loads(line)
            if event['event_type'] == 'alert':
                if 'app_proto' in event:
                    app_proto = event['app_proto']
                else:
                    app_proto = event['proto']
                cnt_categories[event['alert']['category']] += 1
                cnt_signature[event['alert']['signature']] += 1
                cnt_severity[event['alert']['severity']] += 1
                print(
                    f"{event['timestamp']}:  {event['src_ip']}:{event['src_port']} - {app_proto} ->  {event['dest_ip']}:{event['dest_port']}  [{event['alert']['severity']}]  [{event['alert']['category']}]  [{event['alert']['signature']}]")

    print("\nCategory\t\toccurrences")
    for key, value in sorted(cnt_categories.items()):
        print(f"{key:<40} {value}")

    print("\nSignature\t\toccurrences")
    for key, value in sorted(cnt_signature.items()):
        print(f"{key:<63} {value}")

    print("\nSeverity\toccurrences")
    for key, value in sorted(cnt_severity.items()):
        print(f"{key:<15} {value}")


if __name__ == "__main__":
    # args = parse_arguments(sys.argv[1:])  # omit program name
    args = parse_arguments(
        ['-f', 'Resources\Pcap2.pcap'])
        # ['--help'])
        # ['-c', '5'])

    print_args(args)
    file_path, capture_packets = set_parameters(args)

    if capture_packets > 0:
        file_path = make_pcap(file_path, capture_packets)

    if not file_path:
        sys.exit("Arguments not provided!")  # 2 Unix programs generally use 2 for command line syntax errors and 1 for all other kind of errors

    file_name = os.path.basename(file_path)
    file_name_wo_ext = os.path.splitext(file_name)[0]
    results_dir = os.path.join("Results", file_name_wo_ext)

    if not os.path.exists(results_dir):
        os.mkdir(results_dir)
    print(file_name, file_name_wo_ext, results_dir)

    statistic_analysis(file_path, results_dir)

    suricata_analysis(file_path, results_dir)


