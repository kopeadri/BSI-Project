import subprocess
import os
import json
from collections import Counter

SURICATA_INSTALL_DIR = "D:\Programy\Suricata"  # TODO wywalić do pliku konfiguracyjnego


class SuricateAnalyzer:
    def __init__(self, file_path):
        self.pcap_file_path = file_path
        self.result_dir = "."

    def analyze(self):
        self.call_suricata()
        eve_json_path = os.path.join(self.result_dir, 'eve.json')
        self.parse_suricate_json(eve_json_path)

    def call_suricata(self):
        suricata_exe_path = os.path.join(SURICATA_INSTALL_DIR, "suricata.exe")
        suricata_config_path = os.path.join(SURICATA_INSTALL_DIR, "suricata.yaml")
        command = [suricata_exe_path, "-c", suricata_config_path, "-l", self.result_dir, "-r", self.pcap_file_path, "-v"]
        result = subprocess.run(command)

    def parse_suricate_json(self, eve_json_path):
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

        self.print_summary(cnt_categories, cnt_signature, cnt_severity)

    def print_summary(self, cnt_categories, cnt_signature, cnt_severity):
        print("\nCategory\t\toccurrences")
        for key, value in sorted(cnt_categories.items()):
            print(f"{key:<40} {value}")

        print("\nSignature\t\toccurrences")
        for key, value in sorted(cnt_signature.items()):
            print(f"{key:<63} {value}")

        print("\nSeverity\toccurrences")
        for key, value in sorted(cnt_severity.items()):
            print(f"{key:<15} {value}")

    def set_result_dir(self, result_dir):
        self.result_dir = result_dir

    def set_pcap_file_path(self,pcap_file_path):
        self.pcap_file_path = pcap_file_path
