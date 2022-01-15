import os
import sys
import subprocess
from datetime import datetime
from plyer import notification
import json
from collections import Counter


class SuricateAnalyzer:
    def __init__(self, file_path, mode, suricata_install_dir):
        self.pcap_file_path = file_path
        self.result_dir = "."
        self.alert_flag = False
        self.mode = mode  # 'static', 'real-time' TODO enum
        self.suricata_install_dir = suricata_install_dir

    def analyze(self):
        self.call_suricata()
        eve_json_path = os.path.join(self.result_dir, 'eve.json')
        alerts_summary = self.parse_suricate_json(eve_json_path)
        return alerts_summary

    def call_suricata(self):
        suricata_exe_path = os.path.join(self.suricata_install_dir, "suricata.exe")
        suricata_config_path = os.path.join(self.suricata_install_dir, "suricata.yaml")
        command = [suricata_exe_path, "-c", suricata_config_path, "-l", self.result_dir, "-r", self.pcap_file_path,
                   "-v"]
        result = subprocess.run(command)

    def parse_suricate_json(self, eve_json_path):
        cnt_categories = Counter()
        cnt_signature = Counter()
        cnt_severity = Counter()

        malicious_packets = ""

        with open(eve_json_path) as f:
            for line in f:
                event = json.loads(line)
                if event['event_type'] == 'alert':
                    self.alert_flag = True

                    if 'app_proto' in event:
                        app_proto = event['app_proto']
                    else:
                        app_proto = event['proto']
                    cnt_categories[event['alert']['category']] += 1
                    cnt_signature[event['alert']['signature']] += 1
                    cnt_severity[event['alert']['severity']] += 1

                    if self.mode == 'real-time':
                        malicious_packets += f"{event['timestamp']}:  {event['src_ip']}:{event['src_port']} - {app_proto} ->  {event['dest_ip']}:{event['dest_port']}  [{event['alert']['severity']}]  [{event['alert']['category']}]  [{event['alert']['signature']}\n]"
                    else:
                        print(
                            f"{event['timestamp']}:  {event['src_ip']}:{event['src_port']} - {app_proto} ->  {event['dest_ip']}:{event['dest_port']}  [{event['alert']['severity']}]  [{event['alert']['category']}]  [{event['alert']['signature']}]")
                        malicious_packets += f"{event['timestamp']}:  {event['src_ip']}:{event['src_port']} - {app_proto} ->  {event['dest_ip']}:{event['dest_port']}  [{event['alert']['severity']}]  [{event['alert']['category']}]  [{event['alert']['signature']}\n]"

        # date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        date = datetime.now().strftime("%d_%m_%Y__%H_%M_%S")

        if self.mode == 'real-time':
            if self.alert_flag:
                notification.notify(title="Analizator ruchu sieciowego {}".format(date),
                                    message="Wykryto podejrzany ruch w sieci - sprawdź logi!",
                                    app_icon="Resources\\warning_icon.ico",
                                    timeout=50)
                self.print_summary(cnt_categories, cnt_signature, cnt_severity, malicious_packets, date)
        else:
            self.print_summary(cnt_categories, cnt_signature, cnt_severity, malicious_packets, date)

        return {'categories': cnt_categories,
                'signature': cnt_signature,
                'severity': cnt_severity}

    def print_summary(self, cnt_categories, cnt_signature, cnt_severity, malicious_packets, date):
        original_stdout = sys.stdout
        with open('Alert_logs_' + date + '.txt', 'a') as f:
            sys.stdout = f
            print(malicious_packets)
            print("\nCategory\t\toccurrences")
            for key, value in sorted(cnt_categories.items()):
                print(f"{key:<40} {value}")

            print("\nSignature\t\toccurrences")
            for key, value in sorted(cnt_signature.items()):
                print(f"{key:<63} {value}")

            print("\nSeverity\toccurrences")
            for key, value in sorted(cnt_severity.items()):
                print(f"{key:<15} {value}")

            sys.stdout = original_stdout

    def set_result_dir(self, result_dir):
        self.result_dir = result_dir

    def set_pcap_file_path(self, pcap_file_path):
        self.pcap_file_path = pcap_file_path
