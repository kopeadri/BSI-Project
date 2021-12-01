import os
import sys

from StatisticAnalyzer import StatisticAnalyzer
from SuricateAnalyzer import SuricateAnalyzer


class Analyzer:
    def __init__(self, args):
        self.pcap_file_path = None
        self.capture_packets_cnt = 0
        self.result_dir = "."

        self.set_parameters_from_args(args)

        self.statistic_analyzer = StatisticAnalyzer(self.pcap_file_path, self.capture_packets_cnt)
        self.suricate_analyzer = SuricateAnalyzer(self.pcap_file_path)

    def set_parameters_from_args(self, args):
        self.pcap_file_path = args.file
        self.capture_packets_cnt = args.capture_packets
        self.validate_parameters()

    def validate_parameters(self):
        if not self.pcap_file_path and self.capture_packets_cnt == 0:
            sys.exit(
                "Arguments not provided!")  # 2 Unix programs generally use 2 for command line syntax errors and 1 for all other kind of errors

    def run(self):
        self.statistic_analyzer.capture_pcap_if_needed()
        if self.capture_packets_cnt > 0:
            self.pcap_file_path = self.statistic_analyzer.get_pcap_file_path()
            self.suricate_analyzer.set_pcap_file_path(self.pcap_file_path)
        self.set_result_dir()
        self.statistic_analyzer.analyze()
        self.suricate_analyzer.analyze()

    def set_result_dir(self):
        file_name = os.path.basename(self.pcap_file_path)
        file_name_wo_ext = os.path.splitext(file_name)[0]
        self.result_dir = os.path.join("Results", file_name_wo_ext)

        if not os.path.exists(self.result_dir):
            os.mkdir(self.result_dir)

        self.statistic_analyzer.set_result_dir(self.result_dir)
        self.suricate_analyzer.set_result_dir(self.result_dir)
