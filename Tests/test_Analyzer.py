import Analyzer as An
from Analyzer import Analyzer
from ArgParser import ArgParser
import os
import pytest

class TestAnalyzer:

    def test_get_suricata_install_dir(self):
        assert An.get_suricata_install_dir()


    def test_validate_parameters(self):
        analyzer = Analyzer("file.pcap", 50)
        analyzer.validate_parameters()
        assert analyzer.pcap_file_path == "file.pcap"
        assert analyzer.capture_packets_cnt == 50

    def test_wrong_validate_parameters(self):
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            analyzer = Analyzer()
            analyzer.validate_parameters()
        assert pytest_wrapped_e.type == SystemExit

    def test_set_parameters_from_args(self):
        arguments = ['-c', '500']
        arg_parser = ArgParser()
        args = arg_parser.parse_arguments(arguments)
        analyzer = Analyzer("pcap.pcap")
        analyzer.set_parameters_from_args(args)
        #assert analyzer.pcap_file_path == "pcap.pcap"
        assert analyzer.capture_packets_cnt == 500

    def test_set_result_dir(self):
        analyzer = Analyzer("pcap.pcap", 50)
        analyzer.set_result_dir()
        assert analyzer.result_dir == 'Results\pcap'