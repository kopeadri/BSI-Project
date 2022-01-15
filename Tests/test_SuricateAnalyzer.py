from SuricateAnalyzer import SuricateAnalyzer
import Analyzer
import os
from collections import Counter

class TestSuricateAnalyzer:


    def test_result_dir(self):
        suricate_analyzer = SuricateAnalyzer("pcap.pcap", 'static', Analyzer.get_suricata_install_dir())
        suricate_analyzer.set_result_dir("Result")
        assert suricate_analyzer.result_dir == "Result"

    def test_set_pcap_file_path(self):
        suricate_analyzer = SuricateAnalyzer("pcap.pcap", 'static', Analyzer.get_suricata_install_dir())
        suricate_analyzer.set_pcap_file_path("pcap_other.pcap")
        assert suricate_analyzer.pcap_file_path == "pcap_other.pcap"

    def test_parse_suricate_json_categories(self):
        suricate_analyzer = SuricateAnalyzer("Pcap2.pcap", 'static', Analyzer.get_suricata_install_dir())
        eve_file = os.path.dirname(os.path.abspath(os.getcwd()))+"\Results\Pcap2\eve.json"
        dict = suricate_analyzer.parse_suricate_json(eve_file)
        assert dict['categories'] == Counter({"A Network Trojan was detected": 40,
                                      "Misc activity": 24,
                                      "Potential Corporate Privacy Violation": 24,
                                      "Potentially Bad Traffic": 26})

    def test_parse_suricate_json_signatures(self):
        suricate_analyzer = SuricateAnalyzer("Pcap2.pcap", 'static', Analyzer.get_suricata_install_dir())
        eve_file = os.path.dirname(os.path.abspath(os.getcwd())) + "\Results\Pcap2\eve.json"
        dict = suricate_analyzer.parse_suricate_json(eve_file)
        assert dict['signature'] == Counter({"ET INFO EXE - Served Inline HTTP": 24,
                                                "ET INFO JAVA - Java Archive Download By Vulnerable Client": 24,
                                                "ET POLICY Java EXE Download": 16,
                                                "ET POLICY PE EXE or DLL Windows file download HTTP": 24,
                                                "ET POLICY Vulnerable Java Version 1.7.x Detected": 26})

    def test_parse_suricate_json_severities(self):
        suricate_analyzer = SuricateAnalyzer("Pcap2.pcap", 'static', Analyzer.get_suricata_install_dir())
        eve_file = os.path.dirname(os.path.abspath(os.getcwd())) + "\Results\Pcap2\eve.json"
        dict = suricate_analyzer.parse_suricate_json(eve_file)
        assert dict['severity'] == Counter({1: 64,
                                            2: 26,
                                            3: 24})

