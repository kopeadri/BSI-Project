from StatisticAnalyzer import StatisticAnalyzer

class TestStatisticAnalyzer:

    def test_get_pcap_file_path(self):
        statistic_analyzer = StatisticAnalyzer("pcap.pcap", 30)
        assert statistic_analyzer.get_pcap_file_path() == "pcap.pcap"

    def test_set_result_dir(self):
        statistic_analyzer = StatisticAnalyzer("pcap.pcap", 30)
        statistic_analyzer.set_result_dir("Results")
        assert statistic_analyzer.result_dir == "Results"
