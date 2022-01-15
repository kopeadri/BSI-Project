from unittest import TestCase
from ArgParser import ArgParser
import os
import argparse
import pytest

class TestArgParser(TestCase):
    arg_parser = ArgParser()

    def test_right_file_path(self):
        file_path = os.path.dirname(os.path.abspath(os.getcwd()))+"\Resources\Pcap2.pcap"
        returned_path = ArgParser().file_path(file_path)
        assert returned_path == os.path.normpath(file_path)

    def test_right_positive_int(self):
        value = 10
        returned_value = ArgParser().positive_int(value)
        assert returned_value == int(10)

"""
    def test_wrong_positive_int(self):
        value = -10
        with pytest.raises(SystemExit) as e:
            ArgParser().positive_int(value)

        assert isinstance(e.value.__context__, argparse.ArgumentTypeError)

        #returned_value = ArgParser().positive_int(value)
        #assert returned_value == int(10)
"""
"""
    def test_wrong_file_path(self):
        file_path = "\Resources\Pcap2.pcap"
        try:
            ArgParser().file_path(file_path)
        except SystemExit as e:
            assert isinstance(e.__context__, argparse.ArgumentTypeError)
"""