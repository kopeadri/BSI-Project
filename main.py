import os
import argparse
import sys

from Analyzer import Analyzer
from ArgParser import ArgParser


def main():

    # arguments = sys.argv[1:] # omit program name
    arguments = ['-f', 'Resources\Pcap2.pcap']
    # arguments = ['-f', 'Resources\wireshark3.pcap']
    # arguments = ['-c', '500']
    # arguments = ['--help']
    # arguments = ['-f', 'Resources\Pcap2.pcap', '-c', '50']  # w takiej sytuacji bierzemy pod uwagę tylko argument -c
    # arguments = ['-c', '-500'] # komunikat, że nie może być <= 0
    # arguments = ['-f', 'Resources\Pcap45.pcap'] # komunikat, że ścieżka nie istnieje
    # arguments = [] # komunikat Arguments not provided!

    arg_parser = ArgParser()
    args = arg_parser.parse_arguments(arguments)
    arg_parser.print_args(args)

    analyzer = Analyzer(args.file, args.capture_packets)
    analyzer.run()


if __name__ == "__main__":
    print("hello")
    main()
