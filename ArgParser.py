import argparse
import os


class ArgParser:
    def file_path(self, path):
        if os.path.isfile(os.path.normpath(path)):
            return os.path.normpath(path)
        else:
            raise argparse.ArgumentTypeError(f"readable_file:{path} is not a valid path")

    def positive_int(self, value):
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
        return ivalue

    def parse_arguments(self, args):
        arg_parser = argparse.ArgumentParser(description='PCAPs analyzer')
        arg_parser.add_argument('-f', '--file', metavar='FILE_PATH', type=self.file_path, default=None,
                                help='If used, the PCAP file from the given path is analyzed. If provided together with CAPTURE_PACKETS argument, FILE is not considered.')
        arg_parser.add_argument('-c', '--capture-packets', metavar='CAPTURE_PACKETS_COUNT', type=self.positive_int, default=0,
                                help='If used, the given number of packets will be captured, saved as PCAP file and analyzed. Location for captured PCAP is ./Resources/captured_TIMESTAMP.pcap.')
        return arg_parser.parse_args(args)

    def print_args(self, args):
        for arg in vars(args):
            print(arg, ":", getattr(args, arg))


