#!/usr/bin/env python3

import sys
import argparse
from argparse import RawTextHelpFormatter

# Custom usage / help menu.
class HelpFormatter(argparse.HelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = ''
        return super(HelpFormatter, self).add_usage(
            usage, actions, groups, prefix)


def parse_args():
  ''' Define arguments '''
  
  # Custom help menu.
  custom_usage = """
Zeroscan
--------------------------------------------------\n
Usage: 
  python3 zeroscan.py -t dc01 192.168.1.10
  python3 zeroscan.py -tf /path/to/targetfile.txt
  
"""
  
  # Define parser
  parser = argparse.ArgumentParser(formatter_class=HelpFormatter, description='', usage=custom_usage, add_help=False)
  # Primary Options.
  parser._optionals.title = 'Primary options'
  parser.add_argument('-t', dest='target', required=False, nargs=2, action='store', metavar='TARGET', help='Single target using netbiosname and ipaddress. I.e "dc01 192.168.1.10"')
  parser.add_argument('-tf', dest='targetfile', required=False, type=str, action='store', metavar='TARGETSFILE', help='File that contains one target per line using netbiosname and ipaddress. I.e "dc01 192.168.1.10"')
  # Secondary Options.
  optional_group = parser.add_argument_group('Secondary options')
  optional_group.add_argument('-h','--help', action='help', help='Show this help message and exit')
  optional_group.add_argument('-v', '--verbose', action='store_true', help='Configure verbosity level')
  # Print 'help' if no options are defined.
  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
  # Initiate parser instance.
  args = parser.parse_args()
  return args

def main():
  import arguments
  args = arguments.parse_args()
  # Debug print.
  print(args)


if __name__ == "__main__":
    main()
