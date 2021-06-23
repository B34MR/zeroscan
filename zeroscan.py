#!/usr/bin/env python3

from utils import arguments
from utils import richard as r
from utils import zerologon
import sys
import logging


def readfile(filepath):
  ''' 
  Return contents from filepath in a list. 
  Arg(s):filepath:str'''

  with open(filepath, 'r+') as f1:
    lines = [line.strip() for line in f1]

    return lines


def main():
  ''' Main Func'''
  
  MAX_ATTEMPTS = 2000
  targetlst = []
  
  # Args - init args.
  args = arguments.parse_args()
  
  # Args - single target.
  if args.target:
    hostname, ipaddress = args.target
    targetlst.append([hostname.rstrip('$'), ipaddress])
  
  # Args - multiple targets.
  if args.targetfile:
    lines = readfile(args.targetfile)
    for line in lines:
      hostname, ipaddress = line.split()
      targetlst.append([hostname.rstrip('$'), ipaddress])

  # Debug - print target(s).
  [logging.debug(f'Target(s): {target}') for target in targetlst]

  for target in targetlst:
    hostname, ipaddress = target

    # Zeroscan - instance init.
    zl = zerologon.ZeroLogon(ipaddress, hostname)

    # Zerologon - Launch authentication attack.
    with r.console.status(status=f'[status.text]Performing authentication attempts...') as status:
      rpc_con = None
      for attempt in range(0, MAX_ATTEMPTS):  
        rpc_con = zl.run()
        if rpc_con != 0xc0000022:
          break
     # DEV
      if not rpc_con:
        r.console.print(f'{hostname} [white]{ipaddress}[/white] [green]NOT VULNERABLE\n')
      else:
        if str(rpc_con) == 'Could not connect: [Errno 113] No route to host':
          r.console.print(f'{hostname} [white]{ipaddress}[/white] [orange3]{str(rpc_con)}\n')
        elif str(rpc_con) == 'Could not connect: [Errno 111] Connection refused':
          r.console.print(f'{hostname} [white]{ipaddress}[/white] [dark_orange3]{str(rpc_con)}\n')
        else:
          # print(str(rpc_con))
          r.console.print(f'{hostname} [white]{ipaddress}[/white] [red]VULNERABLE\n')


if __name__ == '__main__':
  main()

# Dev - comments
# zerologon class - refactor
# main - add docstrings, table, fix stoud.
# richard -  add theme.