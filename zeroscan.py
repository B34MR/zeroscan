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
  ''' Main func '''
  
  MAX_ATTEMPTS = 2000
  targetlst = []
  
  # Args - init args.
  args = arguments.parse_args()
  
  # Args - single target.
  if args.target:
    hostname, ipaddress = args.target
    targetlst.append([hostname.rstrip('$'), ipaddress])
  
  # Args - inputlist.
  if args.inputlist:
    lines = readfile(args.inputlist)
    for line in lines:
      hostname, ipaddress = line.split()
      targetlst.append([hostname.rstrip('$'), ipaddress])

  # Debug - print target(s).
  [logging.debug(f'Target(s): {target}') for target in targetlst]

  # Table title.
  table = r.Table(title="[t.title]Zeroscan", box=r.box.DOUBLE_EDGE, style='table')
  # Table Columns.
  table.add_column('Hostname', justify='left', no_wrap=True, style='t.col1')
  table.add_column('IP Address', justify='left', no_wrap=True,  style='t.col2')
  table.add_column('CVE-2020-1472', justify='left', no_wrap=False, style='t.col3')

  try:
    r.console.print(f'[bright_white]CVE-2020-147')
    for target in targetlst:
      hostname, ipaddress = target
      # Zerologon - init instance and launch authentication attack.
      zl = zerologon.ZeroLogon(ipaddress, hostname)
      with r.console.status(spinner='bouncingBall', status=f'[status.text]{hostname.upper()} {ipaddress}') as status:
        rpc_con = None
        # Counter - for authentication attempts.
        counter = 0
        for attempt in range(0, MAX_ATTEMPTS):
          rpc_con = zl.run()
          counter += 1
          if rpc_con != 0xc0000022:
            break
        
        # Print - authentication attempt for single target.
        r.console.print(f'[grey58]{hostname.upper()} {ipaddress} [grey37]- auth attempts: {counter}')
        # Table - insert rpc response code into table.
        if rpc_con == 0xc0000022:
          table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'{rpc_con}' if args.rpcmessage else f'[green]NOT VULNERABLE')
        elif 'impacket.dcerpc.v5.rpcrt.DCERPC_v5' in str(rpc_con):
          table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'{rpc_con}' if args.rpcmessage else  f'[red]VULNERABLE')
        else:
          table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'{rpc_con}' if args.rpcmessage else f'NA')

  except KeyboardInterrupt:
    print(f'\nQuit: detected [CTRL-C]')
  
  # Render table.
  r.console.print('\n')
  r.console.print(table)
  r.console.print('\n')

if __name__ == '__main__':
  main()
