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
  
  # Args - multiple targets.
  if args.targetfile:
    lines = readfile(args.targetfile)
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
  table.add_column('CVE-2020-1472', justify='left', no_wrap=True, style='t.col3')
  # table.add_column('NULL Session')
  # table.add_column('SMB')
  # table.add_column('PrinterBug')
  # table.add_column('LDAPS')

  try:
    for target in targetlst:
      hostname, ipaddress = target

      # Zerologon - init instance and launch authentication attack.
      zl = zerologon.ZeroLogon(ipaddress, hostname)
      with r.console.status(spinner='bouncingBall', status=f'[status.text]CVE-2020-147 {hostname.upper()} {ipaddress}') as status:
        rpc_con = None
        for attempt in range(0, MAX_ATTEMPTS):
          rpc_con = zl.run()
          if rpc_con != 0xc0000022:
            break
        r.console.print(f'{hostname.upper()} {ipaddress}')

        # Stdout parser.
        if not rpc_con:
          # Not Vulnerable.
          table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'NOT VULNERABLE')
        else:
          # No route to host.
          if str(rpc_con) == 'Could not connect: [Errno 113] No route to host':
            table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'{str(rpc_con)}')
          # Connection refused.
          elif str(rpc_con) == 'Could not connect: [Errno 111] Connection refused':
            table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'{str(rpc_con)}')
          # Vulnerable.
          else:
            table.add_row(f'{hostname.upper()}', f'{ipaddress}', f'[red]VULNERABLE')
    
  except KeyboardInterrupt:
    print(f'\nQuit: detected [CTRL-C]')
  
  # Render table.
  r.console.print('\n')
  r.console.print(table)
  r.console.print('\n')

if __name__ == '__main__':
  main()
