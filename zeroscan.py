#!/usr/bin/env python3

from utils import arguments
from utils import mkdir
from utils import richard as r
from utils import sqlite as db
from utils import zerologon
import os
import sys
import logging


# Stable versions.
nm_stablever = '7.91'

# Outputfile dirs.
MAIN_DIR = './outputfiles'
findings_dir = os.path.join(MAIN_DIR, 'findings')
portscans_dir = os.path.join(MAIN_DIR, 'portscans')
xml_dir = os.path.join(MAIN_DIR, 'xml')

# Nmap temp target/inputlist filepath.
targetfilepath = os.path.join(MAIN_DIR, 'targets.txt')

# Banner - main header.
r.banner('Zeroscan'.upper())

# Create dirs.
directories = [portscans_dir, findings_dir, xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]


def readfile(filepath):
  ''' 
  Return contents from a file. 
  Arg(s):filepath:str'''

  with open(filepath, 'r+') as f1:
    lines = [line.strip() for line in f1]

    return lines


def main():
  ''' Main func '''
  
  # Const.
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
  # Args - droptable.
  if args.droptable:
    db.drop_table('zeroscan')
  # Sqlite - database init.
  db.create_table_zeroscan()

  # Debug - print target(s).
  [logging.debug(f'Target(s): {target}') for target in targetlst]

  # Table title.
  table = r.Table(title="[t.title]Zeroscan", box=r.box.DOUBLE_EDGE, style='table')
  # Table Columns.
  table.add_column('Hostname', justify='left', no_wrap=True, style='t.col1')
  table.add_column('IP Address', justify='left', no_wrap=True,  style='t.col2')
  table.add_column('CVE-2020-1472', justify='left', no_wrap=False, style='t.col3')
  table.add_column('SMBv2-SIGNING', justify='left', no_wrap=False, style='t.col3')

  try:
    # H2
    r.console.print(f'[bright_white]CVE-2020-1472')
    for target in targetlst:
      hostname, ipaddress = target
      # Sqlite - insert target data.
      db.insert_data(hostname.upper(), ipaddress, '', '')
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
        # Table - insert rpc response code into database.
        if rpc_con == 0xc0000022:
          db.update_CVE_2020_1472(hostname.upper(), ipaddress, str(rpc_con))
        elif 'impacket.dcerpc.v5.rpcrt.DCERPC_v5' in str(rpc_con):
          db.update_CVE_2020_1472(hostname.upper(), ipaddress, str(rpc_con))
        else:
          db.update_CVE_2020_1472(hostname.upper(), ipaddress, str(rpc_con))
  except KeyboardInterrupt:
    print(f'\nQuit: detected [CTRL-C]')

    
  # DEV - Nmapper.
  if args.nmap:
    from utils import nmapper
    from utils import xmlparser

    # Vars.
    nm_script = 'smb2-security-mode'
    nm_port = '445'
    nm_xmlfile = os.path.join(xml_dir, 'smb2-security-mode.xml')

    # Write ipaddress targets to targetfile.
    lines =  [i[1] for i in targetlst]
    with open(targetfilepath , 'w+') as f1:
      for line in lines:
        f1.write(f'{line}\n')
    
    # Nmapper - instance init and run scan.
    nm = nmapper.Nmapper(nm_script, nm_port, targetfilepath, nm_xmlfile)
    # H2
    r.console.print(f'\n[bright_white]SMBv2-SIGNING')
    print(nm.cmd)
    nm.run_scan()

    # XmlParse - instance init, read xmlfile and return results to database.
    xmlparse = xmlparser.NseParser()
    xmlresults = xmlparse.run(nm_xmlfile)
    # Omit None results and print to stdout.
    for i in xmlresults:
      if i[1] != None:
        # Sqlite - insert xmlfile results (i[0]:ipaddress, i[1]:nseoutput). 
        db.update_smbv2_signing(i[0], i[1])
        # Print nse-scan results to stdout.
        r.console.print(f'{i[0]} {i[1].upper()}')
    print('\n')
    # exit()

  table_data = db.get_data('zeroscan')
  for i in table_data:
    # RPC code '0xc0000022' is equivalent to 'str:3221225506'
    if i[2] == '3221225506':
      table.add_row(i[0], i[1], i[2] if args.rpcmessage else f'[green]NOT VULNERABLE', i[3])
    elif 'impacket.dcerpc.v5.rpcrt.DCERPC_v5' in i[2]:
      table.add_row(i[0], i[1], i[2]  if args.rpcmessage else  f'[red]VULNERABLE', i[3])
    else:
      table.add_row(i[0], i[1], i[2] if args.rpcmessage else f'NA', i[3] )

  # Render table.
  r.console.print('\n')
  r.console.print(table)
  r.console.print('\n')

if __name__ == '__main__':
  main()
