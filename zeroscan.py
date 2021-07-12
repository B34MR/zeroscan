#!/usr/bin/env python3

from utils import arguments
from utils import mkdir
from utils import nmapper
from utils import richard as r
from utils import sqlite as db
from utils import rpcdumpper
from utils import xmlparser
from utils import zerologon
import os
import sys
import logging


# Stable versions.
nm_stablever = '7.91'
impacket_stablever = 'v0.9.23'

# Outputfile dirs.
MAIN_DIR = './outputfiles'
xml_dir = os.path.join(MAIN_DIR, 'xml')

# Nmap temp target/inputlist filepath.
targetfilepath = os.path.join(MAIN_DIR, 'targets.txt')

# Nmapper - vars.
nm_script = 'smb2-security-mode'
nm_port = '445'
nm_xmlfile = os.path.join(xml_dir, 'smb2-security-mode.xml')

# Banner - main header.
r.banner('Zeroscan'.upper())

# Create dirs.
directories = [xml_dir]
dirs = [mkdir.mkdir(directory) for directory in directories]
[logging.info(f'Created directory: {d}') for d in dirs if d is not None]


def version_check(mystr, currentver, stablever):
  ''' 
  Returns if app version is supported or not to stdout. 
  arg(s):mystr:str, currentver:str, stablever:str '''

  if currentver == stablever:
    r.console.print(f'[i grey37]{mystr} {currentver}')
  else:
    r.console.print(f'[red][!] Warning[i] using {mystr} {currentver}')


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

  # Write ipaddress to targetfile.
  lines =  [i[1] for i in targetlst]
  with open(targetfilepath , 'w+') as f1:
    for line in lines:
      f1.write(f'{line}\n')
  
  # Debug - print target(s).
  [logging.debug(f'Target(s): {target}') for target in targetlst]


  # CVE-2020-1472 mode.
  try:
    version_check('Impacket', \
      rpcdumpper.Rpcdumpper.get_version(), impacket_stablever)
    # Zerologon - print cmd.
    print(f"\n{' '.join(sys.argv[::])}")
    # Heading 2 - scan type.
    r.console.print(f'[grey27]CVE-2020-1472')
    
    for target in targetlst:
      hostname, ipaddress = target  
      # DEV, relocate sqlite insert statment.
      # Sqlite - insert target data.
      db.insert_data(hostname.upper(), ipaddress, None, None, None, None)
      
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
        
        # Print - authentication attempts.
        r.console.print(f'[grey58]{hostname.upper()} {ipaddress} [grey37] - AUTH-ATTEMPTS: {counter}')
        # Sqlite - update table:zeroscan, column:cve-2020-1472
        db.update_CVE_2020_1472(hostname.upper(), ipaddress, str(rpc_con))
    print('\n')
  except KeyboardInterrupt:
    print(f'\nQuit: detected [CTRL-C]')

  
  # MS-PAR/MS-RPRN
  try:
    version_check('Impacket', \
      rpcdumpper.Rpcdumpper.get_version(), impacket_stablever)
    # Rpcdumpper - print cmd.
    print(f"\n{rpcdumpper.Rpcdumpper('').cmd}ipaddress")
    # Heading 2 - scan type.
    r.console.print(f'[grey27]MS-PAR/MS-RPRN')
    
    for target in targetlst:
      hostname, ipaddress = target
      # Rpcdumpper - init and launch scan.
      rpcdump = rpcdumpper.Rpcdumpper(ipaddress)
      with r.console.status(spinner='bouncingBall', status=f'[status.text]{hostname.upper()} {ipaddress}') as status:
        results = rpcdump.run_scan()
        # Rcpdumpper - Get results:bool and update database.
        is_mspar = rpcdump.is_substring(results, 'MS-PAR')
        is_msrprn = rpcdump.is_substring(results, 'MS-RPRN')
        # Sqlite - update table:zeroscan, column:print_services. 
        db.update_MS_PAR(ipaddress, str(is_mspar))
        db.update_MS_RPRN(ipaddress, str(is_msrprn))

        r.console.print(f'[grey58]{hostname.upper()} {ipaddress}[grey37] - MS-PAR: {is_mspar}, MS-RPRN: {is_msrprn}')
    print('\n')
  except KeyboardInterrupt as e:
    print(f'\nQuit: detected [CTRL-C]')


  # SMBv2-Security mode.
  try:
    # Nmapper - obj init.
    nm = nmapper.Nmapper(nm_script, nm_port, targetfilepath, nm_xmlfile)
    # Nmapper - version check.
    version = version_check('Nmap', nm.get_version(), nm_stablever)
    # Nmapper - print cmd.
    print(f'\n{nm.cmd}')
    # Nmapper - print cmd and launch scan.
    with r.console.status(spinner='bouncingBall', status=f'[status.text]{ipaddress}') as status:
      # Heading 2 - scan type.
      r.console.print(f'[grey27]{nm_script.upper()}')
      nm.run_scan()
      # XmlParse - instance init, read xmlfile and return results to database.
      xmlparse = xmlparser.NseParser()
      xmlresults = xmlparse.run(nm_xmlfile)
      # Omit None results and print to stdout.
      for i in xmlresults:
        if i[1] != None:
          # Sqlite - insert xmlfile results (i[0]:ipaddress, i[1]:nseoutput). 
          db.update_smbv2_security(i[0], i[1])
          # Print nse-scan results to stdout.
          r.console.print(f'[grey58]{i[0]} [grey37]- {i[1].upper()}')
        else:
          print(i[0], i[1])
      print('\n')
  except KeyboardInterrupt:
    print(f'\nQuit: detected [CTRL-C]')


  # Table title.
  table = r.Table(title="[t.title]Zeroscan Database", box=r.box.DOUBLE_EDGE, style='table')
  # Table Columns.
  table.add_column('[white]Hostname', justify='left', no_wrap=True, style='t.col1')
  table.add_column('[white]IP Address', justify='left', no_wrap=True,  style='t.col2')
  table.add_column('[white]CVE-2020-1472', justify='left', no_wrap=False, style='t.col3')
  table.add_column('[white]MS_PAR', justify='left', no_wrap=False, style='t.col4')
  table.add_column('[white]MS_RPRN', justify='left', no_wrap=False, style='t.col5')
  table.add_column('[white]SMBv2 Security', justify='left', no_wrap=False, style='t.col6')
  # Pretty Print Table.  
  table_data = db.get_data('zeroscan')
  # i[0]:hostname, i[1]:ipaddress, i[2]:CVE_2020_1472, i[3]MS_PAR, i[4]MS_RPRN, i[5]:smbv2_security.
  for i in table_data:
    logging.debug(i)
    # RPC code '0xc0000022' is equivalent to 'str:3221225506'
    if i[2] == '3221225506':
      table.add_row(i[0],\
        i[1], \
        i[2] if args.rpcmessage else 'NOT VULNERABLE',\
        i[3] if i[3] == 'False' else f'[red]{i[3]}',
        i[4] if i[4] == 'False' else f'[red]{i[4]}',
        i[5] if i[5] == 'Message signing enabled but not required' else f'[grey58]{i[5]}')
    elif 'impacket.dcerpc.v5.rpcrt.DCERPC_v5' in i[2]:
      table.add_row(i[0],\
        i[1],\
        i[2] if args.rpcmessage else '[red]VULNERABLE',\
        i[3] if i[3] == 'False' else f'[red]{i[3]}',
        i[4] if i[4] == 'False' else f'[red]{i[4]}',
        i[5] if i[5] == 'Message signing enabled but not required' else f'[grey58]{i[5]}')
    else:
      table.add_row(i[0],\
        i[1],\
        i[2] if args.rpcmessage else 'NA',\
        i[3] if i[3] == 'False' else f'[red]{i[3]}',
        i[4] if i[4] == 'False' else f'[red]{i[4]}',
        i[5] if i[5] == 'Message signing enabled but not required' else f'[grey58]{i[5]}')
  # Render table.
  r.console.print('\n')
  r.console.print(table)
  r.console.print('\n')

if __name__ == '__main__':
  main()
