#!/usr/bin/env python3

import subprocess
import logging


class Rpcdumpper:
	'''  Impacket's rpcdump.py class wrapper '''

	# Impacket version cmd.
	version_cmd = 'rpcdump.py -h'


	def __init__(self, ipaddress):
		''' Init arg(s)ipaddress:str '''
		
		self.ipaddress = ipaddress
		self.cmd = f'rpcdump.py @{self.ipaddress}'


	@classmethod
	def get_version(cls):
		'''Return Impacket version:str '''
		
		# Impacket version cmd.
		cmd = cls.version_cmd.split(' ')

		try:
			proc = subprocess.run(cmd, 
				shell=False, 
				check=False, 
				capture_output=True, 
				text=True)
		except Exception as e:
			raise e
		else:
			logging.debug(proc.stderr)
			version =  proc.stdout[0:16].split(' ')
			
			return version[1]


	def is_substring(self, stdout, substring):
		''' Find substring from stdout.
		arg(s) substring:str '''
			
		try:
			i = stdout.index(substring)
		except ValueError as e:
			logging.debug(f'{e}: {substring}')
			return False
		else:
			logging.debug(stdout[i:i + 7])
			return True


	def run_scan(self):
		''' Launch rpcdump.py scan via subprocess wrapper. '''

		# Rpcdump.py cmd.
		cmd = self.cmd.split(' ')

		try:
			proc = subprocess.run(cmd, 
				shell=False,
				check=True,
				capture_output=True,
				text=True)
		except Exception as e:
			raise e
		else:
			# Debug print only.
			logging.info(f'STDOUT:\n{proc.stdout}')
			logging.debug(f'STDERR:\n{proc.stderr}')
			
			return proc.stdout

# Dev - note.
# Protocol failed: Could not connect: [Errno 113] No route to host'