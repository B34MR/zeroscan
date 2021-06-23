#!/usr/bin/env python3

from rich.console import Console
from rich.logging import RichHandler
# from rich.table import Table
# from rich import box
# from rich.panel import Panel
# from rich.theme import Theme
import logging
from utils import arguments
# import sys

# Args - init.
args = arguments.parse_args()
if args.verbose:
	loglevel = 'DEBUG'
else:
	loglevel = 'WARNING'

# Rich console and theme init.
# themefile = './utils/theme.ini'
# mytheme = Theme().read(themefile)
# console = Console(theme=mytheme)
console = Console()
# logger - Rich
logging.basicConfig(
	# filename='',
	level=loglevel,
	format='%(message)s',
	datefmt='[%X]',
	handlers=[RichHandler(console=console, rich_tracebacks=True, omit_repeated_times=False)]
	)
logging = logging.getLogger('rich')


# def banner(banner_title):
# 	''' Rich util Banner.'''

# 	print('\n')
# 	console.print(Panel('', title=f'[h1]{banner_title}', 
# 		height=1, width=95, box=box.DOUBLE_EDGE))


# # Non Rich util.
# def ctrl_c(txt='[ENTER] to continue / [CTRL-C] to quit...'):
# 	''' Press ENTER / CTRL-C '''

# 	try:
# 		input(f'\n{txt}')
# 	except KeyboardInterrupt:
# 		print(f'\nQuit: detected [CTRL-C] ')
# 		sys.exit(0)