from lib2to3.pytree import convert
import subprocess as sp
import json
import sys
import os
import re

from config import get_config, get_stats, set_stats, get_SimManager
from macros import RESULTS_DIR, BIN_NAME, BIN_PATH, TIMEOUT, STATS
from macros import TIME_SPENT, F_CALLED


def get_num_of_paths():
	return len(get_SimManager().deadended)


def get_fnames():

	def clean_addr(addr):
		if addr[0] == '0':
			addr = addr[1:]
		return addr

	symbols = {}
	bin_path, = get_config(BIN_PATH)

	# nm binary | grep \ T \ 
	command_nm = ['nm', bin_path ]
	command_grep = ['grep', '\ T\ ']
	
	p1 = sp.Popen(command_nm, stdout=sp.PIPE)
	p2 = sp.Popen(command_grep, stdin=p1.stdout, stdout=sp.PIPE)
	nm_out, _ = p2.communicate()
	nm_out = nm_out.decode('utf-8')
	
	for line in nm_out.splitlines():
		split = line.split()
		addr = split[0]
		symbol = split[2]
		symbols[clean_addr(addr)] = symbol


	# objdump -d binary | grep \ plt \
	command_objdump = ['objdump', '-d', bin_path]
	command_grep = ['grep', '@plt\>']

	p3 = sp.Popen(command_objdump, stdout=sp.PIPE)
	p4 = sp.Popen(command_grep, stdin=p3.stdout, stdout=sp.PIPE)
	objdump_out, _ = p4.communicate()
	objdump_out = objdump_out.decode('utf-8')	

	for line in objdump_out.splitlines():
		split = line.split()
		addr = split[-2]
		symbol = split[-1]
		symbol = re.split(r'[@ \< \>]', symbol)[1]		
		symbols[clean_addr(addr)] = symbol 

	return symbols




def timout_handler(signum, frame):
	timeout, stats = get_config(TIMEOUT, STATS)
	if stats:
		save_stats(is_timeout=True)
    
	sys.exit(f'[!] Timeout Detected {timeout} seconds')



def count_fcall(state):
	addr = str(state.inspect.function_address) 	#<BV32 0x80483a3>	
	addr = addr.split()[1] 			 		 	#0x80483a3>
	addr = addr[:-1]					  		#0x80483a3
	addr = addr[2:]								#80483a3

	f_called, = get_stats(F_CALLED)
	if addr in f_called.keys():
		f_called[addr] += 1
	else:
		f_called[addr] = 1
	set_stats((F_CALLED, f_called))



def save_stats(is_timeout=False):

	#Settings
	results_dir, binary, timeout = get_config(RESULTS_DIR, BIN_NAME, TIMEOUT)

	#Statistics
	time_spent, f_called = get_stats(TIME_SPENT, F_CALLED)

	# Create results folder if it does not exist yet
	if not os.path.exists(results_dir):
		os.makedirs(results_dir)        
	
	name = binary
	out_stats = {}
	
	if is_timeout:
		out_stats['Time'] = timeout
	else:
		out_stats['Time'] = time_spent

	out_stats['N_Paths'] = get_num_of_paths()
	
	#Convert function call addrs to symbols
	fnames = get_fnames()
	converted = {}
	for f in f_called.keys():
		if f in fnames.keys():
			fname = fnames[f]
			converted[fname] = f_called[f]

	out_stats['Fcalled'] = converted
	out_stats['Fcalled'].pop('main', None)
	
	out_stats = {name:out_stats}

	file = open(f'{results_dir}/{binary}_stats.json', 'w')
	json_object = json.dumps(out_stats, indent = 2)
	file.write(json_object)
	file.flush()
	file.close()