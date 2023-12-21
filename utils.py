import subprocess as sp
import json
import time
import os
import re

import claripy

from config import get_config, get_stats, set_stats, get_SimManager
from macros import RESULTS_DIR, BIN_NAME, BIN_PATH, TIMEOUT, STATS
from macros import TIME_SPENT, F_CALLED, F_NAMES, PATHS_DIR, SYM_VAR


def get_paths():
	paths = get_SimManager().deadended + get_SimManager().active
	return paths


def write2file(file, var):
	with open(file,'a') as f:
		f.write(f'{var}\n')

def truncate(file):
	with open(file,'w'):
		return

def save_paths(states):
	paths_dir, bin_name = get_config(PATHS_DIR, BIN_NAME)

	# Create results folder if it does not exist yet
	if not os.path.exists(paths_dir):
		os.makedirs(paths_dir)     

	def filter_gen(var):
		if SYM_VAR in str(var):
			return True
		return False
	
	id = 0
	for state in states:
		file = f'{paths_dir}/{bin_name}_{id}.path'
		truncate(file)
		
		vars = state.solver.all_variables
		vars = list(filter(filter_gen, vars))	
		
		for var in vars:
			v = state.solver.eval(var)
			write2file(file, v)
		id += 1


def get_fnames():

	def clean_addr(addr):
		addr = re.sub(r'^0+', '', addr)
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
    
	print(f'[!] Timeout Detected {timeout} seconds')
	os._exit(0)



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



def save_stats(is_timeout=False, exception=None, start=None):
	
	#Settings
	results_dir, binary, timeout = get_config(RESULTS_DIR, BIN_NAME, TIMEOUT)

	#Statistics
	time_spent, f_called, fnames = get_stats(TIME_SPENT, F_CALLED, F_NAMES)

	# Create results folder if it does not exist yet
	if not os.path.exists(results_dir):
		os.makedirs(results_dir)        
	
	out_stats = {}
	
	if exception:
		time_spent = round(time.time()-start, 4)
		out_stats['Exception'] = f'{type(exception)}:{exception}'
	
	if is_timeout:
		out_stats['Time'] = f'Timeout:{timeout}'
	else:
		out_stats['Time'] = time_spent

	out_stats['T_Solver'] = round(claripy.SOLVER_TIME, 4)
	out_stats['N_Paths'] = len(get_paths())
	
	#Convert function call addrs to symbols
	converted = {}
	for f in f_called.keys():
		if f in fnames.keys():
			fname = fnames[f]
			converted[fname] = f_called[f]

	out_stats['Fcalled'] = converted
	out_stats['Fcalled'].pop('main', None)
	
	out_stats = {binary:out_stats}

	file = open(f'{results_dir}/{binary}_stats.json', 'w')
	json_object = json.dumps(out_stats, indent = 2)
	file.write(json_object)
	file.flush()
	file.close()