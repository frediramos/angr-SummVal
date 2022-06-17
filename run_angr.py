#!/usr/bin/env python3
import argparse
import logging
import signal
import time

from angr import Project
from angr import options, BP_AFTER

import API.Validation as Validation_API
import API.Solver as Solver_API
import API.Constraints as Constraints_API

from macros import *
from config import set_config, get_config
from config import set_stats, set_SimManager

from utils import save_stats, timout_handler, count_fcall

def cmd_args():
	parser = argparse.ArgumentParser(description='angr extension for summary testing/validation')

	group1 = parser.add_argument_group('General')
	group2 = parser.add_argument_group('Summary Validation')

	group1.add_argument('binary', metavar='bin', type=str,
						help='Path to the target binary')

	group1.add_argument('-stats', action='store_true',
						help='Save execution statistics in a Json file', default=False)

	group1.add_argument('--results', metavar='path', type=str,
						help='Directory where outputs should saved (default: ./)', default='.')   

	group1.add_argument('--timeout', metavar='sec', type=int,
						help='Execution Timeout in seconds (default: 1800sec, 30min)', default=30*60)    													
	
	group1.add_argument('-debug', action='store_true',
						help='Enable debug logging to console')

	group1.add_argument('--summ_ignore', metavar='file', type=str,
						help='Do NOT use summaries for functions in the given input file', default=None)						
	
	group2.add_argument('-ascii', action='store_true',
						help='Convert ASCII values to characters in counterexamples')

	return parser.parse_args()


def setup():

	args = cmd_args()
	
	#Binary
	binary_path = args.binary
	binary_name = binary_path.split('/')[-1]

	#General options
	timeout = args.timeout
	stats = args.stats
	ignore = args.summ_ignore

	results_dir = args.results
	if results_dir[-1] == '/':
		results_dir = results_dir[:-1]
	
	if args.debug:
		logging.getLogger('angr').setLevel('DEBUG')	

	#Validation options
	convert_chars = args.ascii

	#Save config options
	settings = [
		(BIN_PATH, binary_path),
		(BIN_NAME, binary_name),
		(CONVERT_CHARS, convert_chars),
		(RESULTS_DIR, results_dir),
		(TIMEOUT, timeout),
		(STATS, stats)
	]
	set_config(*settings)

	return binary_path



if __name__ == "__main__":

	binary = setup()
	print_stats, = get_config(STATS)

	#Import Binary
	p = Project(binary)

	#Hook API symbols
	#Solver
	p.hook_symbol('new_sym_var_named', Solver_API.new_sym_var_named())
	p.hook_symbol('new_sym_var_array', Solver_API.new_sym_var_array())
	p.hook_symbol('is_symbolic', Solver_API.is_symbolic())
	p.hook_symbol('is_sat', Solver_API.is_sat())
	p.hook_symbol('assume', Solver_API.assume())
	p.hook_symbol('maximize', Solver_API.maximize())
	p.hook_symbol('minimize', Solver_API.minimize())

	#Validation
	p.hook_symbol('halt_all', Validation_API.halt_all())
	p.hook_symbol('mem_addr', Validation_API.mem_addr())
	p.hook_symbol('save_current_state', Validation_API.save_current_state())
	p.hook_symbol('get_cnstr', Validation_API.get_cnstr())
	p.hook_symbol('store_cnstr', Validation_API.store_cnstr())
	p.hook_symbol('check_implications', Validation_API.check_implications())
	p.hook_symbol('print_counterexamples', Validation_API.print_counterexamples())

	#Constraints
	p.hook_symbol('_solver_EQ', Constraints_API.solver_EQ())
	p.hook_symbol('_solver_NEQ', Constraints_API.solver_NEQ())
	p.hook_symbol('_solver_LT', Constraints_API.solver_LT())
	p.hook_symbol('_solver_LE', Constraints_API.solver_LE())
	p.hook_symbol('_solver_SLE', Constraints_API.solver_SLE())
	p.hook_symbol('_solver_SLT', Constraints_API.solver_SLT())
	p.hook_symbol('_solver_NOT', Constraints_API.solver_NOT())
	p.hook_symbol('_solver_Or', Constraints_API.solver_Or())
	p.hook_symbol('_solver_And', Constraints_API.solver_And())
	p.hook_symbol('_solver_ITE', Constraints_API.solver_ITE())
	p.hook_symbol('_solver_ITE_VAR', Constraints_API.solver_ITE_VAR())


	state = p.factory.entry_state(add_options={options.TRACK_SOLVER_VARIABLES})
	state.libc.simple_strtok = False

	if print_stats:
		state.inspect.b('call', when=BP_AFTER, action=count_fcall)
	
	sm = p.factory.simulation_manager(state)
	set_SimManager(sm)
	

	#Register Timeout
	timeout_val, = get_config(TIMEOUT)
	signal.signal(signal.SIGALRM, timout_handler)
	signal.alarm(timeout_val)

	#Run Symbolic Execution
	start = time.time()
	sm.run()
	end = time.time()

	#Store execution time
	set_stats((TIME_SPENT, round(end-start, 4)))


	if print_stats:
		save_stats()


