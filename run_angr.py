#!/usr/bin/env python3
import argparse

import logging
from angr import Project, options

import API.Validation as Validation_API
import API.Solver as Solver_API
import API.Constraints as Constraints_API
import config


def cmd_args():
	parser = argparse.ArgumentParser(description='angr summary validation')
	
	parser.add_argument('--json_log', metavar='path', type=str,
						help='Save counterexample results in a json file', default=None)
	
	parser.add_argument('-ascii', action='store_true',
						help='Convert ASCII values to characters when displaying counterexamples')

	parser.add_argument('-debug', action='store_true',
						help='Enable debug logging to console')

	parser.add_argument('binary', metavar='path', type=str,
						help='Path to the validation test binary')


	return parser.parse_args()


def setup():

	args = cmd_args()
	
	#Binary
	binary_path = args.binary
	binary_name = binary_path.split('/')[-1]

	#Options
	json_log = args.json_log
	if json_log is not None:
		if not json_log.endswith('.json'):
			json_log = json_log + '.json'
	else:
		json_log = f'./{binary_name}.json'

	if args.debug:
		logging.getLogger('angr').setLevel('DEBUG')	

	convert_chars = args.ascii

	config.Settings['binary_path'] = binary_path
	config.Settings['binary_name'] = binary_name
	config.Settings['json_log'] = json_log
	config.Settings['convert_chars'] = convert_chars

	return binary_path



if __name__ == "__main__":

	binary = setup()

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
	sm = p.factory.simulation_manager(state)

	Validation_API.SM = sm


	sm.run()
