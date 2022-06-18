from angr import SimProcedure

class _fgets(SimProcedure):

	def run(self, stringAddr, length, stream):

		if(self.state.solver.symbolic(length)):
			constraints = tuple(self.state.solver.constraints)
			length = self.state.solver.max(sym_var, extra_constraints=(constraints))

		size = self.state.solver.eval(length)

		while size-1 > 0:
			sym_var = self.state.solver.BVS("symvar", 8)
			self.state.memory.store(stringAddr,sym_var)
			stringAddr += 1
			size -= 1

		self.state.memory.store(stringAddr, b'\0')

		self.ret(stringAddr)


class _malloc(SimProcedure):
	def run(self, sim_size):
		return self.state.heap._malloc(sim_size)

class _free(SimProcedure):
	def run(self, ptr):
		self.state.heap._free(ptr)

class _calloc(SimProcedure):
	def run(self, sim_nmemb, sim_size):
		return self.state.heap._calloc(sim_nmemb, sim_size)

class _realloc(SimProcedure):
	def run(self, ptr, size):
		return self.state.heap._realloc(ptr, size)        