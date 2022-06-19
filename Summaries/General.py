from angr import SimProcedure

class _malloc(SimProcedure):
	def run(self, sim_size):
		return self.state.heap.malloc(sim_size)

class _free(SimProcedure):
	def run(self, ptr):
		self.state.heap.free(ptr)

class _calloc(SimProcedure):
	def run(self, sim_nmemb, sim_size):
		return self.state.heap.calloc(sim_nmemb, sim_size)

class _realloc(SimProcedure):
	def run(self, ptr, size):
		return self.state.heap.realloc(ptr, size)        