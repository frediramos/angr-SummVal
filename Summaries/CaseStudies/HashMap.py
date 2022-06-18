from angr import SimProcedure

HASH_COUNTER = 0
class hashmap_hash(SimProcedure):


    def run(self, strkey, maxHash):
        maxHash = self.state.solver.eval(maxHash)     
        global HASH_COUNTER
        hash_value = HASH_COUNTER % (maxHash + 1)
        HASH_COUNTER += 1 
        print('hashmap_hash:',hash_value)
        self.ret(hash_value)