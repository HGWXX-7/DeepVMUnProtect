from automaticvmcracker.Util.dexsearcher import *


class FilePointer(object):
    def __init__(self, addr_limit, pointer=0):
        self.pointer = pointer
        self.addr_counter = np.full(addr_limit, False, dtype=bool)
        self.last_addr = []
        self.logger = logging.getLogger("FilePointer")

    def jump_address(self, dest_addr):
        self.last_addr.append(self.pointer)
        self.pointer = dest_addr

    def recover_address(self):
        self.pointer = self.last_addr.pop()

    def get_pointer(self):
        return self.pointer

    def set_pointer(self, pointer):
        self.pointer = pointer

    def read_file(self, step):
        # self.logger.debug("before step, pointer:{}, step:{}".format(self.pointer, step))
        self.addr_counter[self.pointer: self.pointer+step] = True
        self.pointer += step
        # self.logger.debug("after step, pointer:{}, step:{}".format(self.pointer, step))




