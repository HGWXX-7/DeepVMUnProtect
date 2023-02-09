from automaticvmcracker.Util.dexsearcher import *

class ProtoIdList(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes, size):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.size = size
        self.decode()

    def decode(self):
        for i in range(self.size):
            current_pointer = self.file_pointer.get_pointer()
            self.file_pointer.read_file(0xc)

            parameters_off = convert_bytes_to_int(self.dex_bytes[current_pointer+0x8: current_pointer+0xc])
            if parameters_off != 0:
                self.file_pointer.jump_address(parameters_off)
                size = convert_bytes_to_int(self.dex_bytes[parameters_off: parameters_off + 4])
                if size % 2 == 1:
                    size += 1
                self.file_pointer.read_file(4 + 2 * size)
                self.file_pointer.recover_address()

