from automaticvmcracker.Util.dexsearcher import *


class EncodedFieldList(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes, size):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.size = size
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        for i in range(self.size):
            # read filed_idx_diff
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)
            current_pointer += last

            # read access_flags
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)
            current_pointer += last
