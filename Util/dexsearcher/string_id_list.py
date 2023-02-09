from automaticvmcracker.Util.dexsearcher import *

class StringIdList(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes, size):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.size = size
        self.logger = logging.getLogger("StringIdList")
        self.decode()

    def get_string_length(self):
        counter = 0
        current_pointer = self.file_pointer.get_pointer()
        while self.dex_bytes[counter + current_pointer] != 0:
            counter += 1

        return counter + 1

    def decode(self):
        for i in range(self.size):
            current_pointer = self.file_pointer.get_pointer()
            string_data_off = convert_bytes_to_int(self.dex_bytes[current_pointer:current_pointer+0x4])

            self.file_pointer.read_file(0x4)
            self.file_pointer.jump_address(string_data_off)
            # read array length
            size, last = convert_uleb128_to_int(self.dex_bytes[string_data_off: string_data_off + 5])
            self.file_pointer.read_file(last)
            last = self.get_string_length()
            self.file_pointer.read_file(last)
            self.file_pointer.recover_address()

