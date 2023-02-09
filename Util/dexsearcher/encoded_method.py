from automaticvmcracker.Util.dexsearcher import *


class EncodedMethod(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes, size):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.size = size
        self.decode()

    def decode(self):
        for i in range(self.size):
            current_pointer = self.file_pointer.get_pointer()
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)

            current_pointer += last
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)

            current_pointer += last
            code_off, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)

            if code_off != 0:
                self.file_pointer.jump_address(code_off)
                CodeItem(self.file_pointer, self.dex_bytes)
                self.file_pointer.recover_address()
