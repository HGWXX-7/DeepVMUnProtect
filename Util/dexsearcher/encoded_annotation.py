from automaticvmcracker.Util.dexsearcher import *


class EncodedAnnotation(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        current_pointer += last
        size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        for i in range(size):
            current_pointer += last
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)
            EncodedValue(self.file_pointer, self.dex_bytes)


