from automaticvmcracker.Util.dexsearcher import *

class InterfaceItemList(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        size = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
        self.file_pointer.read_file(4 + size * 2)
