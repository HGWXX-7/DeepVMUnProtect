from automaticvmcracker.Util.dexsearcher import *


class EncodedMethodLists(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes, size):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.size = size
        self.decode()

    def decode(self):
        EncodedMethod(self.file_pointer, self.dex_bytes, self.size)
