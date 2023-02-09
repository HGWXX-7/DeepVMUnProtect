from automaticvmcracker.Util.dexsearcher import *

class AnnotationItem(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        # read VISIBILITY
        self.file_pointer.read_file(1)
        EncodedAnnotation(self.file_pointer, self.dex_bytes)

