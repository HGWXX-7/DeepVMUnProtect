from automaticvmcracker.Util.dexsearcher import *

class ClassDataItem(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        static_fields_size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        current_pointer += last
        instance_fields_size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        current_pointer += last
        direct_methods_size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        current_pointer += last
        virtual_methods_size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        if static_fields_size > 0:
            EncodedFieldList(self.file_pointer, self.dex_bytes, static_fields_size)

        if instance_fields_size > 0:
            EncodedFieldList(self.file_pointer, self.dex_bytes, instance_fields_size)

        if direct_methods_size > 0:
            EncodedMethod(self.file_pointer, self.dex_bytes, direct_methods_size)

        if virtual_methods_size > 0:
            EncodedMethod(self.file_pointer, self.dex_bytes, virtual_methods_size)
