from automaticvmcracker.Util.dexsearcher import *


class CodeItem(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        begin_off = self.file_pointer.get_pointer()
        tries_size = convert_bytes_to_short(self.dex_bytes[begin_off+6: begin_off+8])
        debug_info_off = convert_bytes_to_int(self.dex_bytes[begin_off+8: begin_off+12])
        insns_size = convert_bytes_to_int(self.dex_bytes[begin_off+12: begin_off+16])
        self.file_pointer.read_file(16 + 2 * insns_size)

        if debug_info_off != 0:
            self.file_pointer.jump_address(debug_info_off)
            DebugInfoItem(self.file_pointer, self.dex_bytes)
            self.file_pointer.recover_address()

        if tries_size != 0:
            if insns_size & 1 == 1:
                self.file_pointer.read_file(2)

            self.file_pointer.read_file(8 * tries_size)

            current_pointer = self.file_pointer.get_pointer()
            size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)

            current_pointer += last
            for i in range(size):
                catch_type_size, last = convert_sleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
                current_pointer += last
                self.file_pointer.read_file(last)

                if catch_type_size != 0:
                    numhandlers = abs(catch_type_size)
                    for j in range(numhandlers):
                        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
                        self.file_pointer.read_file(last)
                        current_pointer += last

                        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
                        self.file_pointer.read_file(last)
                        current_pointer += last

                if catch_type_size <= 0:
                    current_pointer = self.file_pointer.get_pointer()
                    _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
                    self.file_pointer.read_file(last)
                    current_pointer += last
