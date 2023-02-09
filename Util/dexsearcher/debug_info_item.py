from automaticvmcracker.Util.dexsearcher import *

class DebugInfoItem(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.handler = {
            DBG_ADVANCE_PC:             self.advance_pc,
            DBG_ADVANCE_LINE:           self.advance_line,
            DBG_START_LOCAL:            self.start_local,
            DBG_START_LOCAL_EXTENDED:   self.start_local_extended,
            DBG_END_LOCAL:              self.end_local,
            DBG_RESTART_LOCAL:          self.restart_local,
            DBG_SET_PROLOGUE_END:       self.set_prologue_end,
            DBG_SET_EPILOGUE_BEGIN:     self.set_epilogue_begin
        }
        self.decode()

    def advance_pc(self):
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def advance_line(self):
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_sleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def start_local(self):
        # read register_number
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        # read name_idx
        current_pointer += last
        _, last = convert_uleb128p1_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        # read type_idx
        current_pointer += last
        _, last = convert_uleb128p1_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def start_local_extended(self):
        self.start_local()

        # read sig_idx
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128p1_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def end_local(self):
        # read register_num
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def restart_local(self):
        # read register_num
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def set_prologue_end(self):
        pass

    def set_epilogue_begin(self):
        pass

    def set_file(self):
        # read name_idx
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128p1_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

    def default_handler(self):
        pass

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        # read line_start
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)
        current_pointer += last
        # read parameter size
        parameters_size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)
        current_pointer += last

        # read parameter_names
        for i in range(parameters_size):
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)
            current_pointer += last


        # read opcode
        while True:
            opcode = convert_bytes_to_short(self.dex_bytes[current_pointer: current_pointer+2])
            current_pointer += 2
            self.file_pointer.read_file(2)

            if opcode == DBG_END_SEQUENCE:
                break
            else:
                handler = self.handler.get(opcode, self.default_handler)
                handler()

