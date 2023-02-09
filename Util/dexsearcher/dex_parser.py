from automaticvmcracker.Util.dexsearcher import *


class DexParser(object):
    def __init__(self, file_path):
        self.dex_bytes = np.fromfile(file_path, dtype=np.ubyte)
        self.file_pointer = FilePointer(len(self.dex_bytes))
        self.logger = logging.getLogger("DexParser")
        self.decode()

    def decode(self):
        header = HeaderSection(self.file_pointer, self.dex_bytes)
        StringIdList(self.file_pointer, self.dex_bytes, header.string_ids_size)
        TypeIdList(self.file_pointer, self.dex_bytes, header.type_ids_size)
        ProtoIdList(self.file_pointer, self.dex_bytes, header.proto_ids_size)
        FieldIdList(self.file_pointer, self.dex_bytes, header.field_ids_size)
        MethodIdList(self.file_pointer, self.dex_bytes, header.method_ids_size)
        ClassDefItemList(self.file_pointer, self.dex_bytes, header.class_defs_size)

        self.file_pointer.jump_address(header.map_off)
        MapListType(self.file_pointer, self.dex_bytes)
        self.file_pointer.recover_address()


    def check_unlinked_block(self, start, limit):
        '''
        :param start:
        :param limit:
        :return: whether the unlinked start address and end address can construct an unlinked block
        util now, rules are still simple
        '''
        start_address = -1
        bytecode_number = -1


        if start < limit:
            # First skip all of the zeros
            while self.dex_bytes[start] == 0:
                start += 1

            # check length of code item, must larger than 16
            if limit - start > 16:
                length = convert_bytes_to_int(self.dex_bytes[start+12: start+16])
                end = start + 16 + length * 2 - 1
                # check whether end less than limit
                self.logger.debug("length is{}; end is{}".format(hex(length), hex(end)))
                if end <= limit:
                    # check whether the data in byte[end:limit] equals to zero
                    # the byte between end and limit can be anything I think so the following lines will be commented
                    # flag = True
                    # for i in range(end+1, limit+1):
                    #     if self.dex_bytes[i] != 0:
                    #         flag = False
                    #         break
                    # if flag:
                    start_address = start + 16
                    bytecode_number = convert_bytes_to_int(self.dex_bytes[start+12: start+16])

        return start_address, bytecode_number

    def get_unlinked_block(self):
        #FIXME: YOU SHOULD CHECK IT AGAIN

        hwbp_addr = []
        bytecode_numbers = []
        is_recording = False
        begin = 0
        end = 0

        for index, is_accessed in enumerate(self.file_pointer.addr_counter):
            if not is_accessed:
                if not is_recording:
                    begin = index
                    end = index
                    is_recording = True
                else:
                    end = index
            else:
                if is_recording:
                    is_recording = False
                    offset, bytecode_number = self.check_unlinked_block(begin, end)
                    if offset != -1 and bytecode_number != -1:
                        hwbp_addr.append(hex(offset))
                        bytecode_numbers.append(bytecode_number)

        reshaped_breakpoints = []

        for i in range(0, len(hwbp_addr), 4):
            reshaped_breakpoints.append(hwbp_addr[i: i + 4])

        reshaped_bytecode_numbers = []

        for i in range(0, len(bytecode_numbers), 4):
            reshaped_bytecode_numbers.append(bytecode_numbers[i: i + 4])

        return reshaped_breakpoints, reshaped_bytecode_numbers


    def get_accessed_block(self):
        accessed_block = []
        is_recording = False
        begin = 0
        end = 0

        for index, is_accessed in enumerate(self.file_pointer.addr_counter):
            if is_accessed:
                if not is_recording:
                    begin = index
                    end = index
                    is_recording = True
                else:
                    end = index
            else:
                if is_recording:
                    is_recording = False
                    accessed_block.append((hex(begin), hex(end)))

        return accessed_block


# def main():
#     dex_parser_obj = DexParser("/home/morangeous/bigtest/android_project/useful_tools/MyDexParser/dexparser/data/1917764_dexfile_execute.dex")
#     dex_parser_obj.decode()
#     print(dex_parser_obj.get_unlinked_block())
#
#
# if __name__ == '__main__':
#     main()


