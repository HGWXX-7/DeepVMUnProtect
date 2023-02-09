from automaticvmcracker.Util.dexsearcher import *


class EncodedArray(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        for i in range(size):
            EncodedValue(self.file_pointer, self.dex_bytes)


class EncodedAnnotation(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.logger = logging.getLogger("EncodedAnnotation")
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        current_pointer += last
        size, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
        self.file_pointer.read_file(last)

        self.logger.debug("current_pc: {}, current_size: {}".format(hex(self.file_pointer.get_pointer()), size))
        for i in range(size):
            # self.logger.debug("we are parsing No.{} EncodedValue, current"
            #                   " current_pointer {}, last {}, pointer{}".format(i, hex(current_pointer), last, hex(self.file_pointer.get_pointer())))
            current_pointer = self.file_pointer.get_pointer()
            _, last = convert_uleb128_to_int(self.dex_bytes[current_pointer: current_pointer+5])
            self.file_pointer.read_file(last)
            # FIXME: last here is wrong, verified, the convert_uleb128_to_int is wrong
            self.logger.debug("last is {}".format(last))
            EncodedValue(self.file_pointer, self.dex_bytes)


class EncodedValue(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.handler = {
            VALUE_BYTE                      : self.value_byte,
            VALUE_SHORT                     : self.parse_ubyte_array,
            VALUE_CHAR                      : self.parse_ubyte_array,
            VALUE_INT                       : self.parse_ubyte_array,
            VALUE_LONG                      : self.parse_ubyte_array,
            VALUE_FLOAT                     : self.parse_ubyte_array,
            VALUE_DOUBLE                    : self.parse_ubyte_array,
            VALUE_STRING                    : self.parse_ubyte_array,
            VALUE_TYPE                      : self.parse_ubyte_array,
            VALUE_FIELD                     : self.parse_ubyte_array,
            VALUE_METHOD                    : self.parse_ubyte_array,
            VALUE_ENUM                      : self.parse_ubyte_array,
            VALUE_ARRAY                     : self.value_array,
            VALUE_ANNOTATION                : self.value_annotation,
            VALUE_NULL                      : self.parse_nothing,
            VALUE_BOOLEAN                   : self.parse_nothing
        }
        self.logger = logging.getLogger("EncodedValue")
        self.decode()

    def value_byte(self, size):
        assert size == 0, "[FATAL]: encoded_value does not equal to zero, offset is {}".format(self.file_pointer.get_pointer())

        self.file_pointer.read_file(1)

    def parse_ubyte_array(self, size):
        size += 1
        self.file_pointer.read_file(size)

    def value_array(self, size):
        EncodedArray(self.file_pointer, self.dex_bytes)

    def value_annotation(self, size):
        EncodedAnnotation(self.file_pointer, self.dex_bytes)

    def parse_nothing(self, size):
        pass

    def parse_unknows(self, size):
        print("unknown type parsed, current offset is:{}".format(self.file_pointer.get_pointer()))

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        self.logger.debug("before parsing type_args, current pointer is: {}".format(hex(current_pointer)))
        value_type, value_arg = parse_value_type(self.dex_bytes[current_pointer])
        self.file_pointer.read_file(1)

        self.logger.debug("value_arg is {}".format(value_arg))
        self.logger.debug("value_type is {}".format(value_type))
        self.logger.debug("current_pointer is {}".format(hex(current_pointer+1)))
        handler = self.handler.get(value_type, self.parse_unknows)
        handler(value_arg)


