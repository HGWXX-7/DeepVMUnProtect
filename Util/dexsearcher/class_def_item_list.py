from automaticvmcracker.Util.dexsearcher import *


class ClassDefItemList(object):
    def __init__(self, file_pointer: FilePointer, dex_bytes, size):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.size = size
        self.logger = logging.getLogger('ClassDefItemList')
        self.decode()

    def decode(self):
        self.logger.debug("class number:{}".format(self.size))
        for i in range(self.size):
            current_pointer = self.file_pointer.get_pointer()
            interfaces_off = convert_bytes_to_int(self.dex_bytes[current_pointer+0xc: current_pointer+0x10])
            annotations_off = convert_bytes_to_int(self.dex_bytes[current_pointer+0x14: current_pointer+0x18])
            class_data_off = convert_bytes_to_int(self.dex_bytes[current_pointer+0x18: current_pointer+0x1c])
            static_values_off = convert_bytes_to_int(self.dex_bytes[current_pointer+0x1c: current_pointer+0x20])
            self.file_pointer.read_file(0x20)

            self.logger.debug("No.{} class".format(i))
            self.logger.debug("current pointer:{}".format(self.file_pointer.get_pointer()))
            self.logger.debug("interfaces offset:{}".format(interfaces_off))
            self.logger.debug("annotations offset:{}".format(annotations_off))
            self.logger.debug("class data offset:{}".format(class_data_off))
            self.logger.debug("static values offset:{}".format(static_values_off))

            # handle interfaces_off
            if interfaces_off != 0:
                self.file_pointer.jump_address(interfaces_off)
                InterfaceItemList(self.file_pointer, self.dex_bytes)
                self.file_pointer.recover_address()

            # handle annotations_off
            if annotations_off != 0:
                self.file_pointer.jump_address(annotations_off)
                AnnotationsDirectionItem(self.file_pointer, self.dex_bytes)
                self.file_pointer.recover_address()

            # handle class data off
            if class_data_off != 0:
                self.file_pointer.jump_address(class_data_off)
                ClassDataItem(self.file_pointer, self.dex_bytes)
                self.file_pointer.recover_address()

            # handle static_values_off:
            if static_values_off != 0:
                self.file_pointer.jump_address(static_values_off)
                EncodedArray(self.file_pointer, self.dex_bytes)
                self.file_pointer.recover_address()


