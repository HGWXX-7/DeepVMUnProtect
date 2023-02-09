from automaticvmcracker.Util.dexsearcher import *

class AnnotationsSetItem(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.logger = logging.getLogger("AnnotationsSetItem")

        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        self.logger.debug("before get size, current_pointer:{}".format(current_pointer))
        size = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
        current_pointer += 4
        self.file_pointer.read_file(4)

        self.logger.debug("current pointer is {}".format(hex(current_pointer)))
        for i in range(size):
            annotation_off = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
            self.file_pointer.read_file(4)
            current_pointer += 4

            self.logger.debug("No.{} annotation item, annotation_off is :{}".format(i, hex(annotation_off)))
            if annotation_off != 0:
                # Annotation_off_item
                self.file_pointer.jump_address(annotation_off)
                AnnotationItem(self.file_pointer, self.dex_bytes)
                self.file_pointer.recover_address()


