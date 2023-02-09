from automaticvmcracker.Util.dexsearcher import *

class AnnotationsDirectionItem(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        current_pointer = self.file_pointer.get_pointer()
        class_annotations_off = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
        current_pointer += 4

        fields_size = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
        current_pointer += 4

        annotated_methods_size = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
        current_pointer += 4

        annotated_parameters_size = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
        current_pointer += 4
        self.file_pointer.read_file(16)

        if class_annotations_off != 0:
            self.file_pointer.jump_address(class_annotations_off)
            AnnotationsSetItem(self.file_pointer, self.dex_bytes)
            self.file_pointer.recover_address()

        if fields_size > 0:
            for i in range(fields_size):
                # read field_idx
                self.file_pointer.read_file(4)
                current_pointer = self.file_pointer.get_pointer()

                # read annotations_off
                annotations_off = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
                self.file_pointer.read_file(4)
                if annotations_off != 0:
                    self.file_pointer.jump_address(annotations_off)
                    AnnotationsSetItem(self.file_pointer, self.dex_bytes)
                    self.file_pointer.recover_address()

        if annotated_methods_size > 0:
            for i in range(annotated_methods_size):
                # read field_idx
                self.file_pointer.read_file(4)
                current_pointer = self.file_pointer.get_pointer()

                # read annotations_off
                annotations_off = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
                self.file_pointer.read_file(4)
                if annotations_off != 0:
                    self.file_pointer.jump_address(annotations_off)
                    AnnotationsSetItem(self.file_pointer, self.dex_bytes)
                    self.file_pointer.recover_address()

        if annotated_parameters_size > 0:
            for i in range(annotated_parameters_size):
                # read field_idx
                self.file_pointer.read_file(4)
                current_pointer = self.file_pointer.get_pointer()

                # read annotations_off
                annotations_off = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
                self.file_pointer.read_file(4)
                if annotations_off != 0:
                    # read size in annotation_set_ref_list
                    self.file_pointer.jump_address(annotations_off)
                    current_pointer = self.file_pointer.get_pointer()
                    size = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
                    self.file_pointer.read_file(4)
                    current_pointer += 4

                    for j in range(size):
                        # read annotations_off in annotation_set_ref_item
                        annotations_off = convert_bytes_to_int(self.dex_bytes[current_pointer: current_pointer+4])
                        if annotations_off != 0:
                            self.file_pointer.jump_address(annotations_off)
                            AnnotationsSetItem(self.file_pointer, self.dex_bytes)
                            self.file_pointer.recover_address()
                        self.file_pointer.read_file(4)
                        current_pointer += 4
                    self.file_pointer.recover_address()

