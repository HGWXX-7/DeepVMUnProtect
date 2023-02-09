from automaticvmcracker.Util.dexsearcher import *

class HeaderSection(object):
    def __init__(self, file_pointer:FilePointer, dex_bytes):
        self.file_pointer = file_pointer
        self.dex_bytes = dex_bytes
        self.decode()

    def decode(self):
        self.magic           = self.dex_bytes[0x00:0x08]
        self.checksum        = self.dex_bytes[0x08:0x0C]
        self.signature       = self.dex_bytes[0x0C:0x20]
        self.file_size       = convert_bytes_to_int(self.dex_bytes[0x20:0x24])
        self.header_size     = convert_bytes_to_int(self.dex_bytes[0x24:0x28])
        self.endian_tag      = convert_bytes_to_int(self.dex_bytes[0x28:0x2C])
        self.link_size       = convert_bytes_to_int(self.dex_bytes[0x2C:0x30])
        self.link_off        = convert_bytes_to_int(self.dex_bytes[0x30:0x34])
        self.map_off         = convert_bytes_to_int(self.dex_bytes[0x34:0x38])
        self.string_ids_size = convert_bytes_to_int(self.dex_bytes[0x38:0x3C])
        self.string_ids_off  = convert_bytes_to_int(self.dex_bytes[0x3C:0x40])
        self.type_ids_size   = convert_bytes_to_int(self.dex_bytes[0x40:0x44])
        self.type_ids_off    = convert_bytes_to_int(self.dex_bytes[0x44:0x48])
        self.proto_ids_size  = convert_bytes_to_int(self.dex_bytes[0x48:0x4C])
        self.proto_ids_off   = convert_bytes_to_int(self.dex_bytes[0x4C:0x50])
        self.field_ids_size  = convert_bytes_to_int(self.dex_bytes[0x50:0x54])
        self.field_ids_off   = convert_bytes_to_int(self.dex_bytes[0x54:0x58])
        self.method_ids_size = convert_bytes_to_int(self.dex_bytes[0x58:0x5C])
        self.method_ids_off  = convert_bytes_to_int(self.dex_bytes[0x5C:0x60])
        self.class_defs_size = convert_bytes_to_int(self.dex_bytes[0x60:0x64])
        self.class_defs_off  = convert_bytes_to_int(self.dex_bytes[0x64:0x68])
        self.data_size       = convert_bytes_to_int(self.dex_bytes[0x68:0x6C])
        self.data_off		 = convert_bytes_to_int(self.dex_bytes[0x6C:0x70])

        self.file_pointer.read_file(0x70)

