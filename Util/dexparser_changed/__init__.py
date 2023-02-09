import struct
import mmap
import sys
import os
from os.path import abspath, join, dirname
current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(current_dir)
sys.path.append("..")
sys.path.append("../dexparser")

from dexparser import disassembler
from dexparser.errors import InsufficientParameterError
from dexparser.utils import uleb128_value, encoded_field, encoded_method, encoded_annotation

class Dexparser(object):
    """DEX file format parser class
    :param string filedir: DEX file path
    :param bytes fileobj: DEX file object
    """
    def __init__(self, filedir=None, fileobj=None):
        if not filedir and not fileobj:
            raise InsufficientParameterError('fileobj or filedir parameter required.')

        if filedir:
            if not os.path.isfile(filedir):
                raise FileNotFoundError

            with open(filedir, 'rb') as f:
                self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        if fileobj:
            self.data = fileobj

        self.header_data = {
            'magic': self.data[0:8],
            'checksum': struct.unpack('<L', self.data[8:0xC])[0],
            'signiture': self.data[0xC:0x20],
            'file_size': struct.unpack('<L', self.data[0x20:0x24])[0],
            'header_size': struct.unpack('<L', self.data[0x24:0x28])[0],
            'endian_tag': struct.unpack('<L', self.data[0x28:0x2C])[0],
            'link_size': struct.unpack('<L', self.data[0x2C:0x30])[0],
            'link_off': struct.unpack('<L', self.data[0x30:0x34])[0],
            'map_off': struct.unpack('<L', self.data[0x34:0x38])[0],
            'string_ids_size': struct.unpack('<L', self.data[0x38:0x3C])[0],
            'string_ids_off': struct.unpack('<L', self.data[0x3C:0x40])[0],
            'type_ids_size': struct.unpack('<L', self.data[0x40:0x44])[0],
            'type_ids_off': struct.unpack('<L', self.data[0x44:0x48])[0],
            'proto_ids_size': struct.unpack('<L', self.data[0x48:0x4C])[0],
            'proto_ids_off': struct.unpack('<L', self.data[0x4C:0x50])[0],
            'field_ids_size': struct.unpack('<L', self.data[0x50:0x54])[0],
            'field_ids_off': struct.unpack('<L', self.data[0x54:0x58])[0],
            'method_ids_size': struct.unpack('<L', self.data[0x58:0x5C])[0],
            'method_ids_off': struct.unpack('<L', self.data[0x5C:0x60])[0],
            'class_defs_size': struct.unpack('<L', self.data[0x60:0x64])[0],
            'class_defs_off': struct.unpack('<L', self.data[0x64:0x68])[0],
            'data_size': struct.unpack('<L', self.data[0x68:0x6C])[0],
            'data_off': struct.unpack('<L', self.data[0x6C:0x70])[0]
        }

    @property
    def header(self):
        """Get header data from DEX

        :returns: header data

        example:
            >>> Dexparser(filedir='path/to/classes.dex').header
            {'magic': 'dex\x035' ...}
        """
        return self.header_data

    @property
    def checksum(self):
        """Get checksum value of DEX file

        :returns: hexlify value of checksum

        example:
            >>> Dexparser(filedir='path/to/classes.dex').checksum
            0x30405060
        """
        return "%x" %self.header_data.get('checksum')

    def get_strings(self):
        """Get string items from DEX file

        :returns: strings extracted from string_data_item section

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_strings()
            ['Ljava/utils/getJavaUtils', ...]
        """
        strings = []
        string_ids_off = self.header_data['string_ids_off']

        for i in range(self.header_data['string_ids_size']):
            offset = struct.unpack('<L', self.data[string_ids_off+(i*4):string_ids_off+(i*4)+4])[0]
            c_size = self.data[offset]
            c_char = self.data[offset+1:offset+1+c_size]
            strings.append(c_char)

        return strings

    def get_string_by_idx(self, string_index):
        '''Get string by string index instead of the

        :param string_index:
        :return: string: a string in the string_index of string pool
        '''
        string_ids_off = self.header_data['string_ids_off']
        offset = struct.unpack('<L', self.data[string_ids_off+(string_index*4):string_ids_off+(string_index*4)+4])[0]
        c_size = self.data[offset]
        c_char = self.data[offset + 1:offset + 1 + c_size]
        return c_char.decode(encoding='utf-8')

    def get_method_name_by_idx(self, method_index):
        '''Get method name by method index

        :param method_index:
        :return:
        '''
        offset = self.header_data['method_ids_off']
        name_idx = struct.unpack('<L', self.data[offset + (method_index * 8) + 4:offset + (method_index * 8) + 8])[0]
        name = self.get_string_by_idx(name_idx)
        return name


    def get_typeids(self):
        """Get type ids from DEX file

        :returns: descriptor_idx extracted from type_id_item section

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_typeids()
            [133, 355, 773, 494, ...]
        """
        typeids = []
        offset = self.header_data['type_ids_off']

        for i in range(self.header_data['type_ids_size']):
            idx = struct.unpack('<L', self.data[offset+(i*4):offset+(i*4)+4])[0]
            typeids.append(idx)

        return typeids

    def get_methods(self):
        """Get methods from DEX file

        :returns: list of methods defined at DEX file

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_methods()
            [{'class_idx': 132, 'proto_idx': 253, 'name_idx': 3005}, ...]
        """
        methods = []
        offset = self.header_data['method_ids_off']

        for i in range(self.header_data['method_ids_size']):
            class_idx = struct.unpack('<H', self.data[offset+(i*8):offset+(i*8)+2])[0]
            proto_idx = struct.unpack('<H', self.data[offset+(i*8)+2:offset+(i*8)+4])[0]
            name_idx = struct.unpack('<L', self.data[offset+(i*8)+4:offset+(i*8)+8])[0]
            methods.append({'class_idx': class_idx, 'proto_idx': proto_idx, 'name_idx': name_idx})

        return methods

    def get_protoids(self):
        """Get proto idx from DEX file

        :returns: list of proto ids defined at proto_id_item

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_protoids()
            [{'shorty_idx': 3000, 'return_type_idx': 330, 'param_off': 0}, ...]
        """
        protoids = []
        offset = self.header_data['proto_ids_off']

        for i in range(self.header_data['proto_ids_size']):
            shorty_idx = struct.unpack('<L', self.data[offset+(i*12):offset+(i*12)+4])[0]
            return_type_idx = struct.unpack('<L', self.data[offset+(i*12)+4:offset+(i*12)+8])[0]
            param_off = struct.unpack('<L', self.data[offset+(i*12)+8:offset+(i*12)+12])[0]
            protoids.append({'shorty_idx': shorty_idx, 'return_type_idx': return_type_idx, 'param_off': param_off})

        return protoids

    def get_fieldids(self):
        """Get field idx from DEX file

        :returns: list of field ids defined at field_id_item

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_fieldids()
            [{'class_idx': 339, 'type_idx': 334, 'name_idx': 340}, ...]
        """
        fieldids = []
        offset = self.header_data['field_ids_off']

        for i in range(self.header_data['field_ids_size']):
            class_idx = struct.unpack('<H', self.data[offset+(i*8):offset+(i*8)+2])[0]
            type_idx  = struct.unpack('<H', self.data[offset+(i*8)+2:offset+(i*8)+4])[0]
            name_idx  = struct.unpack('<L', self.data[offset+(i*8)+4:offset+(i*8)+8])[0]
            fieldids.append({'class_idx': class_idx, 'type_idx': type_idx, 'name_idx': name_idx})

        return fieldids

    def get_classdef_data(self):
        """Get class definition data from DEX file

        :returns: list of class definition data extracted from class_def_item

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_classdef_data()
            [
                {
                    'class_idx': 3049,
                    'access_flags': 4000,
                    'superclass_idx': 200,
                    'interfaces_off': 343,
                    'source_file_idx': 3182,
                    'annotation_off': 343,
                    'class_data_off': 345,
                    'static_values_off': 8830
                },
                ...
            ]
        """
        classdef_data = []
        offset = self.header_data['class_defs_off']

        for i in range(self.header_data['class_defs_size']):
            class_idx 			= struct.unpack('<L', self.data[offset+(i*32)   :offset+(i*32)+4])[0]
            access_flag 		= struct.unpack('<L', self.data[offset+(i*32)+4 :offset+(i*32)+8])[0]
            superclass_idx 		= struct.unpack('<L', self.data[offset+(i*32)+8 :offset+(i*32)+12])[0]
            interfaces_off 		= struct.unpack('<L', self.data[offset+(i*32)+12:offset+(i*32)+16])[0]
            source_file_idx 	= struct.unpack('<L', self.data[offset+(i*32)+16:offset+(i*32)+20])[0]
            annotation_off 		= struct.unpack('<L', self.data[offset+(i*32)+20:offset+(i*32)+24])[0]
            class_data_off 		= struct.unpack('<L', self.data[offset+(i*32)+24:offset+(i*32)+28])[0]
            static_values_off 	= struct.unpack('<L', self.data[offset+(i*32)+28:offset+(i*32)+32])[0]
            sorted_access = [i for i in disassembler.ACCESS_ORDER if i & access_flag]
            classdef_data.append({
                'class_idx': class_idx,
                'access': [disassembler.access_flag_classes[flag] for flag in sorted_access],
                'superclass_idx': superclass_idx,
                'interfaces_off': interfaces_off,
                'source_file_idx': source_file_idx,
                'annotation_off': annotation_off,
                'class_data_off': class_data_off,
                'static_values_off': static_values_off
            })

        return classdef_data

    def get_class_data(self, offset):
        """Get class specific data from DEX file

        :param integer offset: class_idx offset value
        :returns: specific data of class

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_class_data(offset=3022)
            {
                'static_fields': [
                    {
                        'diff': 30, 'access_flags': 4000
                    }
                ],
                'instance_fields': [
                    {
                        'diff': 32, 'access_flags': 4000
                    }
                ],
                'direct_methods': [
                    {
                        'diff': 30, 'access_flags': 4000, 'code_off': 384304
                    }
                ],
                'virtual_methods': [
                    {
                        'diff': 63, 'access_flags': 4000, 'code_off': 483933
                    }
                ]
            }
        """
        static_fields = []
        instance_fields = []
        direct_methods = []
        virtual_methods = []

        static_field_size, sf_size = uleb128_value(self.data, offset)
        offset += sf_size
        instance_field_size, if_size = uleb128_value(self.data, offset)
        offset += if_size
        direct_method_size, dm_size = uleb128_value(self.data, offset)
        offset += dm_size
        virtual_method_size, vm_size = uleb128_value(self.data, offset)
        offset += vm_size

        for i in range(static_field_size):
            field_idx_diff, access_flags, size = encoded_field(self.data, offset)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff

            static_fields.append({'diff': diff, 'access_flags': access_flags})
            offset += size

        for i in range(instance_field_size):
            field_idx_diff, access_flags, size = encoded_field(self.data, offset)
            if i == 0:
                diff = field_idx_diff
            else:
                diff += field_idx_diff

            instance_fields.append({'diff': diff, 'access_flags': access_flags})
            offset += size

        for i in range(direct_method_size):
            method_idx_diff, access_flags, code_off, size = encoded_method(self.data, offset)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff

            direct_methods.append({
                'diff': diff,
                'access_flags': access_flags,
                'code_off': code_off
            })
            offset += size

        for i in range(virtual_method_size):
            method_idx_diff, access_flags, code_off, size = encoded_method(self.data, offset)
            if i == 0:
                diff = method_idx_diff
            else:
                diff += method_idx_diff

            virtual_methods.append({
                'diff': diff,
                'access_flags': access_flags,
                'code_off': code_off
            })
            offset += size

        return {
            'static_fields': static_fields,
            'instance_fields': instance_fields,
            'direct_methods': direct_methods,
            'virtual_methods': virtual_methods
        }

    def get_code_item(self, offset):
        if offset == 0:
            return None
        registers_size = struct.unpack('<h', self.data[offset :offset+2])[0]
        ins_size = struct.unpack('<h', self.data[offset+2 :offset+4])[0]
        outs_size = struct.unpack('<h', self.data[offset+4 :offset+6])[0]
        tries_size = struct.unpack('<h', self.data[offset+6 :offset+8])[0]
        debug_info_off = struct.unpack('<L', self.data[offset+8 :offset+12])[0]

        return {
            'registers_size': registers_size,
            'ins_size': ins_size,
            'outs_size': outs_size,
            'tries_size': tries_size,
            'debug_info_off': debug_info_off
        }

    def get_class_name_by_id(self, class_index):
        '''Get class name by the class index which is an index into typeIds for this class

        :param class_index:
        :return: class_name:
        '''
        type_offset = self.header_data['type_ids_off']
        class_name_idx = struct.unpack('<L', self.data[type_offset+(class_index*4):type_offset+(class_index*4)+4])[0]
        class_name = self.get_string_by_idx(class_name_idx)

        return class_name

    def get_native_method(self):
        '''Get native methods from DEX file

        :return: a list of native method string
        '''
        self.native_method = []
        self.native_class = []
        class_offset = self.header_data['class_defs_off']
        # counter = 0
        for i in range(self.header_data['class_defs_size']):
            class_idx = struct.unpack('<L', self.data[class_offset + (i * 32):class_offset + (i * 32) + 4])[0]
            class_name = self.get_class_name_by_id(class_idx)
            class_data_off = struct.unpack('<L', self.data[class_offset + (i * 32) + 24:class_offset + (i * 32) + 28])[
                0]
            if class_data_off == 0:
                continue
            class_data_content = self.get_class_data(class_data_off)
            direct_methods = class_data_content['direct_methods']
            virtual_methods = class_data_content['virtual_methods']

            # print(str(counter), end='')
            # print(direct_methods)
            # counter += 1

            for method in direct_methods:
                access_flags = utils.get_access_flags(method['access_flags'])
                if 'native' in access_flags:
                    self.native_method.append(access_flags + " " + self.get_method_name_by_idx(method['diff']))
                    self.native_class.append("class_data_off: " + str(class_data_off) + " " + class_name)

            for method in virtual_methods:
                access_flags = utils.get_access_flags(method['access_flags'])
                if 'native' in access_flags:
                    self.native_method.append(access_flags + " " + self.get_method_name_by_idx(method['diff']))
                    self.native_class.append("class_data_off: " + str(class_data_off) + " " + class_name)

    def search_by_closest_debugoff(self, debugoff, direction):
        while True:
            if direction == 'plus':
                debugoff += 1
            else:
                debugoff -= 1
            byte_array = struct.pack("<L", debugoff)
            try:
                index = self.data.find(byte_array)
                if index != -1:
                    return index
            except ValueError:
                continue

    def get_debug_info_from_begin(self, methodname_to_debugoff, native_function_name):
        closest_method_debug_off = 0
        for item in methodname_to_debugoff:
            methodname = item['method_name']
            debugoff = item['debug_off']
            if methodname == native_function_name:
                break
            elif debugoff != 0:
                closest_method_debug_off = debugoff

        if closest_method_debug_off == 0:
            return None
        else:
            return self.search_by_closest_debugoff(closest_method_debug_off, "plus")


    def get_debug_info_from_end(self, methodname_to_debugoff, native_function_name):
        closest_method_debug_off = 0
        for item in methodname_to_debugoff[::-1]:
            methodname = item['method_name']
            debugoff = item['debug_off']
            if methodname == native_function_name:
                break
            elif debugoff != 0:
                closest_method_debug_off = debugoff

        if closest_method_debug_off == 0:
            return None
        else:
            return self.search_by_closest_debugoff(closest_method_debug_off, "minus")

    def search_binary(self, trgt_binary_arr:bytearray):
        try:
            index = self.data.find(trgt_binary_arr)
            print("found " + str(index))
        except ValueError:
            print("not found")

    def get_debug_info_in_class(self, class_data_off):
        class_data_content = self.get_class_data(class_data_off)
        direct_methods = class_data_content['direct_methods']
        virtual_methods = class_data_content['virtual_methods']
        result = []

        for method in direct_methods:
            method_name = self.get_method_name_by_idx(method['diff'])
            code_off = self.get_code_item(method['code_off'])
            debug_off = 0
            if code_off is not None:
                debug_off = code_off['debug_info_off']

            result.append({
                'method_name': method_name.strip(),
                'debug_off': debug_off,
            })

        for method in virtual_methods:
            method_name = self.get_method_name_by_idx(method['diff'])
            code_off = self.get_code_item(method['code_off'])
            debug_off = 0
            if code_off is not None:
                debug_off = code_off['debug_info_off']

            result.append({
                'method_name': method_name.strip(),
                'debug_off': debug_off,
            })

        return result


    def get_debug_info_offset(self, index:list):
        debug_info_offset = []
        for i in index:
            class_data_off = int(self.native_class[i].split(" ")[1].strip())
            methodname_to_debugoff = self.get_debug_info_in_class(class_data_off)
            target_function_name = self.native_method[i].split(" ")[-1].strip()
            result_from_begin = self.get_debug_info_from_begin(methodname_to_debugoff, target_function_name)
            result_from_end = self.get_debug_info_from_end(methodname_to_debugoff, target_function_name)

            if result_from_end is None and result_from_begin is None:
                debug_info_offset.append(None)
            else:
                if result_from_end is not None and result_from_begin is not None:
                    if result_from_end != result_from_begin:
                        assert False, "[Dexparser]: result_from_end doesn't equal to result_from_begin"
                result = result_from_begin if result_from_end is None else result_from_end
                # the following code is used to adjust the offset to the beginning of the first vBytecode
                length = struct.unpack("<L", self.data[result+4:result+8])[0]
                result += 8
                debug_info_offset.append({
                    "length": length,
                    "offset": result,
                })
        return debug_info_offset

    def print_native_method_class(self):
        print(self.native_class)
        print(self.native_method)

    def get_annotations(self, offset):
        """Get annotation data from DEX file

        :param integer offset: annotation_off offset value
        :returns: specific data of annotation

        example:
            >>> dex = Dexparser(filedir='path/to/classes.dex')
            >>> dex.get_annotations(offset=3022)
            {
                'visibility': 3403,
                'type_idx_diff': 3024,
                'size_diff': 64,
                'name_idx_diff': 30,
                'value_type': 302,
                'encoded_value': 7483
            } 
        """
        class_annotation_off = struct.unpack('<L', self.data[offset	:offset+4])[0]
        class_annotation_size = struct.unpack('<L', self.data[class_annotation_off:class_annotation_off+4])[0]
        annotation_off_item = struct.unpack('<L', self.data[class_annotation_off+4: class_annotation_off+8])[0]
        visibility = self.data[annotation_off_item : annotation_off_item + 1]
        annotation = self.data[annotation_off_item + 1 : annotation_off_item + 8]
        annotation_data = encoded_annotation(self.data, annotation_off_item + 1)
        type_idx_diff, size_diff, name_idx_diff, value_type, encoded_value = annotation_data

        return {
            'visibility': ord(visibility),
            'type_idx_diff': type_idx_diff,
            'size_diff': size_diff,
            'name_idx_diff': name_idx_diff,
            'value_type': ord(value_type),
            'encoded_value': ord(encoded_value)
        }
