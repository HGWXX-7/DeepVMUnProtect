# from ..dexsearcher.util import *
# import ..dexsearcher.file_pointer
# import ..dexsearcher.annotation_item import AnnotationItem
# import ..dexsearcher.annotation_set_item import AnnotationsSetItem
# import ..dexsearcher.annotations_direction_item import AnnotationsDirectionItem
# import ..dexsearcher.class_data_item import ClassDataItem
# import ..dexsearcher.class_def_item_list import ClassDefItemList
# import ..dexsearcher.code_item import CodeItem
# import ..dexsearcher.const_type import *
# import ..dexsearcher.debug_info_item import DebugInfoItem
# import ..dexsearcher.dex_parser import DexParser
# import ..dexsearcher.encoded_annotation import EncodedAnnotation
# import ..dexsearcher.encoded_array import EncodedArray
# import ..dexsearcher.encoded_field_list import EncodedFieldList
# import ..dexsearcher.encoded_method import EncodedMethod
# import ..dexsearcher.encoded_method_list import EncodedMethodLists
# import ..dexsearcher.encoded_value import EncodedValue
# import ..dexsearcher.field_id_list import FieldIdList
# import ..dexsearcher.header_section import HeaderSection
# import ..dexsearcher.interface_item_list import InterfaceItemList
# import ..dexsearcher.method_id_list import MethodIdList
# import ..dexsearcher.proto_id_list import ProtoIdList
# import ..dexsearcher.string_id_list import StringIdList
# import ..dexsearcher.type_id_list import TypeIdList
# import ..dexsearcher.map_list_type

# FilePointer = ..dexsearcher.file_pointer.FilePointer
import logging

# sys.path.append(os.path.dirname(os.path.realpath(__file__)))
# current_dir = os.path.abspath(os.path.dirname(__file__))
# sys.path.append(current_dir)
# sys.path.append("..")
logging.basicConfig(level=logging.ERROR)

# from ..dexsearcher.file_pointer import FilePointer
# import ..dexsearcher.encoded_value
# import ..dexsearcher.encoded_annotation
# import ..dexsearcher.interface_item_list
# import ..dexsearcher.annotation_item
# import ..dexsearcher.annotation_set_item
# import ..dexsearcher.annotations_direction_item
# import ..dexsearcher.class_data_item
# import ..dexsearcher.class_def_item_list
# import ..dexsearcher.code_item
# from ..dexsearcher.const_type import *
# import ..dexsearcher.debug_info_item
# import ..dexsearcher.dex_parser
# import ..dexsearcher.encoded_array
# import ..dexsearcher.encoded_field_list
# import ..dexsearcher.encoded_method
# import ..dexsearcher.encoded_method_list
# import ..dexsearcher.field_id_list
# import ..dexsearcher.header_section
# import ..dexsearcher.method_id_list
# import ..dexsearcher.proto_id_list
# import ..dexsearcher.string_id_list
# import ..dexsearcher.type_id_list
# # from ..dexsearcher.map_list_type import MapListType
# import ..dexsearcher.map_list_type
# import ..dexsearcher.file_pointer
# import ..dexsearcher.encoded_value
#
# FilePointer = ..dexsearcher.file_pointer.FilePointer
# EncodedValue = ..dexsearcher.encoded_value.EncodedValue
# EncodedAnnotation = ..dexsearcher.encoded_annotation.EncodedAnnotation
# InterfaceItemList = ..dexsearcher.interface_item_list.InterfaceItemList
# AnnotationItem = ..dexsearcher.annotation_item.AnnotationItem
# AnnotationsSetItem = ..dexsearcher.annotation_set_item.AnnotationsSetItem
# AnnotationsDirectionItem = ..dexsearcher.annotations_direction_item.AnnotationsDirectionItem
# ClassDataItem = ..dexsearcher.class_data_item.ClassDataItem
# ClassDefItemList = ..dexsearcher.class_def_item_list.ClassDefItemList
# CodeItem = ..dexsearcher.code_item.CodeItem
# DebugInfoItem = ..dexsearcher.debug_info_item.DebugInfoItem
# DexParser = ..dexsearcher.dex_parser.DexParser
# EncodedArray = ..dexsearcher.encoded_array.EncodedArray
# EncodedFieldList = ..dexsearcher.encoded_field_list.EncodedFieldList
# EncodedMethod = ..dexsearcher.encoded_method.EncodedMethod
# EncodedMethodLists = ..dexsearcher.encoded_method_list.EncodedMethodLists
# FieldIdList = ..dexsearcher.field_id_list.FieldIdList
# HeaderSection = ..dexsearcher.header_section.HeaderSection
# MethodIdList = ..dexsearcher.method_id_list.MethodIdList
# ProtoIdList = ..dexsearcher.proto_id_list.ProtoIdList
# StringIdList = ..dexsearcher.string_id_list.StringIdList
# TypeIdList = ..dexsearcher.type_id_list.TypeIdList
# MapListType = ..dexsearcher.map_list_type.MapListType


from automaticvmcracker.Util.dexsearcher.const_type import *
from automaticvmcracker.Util.dexsearcher.util import *
from automaticvmcracker.Util.dexsearcher.file_pointer import FilePointer

from automaticvmcracker.Util.dexsearcher.file_pointer import FilePointer
from automaticvmcracker.Util.dexsearcher.encoded_value import EncodedAnnotation, EncodedValue, EncodedArray
from automaticvmcracker.Util.dexsearcher.debug_info_item import DebugInfoItem
from automaticvmcracker.Util.dexsearcher.code_item import CodeItem
from automaticvmcracker.Util.dexsearcher.encoded_field_list import EncodedFieldList
from automaticvmcracker.Util.dexsearcher.encoded_method import EncodedMethod
from automaticvmcracker.Util.dexsearcher.encoded_method_list import EncodedMethodLists
from automaticvmcracker.Util.dexsearcher.interface_item_list import InterfaceItemList
from automaticvmcracker.Util.dexsearcher.annotation_item import AnnotationItem
from automaticvmcracker.Util.dexsearcher.annotation_set_item import AnnotationsSetItem
from automaticvmcracker.Util.dexsearcher.annotations_direction_item import AnnotationsDirectionItem


from automaticvmcracker.Util.dexsearcher.header_section import HeaderSection
from automaticvmcracker.Util.dexsearcher.field_id_list import FieldIdList
from automaticvmcracker.Util.dexsearcher.method_id_list import MethodIdList
from automaticvmcracker.Util.dexsearcher.proto_id_list import ProtoIdList
from automaticvmcracker.Util.dexsearcher.string_id_list import StringIdList
from automaticvmcracker.Util.dexsearcher.type_id_list import TypeIdList
from automaticvmcracker.Util.dexsearcher.class_data_item import ClassDataItem
from automaticvmcracker.Util.dexsearcher.class_def_item_list import ClassDefItemList
from automaticvmcracker.Util.dexsearcher.map_list_type import MapListType
from automaticvmcracker.Util.dexsearcher.dex_parser import DexParser


