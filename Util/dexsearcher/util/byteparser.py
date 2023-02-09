import os
import psutil
import numpy as np


def show_memory_info(hint):
    pid = os.getpid()
    p = psutil.Process(pid)

    info = p.memory_full_info()
    memory = info.uss / 1024. /1024
    print('{} memory used: {} MB'.format(hint, memory))


def convert_bytes_to_num(bytes):
    value = 0
    for i in range(len(bytes)):
        value |= (bytes[i] << i*8)
    return value


def convert_bytes_to_int(bytes):
    assert 4 >= len(bytes) > 0, "bytes length should between 1 and 4, current bytes:{}".format(bytes)

    return convert_bytes_to_num(bytes)


def convert_bytes_to_short(bytes):
    assert 2 >= len(bytes) > 0, "bytes length should between 1 and 2"

    return convert_bytes_to_num(bytes)

# FIXME
def convert_uleb128_to_int(bytes):
    last = 0
    for last in range(5):
        if bytes[last] & 0x80 == 0:
            break

    value = 0
    for i in range(last + 1):
        value |= (bytes[i] & 0x7f) << i * 7

    return value, last + 1


def convert_sleb128_to_int(bytes):
    last = 0
    signal_bit = 0
    for last in range(5):
        if bytes[last] & 0x80 == 0:
            signal_bit = bytes[last] & 0x40
            break

    value = 0

    if signal_bit == 0:
        value, _ = convert_uleb128_to_int(bytes)
    else:
        for i in range(last + 1):
            value |= ((bytes[i] & 0x7f) ^ 0x7f) << i * 7

        value += 1
        value *= -1

    return value, last + 1


def convert_uleb128p1_to_int(bytes):
    value, last = convert_uleb128_to_int(bytes)

    return value - 1, last


def parse_value_type(byte):
    '''
    This function is used for parsing encoded_value
    :param byte: 8bits
    :return: value_type: 5bits and value_arg: 3bits
    '''

    value_type = byte & 0x1f
    value_arg = (byte & 0xe0) >> 5

    return value_type, value_arg


def read_file_test():
    content = np.fromfile('/home/morangeous/bigtest/android_project/useful_tools/DexParser/data/1917764_dexfile_execute.dex', dtype=np.ubyte)
    print(len(content))
# def test_parse_value_type(byte):
#     type, arg = parse_value_type(byte)
#     print('type:{}, arg:{}'.format(hex(type), arg))
#
#
# dex_bytes = np.fromfile('/home/morangeous/bigtest/android_project/useful_tools/MyDexParser/bin/value_type', dtype=np.ubyte)
# print(convert_uleb128_to_int(dex_bytes[0:2]))


