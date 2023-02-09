import os
import sys

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(current_dir)
sys.path.append("..")

from automaticvmcracker.Util.dexsearcher import DexParser


class TestDexParser(object):
    def __init__(self, dex_path):
        self.dex_path = dex_path

    def test_header_section(self):
        dex_parser_obj = DexParser(self.dex_path)
        offset, byte_number = dex_parser_obj.get_unlinked_block()
        print(offset)
        print(byte_number)

    def print_sys(self):
        for _ in sys.path:
            print(_)


def test_dex():
    print("begin")
    test_dex_parser = TestDexParser('E:\\PycharmProgram\\DataOfAutomaticVMC\\mobi_screensaver_ymgx.dex')
    test_dex_parser.test_header_section()
    print("finished")