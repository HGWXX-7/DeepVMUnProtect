import sys
import os

current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(current_dir)
sys.path.append("..")

from automaticvmcracker.Util.dexsearcher import DexParser

def test():
    dex_parser_obj = DexParser("/home/morangeous/bigtest/android_project/useful_tools/"
                               "frida/FRIDA-DEXDump/python_test/automaticvmcracker/Data/dex/1917764_dexfile_execute.dex")
    print(dex_parser_obj.get_unlinked_block())


test()
