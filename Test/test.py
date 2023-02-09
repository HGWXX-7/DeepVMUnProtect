# import frida
import sys
import os
import re
from os.path import abspath, join, dirname
import logging

import pexpect
current_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(current_dir)
sys.path.append("..")
from Util.APKUtil.APK_parser import APKParser

import threading
import time
import random

frida_sema = threading.Semaphore(0)
lldb_sema = threading.Semaphore(0)
frida_success_flag = 0

def frida():
    print("switch to entrance")
    lldb_sema.release()
    for i in range(10):
        frida_sema.acquire()
        print("switch to another activity")
        lldb_sema.release()

def lldb():
    while True:
        print("lldb is waiting")
        lldb_sema.acquire()
        print("debug starts")
        frida_sema.release()

class Sleep5Thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        print("Begin to launch lldb-server")
        self.result = sleep_5()
        print("5 quit")

    def get_result(self):
        try:
            return self.result
        except:
            return None

def sleep_5():
    global frida_success_flag
    frida_success_flag = 0
    time.sleep(5)
    frida_success_flag = 1
    frida_sema.release()
    return -1

class Sleep10Thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        print("Begin to launch lldb-server")
        sleep_10()
        print("10 quit")


def sleep_10():
    global frida_success_flag
    frida_sema.acquire()
    if frida_success_flag == 1:
        frida_sema.release()
        return
    time.sleep(10)

class Sleep15Thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        print("Begin to launch lldb-server")
        sleep_15()
        print("15 quit")


def sleep_15():
    global frida_success_flag
    frida_sema.acquire()
    if frida_success_flag == 1:
        frida_sema.release()
        return
    time.sleep(15)

# def consumer():
#     print("consumer is waiting")
#     semaphore.acquire()
#     print("Consumer notify : consumed item number %s " % item)

# def producer():
#     global item
#     time.sleep(5)
#     # create a random item
#     item = random.randint(0, 1000)
#     print("producer notify : produced item number %s" % item)
#     semaphore.release()

def reshape_breakpoint(size):
    reshaped_breakpoints = []
    breakpoints = [x for x in range(34)]

    for i in range(0, len(breakpoints), size):
        reshaped_breakpoints.append(breakpoints[i: i + size])

    return reshaped_breakpoints

def main():
    dex_parser_obj = DexParser("/home/morangeous/bigtest/android_project/useful_tools/"
                               "frida/FRIDA-DEXDump/python_test/automaticvmcracker/Data/dex/1917764_dexfile_execute.dex")
    dex_parser_obj.decode()
    print(dex_parser_obj.get_unlinked_block())


if __name__ == '__main__':
    while(True):
        size = input("input the size\n")
        print(reshape_breakpoint(int(size)))
