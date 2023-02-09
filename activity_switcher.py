import os
import sys
from time import sleep
import pexpect
import threading
import re
import logging
from tqdm import tqdm
import glob

logger = logging.getLogger("ActivitySwitcher")
fmt = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
handler = logging.FileHandler("test.log")
handler.setLevel(logging.INFO)
handler.setFormatter(fmt)
logger.addHandler(handler)

# from Test.offset_parser import OffsetParser
# from Util.dexsearcher import DexParser

from automaticvmcracker.offset_parser import OffsetParser
from automaticvmcracker.Util.dexsearcher import DexParser

lldb_client_sema = threading.Semaphore(0)
frida_sema = threading.Semaphore(0)
lldb_server_sema = threading.Semaphore(0)
frida_success = False
lldb_server_success = False
lldb_client_success = False

# def activity_check(package_name, activity_name):
#     command = "adb shell dumpsys activity top | grep ACTIVITY | grep " + package_name
#     while True:
#         content = os.popen(command).read()
#         print(content)
#         if content.find(activity_name) != -1:
#             break

'''
(lldb) c
Process 9740 resuming

Watchpoint 1 hit:
old value: -6985754013778723572
new value: -6985754013778723572
Process 9740 stopped
* thread #1, name = 'e.multiactivity', stop reason = watchpoint 1
    frame #0: 0x0000007c5e0f4a24
->  0x7c5e0f4a24: bfi    w9, w9, #8, #8
    0x7c5e0f4a28: sub    x8, x8, x28
    0x7c5e0f4a2c: lsr    x24, x8, #1
    0x7c5e0f4a30: eor    w27, w9, w10
'''


def sleep_with_tqdm(second):
    for i in tqdm(range(second)):
        sleep(1)


def get_process_pid(package_name):
    command = 'adb shell "ps -A | grep ' + package_name + '"'
    print(command)
    result = os.popen(command)
    content = result.read()
    pid = content.split()[1].strip()
    return int(pid)


def change_script(activity_name):
    script_path = "/home/morangeous/bigtest/android_project/useful_tools/frida/FRIDA-DEXDump/python_test/automaticvmcracker/Test/debug360.js"
    with open(script_path, "r") as script:
        lines = script.readlines()
        lines[0] = "var function_name = \"" + activity_name + ".onCreate\"\n"

    with open(script_path, 'w+') as script:
        script.writelines(lines)


class LLDBServerThread(threading.Thread):
    def __init__(self, tcp_port, package_name):
        threading.Thread.__init__(self)
        self.tcp_port = tcp_port
        self.package_name = package_name

    def run(self):
        print("Begin to launch lldb-server")
        launch_lldb_server(self.tcp_port, self.package_name)
        print("LLDB server quit")

def launch_lldb_server(tcp_port, package_name):
    global lldb_server_success
    lldb_server_success = True
    lldb_server_sema.acquire()
    if not frida_success:
        lldb_server_success = False
        lient_sema.release()
        print("launching frida failed, lldb server quiting")
        return 

    try:
        pid = get_process_pid(package_name)
        print("[launch_lldb_server]: I get it again, pid is: " + str(pid))
    except:
        lldb_server_success = False
        print("[launch_lldb_server]: can not get pid for {}".format(package_name))
        lldb_client_sema.release()
        return
    
    command = 'adb shell -t "su 0 /data/local/tmp/lldb-server-aarch64-1105 g :' + str(tcp_port) + ' --attach ' + str(pid) + '"'
    print("**" + command + "**")
    process = pexpect.spawn(command, timeout=30)
    try:
        process.expect("lldb-server-local_build")
        lldb_client_sema.release()
    except:
        print("[launch_lldb_server]: can not attach the lldb server, quiting")
        lldb_server_success = False
        lldb_client_sema.release()
    process.send("")
    #process.expect("lldb-server exiting")
    print("lldb-server is quiting")


class MainEntraceThread(threading.Thread):
    def __init__(self, command: str, package_name: str, activity_name: str):
        threading.Thread.__init__(self)
        self.command = command
        self.package_name = package_name
        self.activity_name = activity_name

    def run(self):
        print("begin to launch frida")
        attach_main_activity(self.command, self.package_name, self.activity_name)
        print("frida quit")


def attach_main_activity(command, package_name, activity_name):
    global frida_success
    frida_success = True
    change_script(activity_name)
    process = pexpect.spawn(command, encoding='utf-8', logfile=sys.stdout)
    try:
        process.sendline("")
        process.expect("AOSP on msm8996")
        print("[frida]: {}".format(command))
        sleep(20)
    except:
        print("[frida]: can not launch frida while processing {}".format(activity_name))
        lldb_server_sema.release()
        return
    try:
        process.expect("start sleep", timeout=30)
    except:
        print("[frida] failed here")
        print(str(process.buffer.__str__()))
        lldb_server_sema.release()
        frida_success = False
        return -1
    lldb_server_sema.release()
    print("[frida thread]: frida task finished, will quit after 10 sec")
    sleep(10)
    process.sendline("quit")


class OtherActivityThread(threading.Thread):
    def __init__(self, command: str, activity_name: str):
        threading.Thread.__init__(self)
        self.command = command
        self.activity_name = activity_name

    def run(self):
        print("begin to attach and switch other activity")
        self.result = attach_switch_activity(self.command, self.activity_name)
        print("frida quit")

    def get_result(self):
        try:
            return self.result
        except Exception:
            return None


def attach_switch_activity(command, activity_name):
    global frida_success
    frida_success = True
    change_script(activity_name)
    process = pexpect.spawn(command, encoding='utf-8')
    process.sendline("")
    try:
        process.expect("AOSP on msm8996")
        print("entered mainactivity")
        process.sendline('start_another_activity("' + activity_name + '")')
        print("sending command finished, waiting for the result")
    except:
        print("[frida]: can not launch frida while processing {}".format(activity_name))
        lldb_server_sema.release()
        return
    try:
        process.expect("switched finished", timeout=30)
        sleep(20)
        process.expect("start sleep", timeout=30)
    except:
        print("[attach_switch_activity]: Fail to switch in the first time, I will try for the twice ")
        # I will try another time:
        process.sendline('start_another_activity("' + activity_name + '")')
        try:
            process.expect("switched finished", timeout=30)
            sleep(20)
            process.expect("start sleep", timeout=30)
        except:
            lldb_server_sema.release()
            frida_success = False
            return -1
    #TODO: you should start debugging step by step according to the return value of javascript code. For example "start sleep", it is better for you to sleep for 1~2 secs
    #TODO: this function can breakdown when then activity can not be switch to
    lldb_server_sema.release()
    print("[frida thread]: frida task finished, will quit after 10 sec")
    sleep(10)
    process.sendline("quit")


class LLDBClientThread(threading.Thread):
    def __init__(self, activity_switcher, tcp_port, bytecode_number, saving_path, bytecode_offset):
        threading.Thread.__init__(self)
        self.tcp_port = tcp_port
        self.bytecode_number = bytecode_number
        self.saving_path = saving_path
        self.bytecode_offset = bytecode_offset
        self.activity_switcher = activity_switcher

    def run(self):
        print("begin to launch LLDB client")
        connect_lldb(self.activity_switcher, self.tcp_port, self.bytecode_number, self.saving_path, self.bytecode_offset)
        print("LLDB client quit")


def connect_lldb(activity_switcher, tcp_port, bytecode_number: list, saving_path, breakpoints: list):
    global lldb_server_success
    global lldb_client_success

    launch_lldb = "/home/morangeous/workspace/android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64/bin/lldb"
    process = pexpect.spawn(launch_lldb, encoding='utf-8')
    process.logfile = sys.stdout
    process.expect("get_n_bytecode")
    # connect to lldb-server
    lldb_client_sema.acquire()
    if not lldb_server_success:
        print("[lldb_client]: lldb_server failed, quiting")
        return -1
    process.sendline("gdb-remote " + str(tcp_port))
    ret_value = ["failed to get reply", "signal SIGSTOP"]
    ret_index = process.expect(ret_value, timeout=30)
    if ret_index == 0:
        #FIXME: CANNOT CONNECT TO lldb
        pass

    # set memory breakpoint
    # generate address of the first bytecode
    sleep(8)
    ret_value = ["Watchpoint created", "failed"]
    activity_switcher.pull_new_dex_file()
    for hwbp in breakpoints:
        hwbp = activity_switcher.generate_first_address(hwbp)
        process.sendline("wa se expr -s 2 -w read -- " + hwbp)
        process.expect(ret_value)
    # continue to breakpoint and find out which watchpoint hit
    process.buffer = ""
    process.sendline("c")
    try:
        process.expect("stop reason")
        lldb_client_success = True
    except:
        print("[connect_lldb]: fail to catch hwbp here, return")
        lldb_client_success = False
        return
    # design for latest 360
    process.buffer = ""
    process.sendline("c")
    print("we continue again")
    sleep(1000)

    content = str(process.buffer.__str__())
    pattern = re.compile("watchpoint [1-9]\d*")
    breakpoint_number = int(pattern.search(content).group().strip().split(" ")[1]) - 1
    bytecode_number = bytecode_number[breakpoint_number]

    saving_path = saving_path + "_" + str(bytecode_number) + "_" + str(breakpoints[breakpoint_number]) + ".txt"

    # delete memory address
    process.sendline("wa del")
    process.expect("delete all")
    # confirm to delete
    process.sendline("Y")
    process.expect("All watchpoints removed")
    # get pc address
    process.buffer = ""
    process.sendline("re re $pc")
    process.expect("pc = ")
    address = str(process.buffer.__str__())
    pattern = re.compile("0x[0-9a-fA-F]+")
    address = pattern.search(address).group().strip()
    print("raw_address is: \"" + address + "\"")
    address = address.strip()
    # get start and end address
    start_address = hex(int(address, 16))
    end_address = hex(int(address, 16) - 4)
    print("address " + address + "; start_address: " + start_address + "; end_address: " + end_address)

    # get the base_address of libart.so
    command = "image list -o -f libart.so"
    process.sendline(command)
    process.expect("]")
    libart_base = pattern.search(str(process.buffer.__str__())).group().strip()
    with open(saving_path, 'a+') as f:
        f.write("libart.so:{}\n".format(libart_base))

    # repeat single debug for bytecode_number times
    for i in range(bytecode_number):
        command = "exec_trace -s " + start_address + " -e " + end_address + " -f " + saving_path
        process.sendline(command)
        match = process.expect(["we reach the end", "Traceback", "FATAL"], timeout=1800, searchwindowsize=200)
        if match == 1:
            print("[ActivitySwitcher]: This is the last bytecode, quiting")
            break
        elif match == 2:
            print("[ActivitySwitcher]: Something wrong, quiting")

    print("[lldb_client]: lldb client finished, quiting")
    sleep(5)


class ActivitySwitcher(object):
    def __init__(self, apk_path, saving_path) -> None:
        super().__init__()
        # TODO: handle the situation that cannot install successfully
        self.tcp_port = 9707
        self.process_file = "/home/morangeous/MalwareSample/PackedMalware/process.log"
        self.set_tcp_port()
        self.install_apk(apk_path)
        self.offset_parser = OffsetParser(apk_path)
        self.breakpoints, self.bytecode_number = DexParser(self.offset_parser.get_dex_path()).get_unlinked_block()
        method_index_list, self.activity_name = self.offset_parser.get_native_oncreate()
        # self.method_name, self.activity_name = self.offset_parser.get_offset_of_native(method_index_list)
        self.saving_path = self.generate_saving_path(saving_path)
        self.main_activity = self.offset_parser.dex_finder.apk_analyzer.get_main_activity()
        self.package_name = self.offset_parser.dex_finder.apk_analyzer.get_package()

    def divide_breakpoints(self, size):
        reshaped_breakpoints = []

        for i in range(0, len(self.breakpoints), size):
            reshaped_breakpoints.append(self.breakpoints[i: i + size])

        return reshaped_breakpoints

    def generate_saving_path(self, root_path):
        if not os.path.exists(root_path):
            os.makedirs(root_path)

        saving_path = os.path.join(root_path, self.offset_parser.dex_finder.apk_analyzer.get_package())
        print("saving path is: " + saving_path)

        if not os.path.exists(saving_path):
            os.makedirs(saving_path)
        return saving_path

    def generate_first_address(self, bytecode_offset: str):
        # first delete everything in folder: /home/zhao/bigtest/android_project/useful_tools/frida/FRIDA-DEXDump/python_test/automaticvmcracker/Data/dex_and_txt
        # self.offset_parser.dex_finder.delete_dex_and_text()

        # pull the dex_file again
        # self.offset_parser.dex_finder.pull_dex_file()

        # parse the start_address
        address = self.offset_parser.dex_finder.parse_start_address()
        bytecode_offset = int(bytecode_offset, 16)
        logger.setLevel(logging.INFO)
        logger.info(type(address))
        logger.info(address)
        logger.info(hex(bytecode_offset))

        address = int(address, 16)
        address += bytecode_offset
        return hex(address)


    def set_tcp_port(self):
        command = "adb forward tcp:" + str(self.tcp_port) + " tcp:" + str(self.tcp_port)
        os.system(command)

    def start_debug(self):

        log_file = open(self.process_file, 'a+')
        self.switch_main_activity()

        for index in range(1, len(self.activity_name)):
            activity = self.activity_name[index]
            try:
                self.switch_other_activity(activity)
                log_file.write("{} is processed successfully".format(activity))
            except:
                print("[ActivitySwitcher]: Attention, activity: {} failed".format(activity))
                log_file.write("Fail to process {}".format(activity))

        log_file.close()

    def pull_new_dex_file(self):
        self.offset_parser.dex_finder.delete_dex_and_text()
        self.offset_parser.dex_finder.pull_dex_file()

    def switch_main_activity(self):
        # file_name = main_activity + "_" + str(bytecode_number) + "_" + str(bytecode_offset) + ".txt"
        # init variable
        global lldb_client_success
        lldb_client_success = False
        main_activity = self.activity_name[0]
        command = "frida -U -f " + self.package_name \
                  + " -l /home/morangeous/bigtest/android_project/useful_tools/" \
                    "frida/FRIDA-DEXDump/python_test/automaticvmcracker/Test/debug360.js --no-pause"
        print("we will debug main activity by command:\n{}\n".format(command))


        for index, hwbp in enumerate(self.breakpoints):
            if lldb_client_success:
                # in this situation, the breakpoint has been caught, so the rest breakpoints are invalid, we need quit
                break

            self.offset_parser.dex_finder.del_mobile_fart_folder()

            saving_path = os.path.join(self.saving_path, main_activity)
            frida_thread = MainEntraceThread(command, self.package_name, main_activity)
            lldb_server_thread = LLDBServerThread(self.tcp_port, self.package_name)
            lldb_client_thread = LLDBClientThread(self, self.tcp_port, self.bytecode_number[index], saving_path, hwbp)

            frida_thread.start()
            lldb_server_thread.start()
            lldb_client_thread.start()

            lldb_client_thread.join()
            lldb_server_thread.join()
            frida_thread.join()
            print("finished")

    def switch_other_activity(self, activity):
        # file_name = activity + "_" + str(bytecode_number) + "_" + str(bytecode_offset) + ".txt"\
        # init variable
        global lldb_client_success
        lldb_client_success = False


        for index, hwbp in enumerate(self.breakpoints):
            if lldb_client_success:
                break

            self.offset_parser.dex_finder.del_mobile_fart_folder()
            command = "adb shell am force-stop " + self.package_name
            print(command)
            os.system(command)

            sleep(1)
            command = "adb shell am start -n {}/{}".format(self.package_name, self.main_activity)
            os.system(command)
            print("activity is: {}. We will wait 10 sec".format(activity))
            sleep(10)

            command = "frida -U " + self.package_name + \
                      " -l /home/morangeous/bigtest/android_project/useful_tools/frida/FRIDA-DEXDump/python_test/automaticvmcracker/Test/debug360.js --no-pause"

            saving_path = os.path.join(self.saving_path, activity)
            frida_thread = OtherActivityThread(command, activity)
            lldb_server_thread = LLDBServerThread(self.tcp_port, self.package_name)
            lldb_client_thread = LLDBClientThread(self, self.tcp_port, self.bytecode_number[index], saving_path, hwbp)

            frida_thread.start()
            lldb_server_thread.start()
            lldb_client_thread.start()

            lldb_client_thread.join()
            lldb_server_thread.join()
            frida_thread.join()
            print("finished")

    def install_apk(self, apk_path) -> None:
        install_command = "adb install {}".format(apk_path)
        process = pexpect.spawn(install_command)
        ret_val = ["Success", "Failure"]
        index = process.expect(ret_val)
        if index == 0:
            print("Successfully install")
        else:
            print("Fail to install")
            assert False, "Fail to install, so we quit here"

    def uninstall_apk(self):
        uninstall_command = "adb uninstall {}".format(self.package_name)
        process = pexpect.spawn(uninstall_command)
        ret_val = ["Success", "Failure"]
        index = process.expect(ret_val)
        if index == 0:
            print("Successfully uninstall")
        else:
            print("Fail to uninstall")


def test():
    # apk_path = "/home/zhao/bigtest/android_project/useful_tools/frida/FRIDA-DEXDump/python_test/automaticvmcracker/Data/apk/multi_activity_permission_10_jiagu_sign.apk"
    # saving_path = "/home/zhao/bigtest/android_project/useful_tools/frida/FRIDA-DEXDump/python_test/automaticvmcracker/Result/com.example.multiactivity/"
    # activity_switcher = ActivitySwitcher(apk_path, saving_path)
    # activity_switcher.start_debug()
    sleep_with_tqdm(10)

def get_finished_package(saving_path):
    package_names = glob.glob(saving_path)
    return [os.path.basename(x) for x in package_names]

def get_package_name(apk_path):
    content = os.popen("aapt dump badging {} | grep package".format(apk_path)).readlines()
    try:
        content = content[0].strip()
        package_name = content.split('\'')[1]
    except:
        print('apk parse error, quiting')
        package_name = "error"
    
    return package_name

def uninstall_apk(package_name):
    uninstall_command = "adb uninstall {}".format(package_name)
    process = pexpect.spawn(uninstall_command)
    ret_val = ["Success", "Failure"]
    index = process.expect(ret_val)
    if index == 0:
        print("Successfully uninstall")
    else:
        print("Fail to uninstall")

def main():
    apk_root = "/home/morangeous/MalwareSample/PackedMalware/T470Data"
    saving_path = "/home/morangeous/MalwareSample/PackedMalware/Result/Trace"
    log_path = "/home/morangeous/MalwareSample/PackedMalware/log.txt"
    apks = glob.glob(os.path.join(apk_root, "*.apk"))
    finished_package = get_finished_package(saving_path + "/*")
    print('finished_packages:\n{}\n'.format(finished_package))
    with open(log_path, 'a+') as f:
        for apk in apks:
            package_name = get_package_name(apk)
            print('[main]: current apk package name{}'.format(package_name))
            print('[main]: current apk path {}'.format(apk))
            if package_name == "error" or package_name in finished_package:
                print('[main]: we have processed {}'.format(package_name))
                continue
            try:
                activity_switcher = ActivitySwitcher(apk, saving_path)
                f.write("start processing {}\n".format(apk))
                activity_switcher.start_debug()
                f.write("{} is finished\n".format(apk))
            except:
                print("{} failed".format(apk))
                f.write("fail to process {}".format(apk))
            # try to uninstall the app
            try:
                uninstall_apk(package_name)
            except:
                print("[ActivitySwitcher]: uninstall app failed but you are good to go")

def get_unlinked_block():
    dex_parser_obj = DexParser('/home/morangeous/bigtest/android_project/'
                               'useful_tools/MyDexParser/dexparser/data/1917764_dexfile_execute.dex')
    offset, byte_number = dex_parser_obj.get_unlinked_block()
    print(offset)
    print(byte_number)

if __name__ == '__main__':
    main()
