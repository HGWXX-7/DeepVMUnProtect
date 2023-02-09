import os
import re
import glob

from automaticvmcracker.apk_analyzer import APKAnalyzer
from automaticvmcracker.Util.dexparser import Dexparser

class DexFinder(object):
    def __init__(self, apk_path):
        #FIXME: dexparser seems invalid
        #dexparser = Dexparser("../Data/dex_and_txt/1928196_dexfile_execute.dex")
        self.apk_analyzer = APKAnalyzer(apk_path)
        self.dex_path = "/home/morangeous/bigtest/android_project/useful_tools/" \
                        "frida/FRIDA-DEXDump/python_test/automaticvmcracker/Data/dex_and_txt/"

    def grant_write_permission(self):
        # remember that you should call this function before you launch the app
        if not self.apk_analyzer.has_request_write():
            assert False, "[FATAL]: this app has not requested write permission， quiting"

        package_name = self.apk_analyzer.apk.get_package()
        command = "adb shell pm grant " + package_name + \
            " android.permission.WRITE_EXTERNAL_STORAGE"
        os.system(command)
        command = "adb shell pm grant " + package_name + \
            " android.permission.READ_EXTERNAL_STORAGE"
        os.system(command)

    def del_mobile_fart_folder(self):
        fart_folder = "/sdcard/fart/" + self.apk_analyzer.apk.get_package() + "/"
        command = "adb shell rm -rf " + fart_folder
        os.system(command)


    def pull_dex_file(self):
        # TODO: attention that you may match more than 2 files , in order to address this problem, you should
        # get a good knowledge of fart and change it.
        package_name = self.apk_analyzer.apk.get_package()
        print("[DexFinder]: package_name is {}".format(package_name))
        fart_folder = "/sdcard/fart/" + package_name + "/"
        main_activity = self.apk_analyzer.get_main_activity()
        command = "adb shell \"grep -rla " + main_activity + " " + fart_folder + "\""
        print(command)
        result = os.popen(command)
        content = result.read()
        for line in content.splitlines():
            command = "adb pull " + line.strip() + " " + self.dex_path
            os.system(command)

    def parse_start_address(self):
        text_path_prefix = self.dex_path
        text_names = glob.glob(text_path_prefix + "*.txt")
        index = 0

        if len(text_names) == 0:
            print("dex_path is {}".format(text_path_prefix))
            assert False, "[DexFinder]: fart didn't get the corrent textfile or something else goes wrong"

        if len(text_names) > 1:
            print("dexfile list:")
            print(text_names)
            index = input("select a dex file 0~" + str(len(text_names)-1) + ":\n")

        address = ""
        with open(text_names[index]) as f:
            lines = f.readlines()
            address = lines[0].strip()

        return address

    def delete_dex_and_text(self):
        text_path_prefix = self.dex_path + "*"
        os.system("rm -rf " + text_path_prefix)

    def select_dex_file(self):
        #TODO: remember to select a propriate dex file from the folder ../Data/dex_and_txt
        dex_path_prefix = self.dex_path
        dex_names = glob.glob(dex_path_prefix + "*.dex")
        print(dex_names)
        index = 0

        if len(dex_names) == 0:
            print("dex_path is {}".format(dex_path_prefix))
            assert False, "[DexFinder]: fart didn't get the corrent dexfile or something else goes wrong"

        if len(dex_names) > 1:
            print("dexfile list:")
            print(dex_names)
            index = input("select a dex file 0~" + str(len(dex_names)-1) + ":\n")

        return dex_names[index]

    def launch_app(self):
        #TODO: you should implement this function by FRIDA and attention that it is highly possible that
        #TODO: you can not launch an app successfully
        main_activity = self.apk_analyzer.get_main_activity()
        package_name = self.apk_analyzer.get_package()
        main_activity = package_name + "/" + main_activity
        command = "adb shell am start -n " + main_activity
        print("we begin to launch app, command is:\n{}".format(command))
        result = os.popen(command)
        content = result.read()
        pattern = re.compile("exception|error")
        result = pattern.findall(content)
        if len(result) > 0:
            print("failed to launch")




# dexfinder = DexFinder("../Data/apk/hellojnibak_with_permission_10_jiagu_sign.apk")
# dexfinder.grant_write_permission()
# dexfinder.launch_app()
# dexfinder.pull_dex_file()
