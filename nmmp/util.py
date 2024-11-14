import os
from typing import Tuple
from androguard.misc import AnalyzeAPK
from time import sleep
import logging

from click import command
from loguru import logger
import sys
import subprocess

COMMAND = {
    'get_pid': 'adb shell "ps -A | grep {}"',
    'install_apk': 'adb install {}',
    'uninstall_apk': 'adb uninstall {}',
    'get_package_name': 'aapt dumpsys badging {}',
    'device_check': 'adb devices',
    'reboot_device': 'adb reboot',
    'unlock_device_without_pass': [
        'adb shell input keyevent 26', 
        'adb shell input touchscreen swipe 930 880 930 380'],
    'enter_android_system': 'adb shell getprop sys.boot_completed',
    'check_screen_light': 'adb shell dumpsys window policy',
    'get_top_activity': 'adb shell dumpsys activity top',
    'forward_port': 'adb forward tcp:{} tcp:{}'
}


# log_path = "/home/zhao/bigtest/android_project/nmmp/src/log/util.log"
# logger.add(log_path, format="{time} | {level} | {message}")
# logger.add(sys.stdout, level="INFO")

class Util(object):
    def __init__(self) -> None:
        self.logger = logger.bind(tag="Util")
        pass
    
    @staticmethod
    def get_package_name(apk_path: str) -> str:
        a, _, _ = AnalyzeAPK(apk_path)
        return a.get_package()

    @staticmethod
    def get_activity_names(apk_path: str) -> list:
        a, _, _ = AnalyzeAPK(apk_path)
        return a.get_activities()
    
    # FIXME: Remember to test it
    @staticmethod
    def get_package_and_activity(apk_path: str) -> Tuple[str, list]:
        a, _, _ = AnalyzeAPK(apk_path)
        package_name = a.get_package()
        activity_names = a.get_activities()
        main_activity = a.get_main_activity()
        activity_names.remove(main_activity)
        activity_names.insert(0, main_activity)
        
        return package_name, activity_names

    @staticmethod
    def execute_command(command: str) -> str:
        result = os.popen(command).read()
        return result

    @staticmethod
    def install_apk(apk_path: str) -> bool:
        package_name = Util.get_package_name(apk_path=apk_path)
        Util.uninstall_apk(package_name=package_name)
        command = COMMAND['install_apk'].format(apk_path)
        result = Util.execute_command(command=command)
        if "Success" in result:
            return True
        return False

    # FIXME: test it
    @staticmethod
    def uninstall_apk(package_name: str) -> bool:
        command = COMMAND['uninstall_apk'].format(package_name)
        result = Util.execute_command(command)
        Util().logger.info("Uninstall finished")
        if "Success" in result:
            return True
        return False
    
    @staticmethod
    def forward_tcp_port(port: str) -> None:
        command = COMMAND['forward_port'].format(port, port)
        Util().logger.info("Forwarding port by {}".format(command))
        Util.execute_command(command)
        Util().logger.info("Forwarded")

    @staticmethod
    def get_apk_pid(package_name: str) -> str:
        command = COMMAND['get_pid'].format(package_name)
        result = Util.execute_command(command=command)
        pid = ""
        if len(result) != 0:
            pid = result.split()[1]
        else:
            Util().logger.info("The application hasn't been started, pid is nonesense")
        return pid

    @staticmethod
    def check_device() -> bool:
        command = COMMAND['device_check']
        result = list(filter(None, Util.execute_command(command=command).split("\n")))
        if len(result) == 1:
            return False
        return True

    @staticmethod
    def check_enter_system()->bool:
        command = COMMAND['enter_android_system']
        result = Util.execute_command(command=command)
        if result.strip() == "1":
            return True
        
        return False

    # FIXME: use log to replace print
    @staticmethod
    def restart_device() -> bool:
        # reboot the device
        command = COMMAND['reboot_device']
        Util.execute_command(command=command)

        # check whether get device
        while not Util.check_device():
            sleep(1)
        Util().logger.info("Find device")
        
        # check whether enter system
        while not Util.check_enter_system():
            sleep(1)
        Util().logger.info("Enter system")
        
        # unlock the screen 
        commands = COMMAND['unlock_device_without_pass']
        state = Util.execute_command(command=COMMAND['check_screen_light'])

        Util().logger.info("state is {}".format(state))
        if 'mScreenOnEarly=false' in state:
            Util.execute_command(command=commands[0])
        Util.execute_command(command=commands[1])
        Util().logger.info("Reboot complete")
    
    @staticmethod
    def get_top_activity() -> str:
        command = COMMAND['get_top_activity']
        ret_value = Util.execute_command(command=command).split("\n")
        activity_lines = [x for x in ret_value if "ACTIVITY" in x]
        top_activity = activity_lines[-1].split()[1].replace("/", "")
        return top_activity

    @staticmethod
    def check_top_activity(activity_name: str):
        top_activity = Util.get_top_activity()
        if top_activity == activity_name:
            return True
        return False

    @staticmethod
    def delete_file(file_path:str):
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            Util().logger.warning("The file does not exist")
    @staticmethod
    def close_popup():
        try:
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "window", "windows"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if "PopupWindow" in result.stdout or "Application Not Responding" in result.stdout or "has stopped" in result.stdout:
                print("Popup detected. Attempting to close...")
                subprocess.run(["adb", "shell", "input", "keyevent", "4"])  # 返回键关闭弹窗
                print("Popup closed.")
            else:
                print("No popup detected.")
        except Exception as e:
            print(f"Error closing popup: {e}")
        
        Util.cleanup_all_popup()
    
    @staticmethod
    def cleanup_all_popup():
        for _ in range(10):
            subprocess.run(["adb", "shell", "input", "keyevent", "4"])


class BinaryRead(object):
    def __init__(self, data_buffer: bytes) -> None:
        self.data_buffer = data_buffer

    def read_n_char(self, offset, n) -> int:
        result = 0
        radio = 1
        index = 0

        while index <= n:
            result += self.data_buffer[offset + index] * radio
            radio *= 256
            index += 1
        
        return result

    def read_char(self, offset: int, adjust_offset=False) -> int:
        if adjust_offset:
            return self.read_n_char(offset, 0), offset + 1
        return self.read_n_char(offset, 0)

    def read_short(self, offset: int, adjust_offset=False) -> int:
        if adjust_offset:
            return self.read_n_char(offset, 1), offset + 2     
        return self.read_n_char(offset, 1)

    def read_int(self, offset: int, adjust_offset=False) -> int:
        if adjust_offset:
            return self.read_n_char(offset, 3), offset + 4
        return self.read_n_char(offset, 3)

    
    
    