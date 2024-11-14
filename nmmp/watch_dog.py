import pexpect
from time import sleep
import threading
from loguru import logger
import sys
import time
import subprocess
import queue

class AndroidProcessNotFound(Exception):
    """Android Process Detection Abnormal"""
    def __init__(self, package_name):
        super().__init__(f"Android process '{package_name}' not found.")




class AndroidWatchdog(threading.Thread):
    def __init__(self, package_name, exception_queue):
        super().__init__(daemon=True)
        self.package_name = package_name
        self.watchdog_active = False  # 控制 watchdog 线程状态
        self.name = "WatchDog"
        self.exception_queue = exception_queue
        self.logger = logger.bind(tag=self.name)
        self._stop_event = threading.Event()

    def is_process_alive(self):
        """通过 adb 检测 Android 进程是否存活。"""
        try:
            result = subprocess.run(
                ["adb", "shell", f"ps -A | grep {self.package_name}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3
            )
            return bool(result.stdout.strip())
        except subprocess.TimeoutExpired:
            print("ADB command timed out.")
            return False
        
    def check_anr_popup(self):
        try:
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "window", "windows"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if "Application Not Responding" in result.stdout or "has stopped" in result.stdout:
                self.close_anr_popup()
                return True
            
        except Exception as e:
            print(f"Error detecting ANR popup: {e}")
            return False

    def close_anr_popup(self):
        try:
            # 模拟按返回键关闭 ANR 弹窗
            subprocess.run(["adb", "shell", "input", "keyevent", "4"])  # KEYCODE_BACK
            print("ANR popup closed.")
        except Exception as e:
            print(f"Error closing ANR popup: {e}")

    def run(self):
        """Watchdog 线程的主逻辑，监控 Android 进程状态。"""
        print("Watchdog started...")
        try:
            while not self._stop_event.is_set():
                if not self.is_process_alive() or self.check_anr_popup():
                    self.exception_queue.put(AndroidProcessNotFound(self.package_name))
                time.sleep(2)
        except Exception as e:
            self.exception_queue.put(e)  # 将异常放入队列


    def watchdog(self):
        """Watchdog 线程：监控 Android 进程是否存活。"""
        print("Watchdog started...")
        while self.watchdog_active:
            if not self.is_process_alive() or self.check_anr_popup():
                raise AndroidProcessNotFound(self.package_name)  # 抛出异常终止程序
            time.sleep(2)  # 每 2 秒检查一次

    def stop(self):
        """停止 watchdog 线程。"""
        self._stop_event.set()


