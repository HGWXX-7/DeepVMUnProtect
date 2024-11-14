from time import sleep
from frida_controler import FridaControler
from loguru import logger
from lldb_server import LLDBServer
from lldb_client import LLDBClient
from frida_server import FridaServer
from util import Util
import sys
import os
import json
import threading
import time
import re
from androguard.core.bytecodes.apk import APK
from tqdm import tqdm
import signal
import queue
from watch_dog import AndroidProcessNotFound, AndroidWatchdog

logger.remove()
log_path = "/home/zhao/bigtest/android_project/nmmp/src/log/all.log"
logger.add(log_path, format="{time} | {level} | {message}")
logger.add(sys.stdout, level="INFO")


# 定义超时异常
class TimeoutException(Exception):
    pass

class ProgramException(Exception):
    
    def __init__(self, message, code=None):
        super().__init__(message)  # 调用父类构造方法
        self.code = code  # 额外的错误代码

    def __str__(self):
        """返回异常的字符串表示。"""
        if self.code:
            return f"[Error {self.code}] {super().__str__()}"
        return super().__str__()

# 超时处理函数
def handler(signum, frame):
    raise TimeoutException("Exceeding time limit, quit here")
    


class AutoTracer(object):
    # def __init__(self, apk_path: str, trace_save_path: str) -> None:
    #     self.apk_path = apk_path
    #     self.trace_save_path = trace_save_path
    #     self.config()
    #     self.prepare_apk()
    
    # TODO: Add original folder
    def __init__(self, packed_apk_folder: str, nmmp_so_folder: str, trace_folder: str, timeout_json: str) -> None:
        self.trace_folder = trace_folder
        self.config()
        self.init_apk_info(packed_apk_folder=packed_apk_folder, nmmp_so_folder=nmmp_so_folder, timeout_json_path=timeout_json)

    
    '''
    apk_info:[
        {
            "apk_path": "/path/to/apk",
            "package_name": "com.xxx.xxx",
            "activity_name": "com.xxx.xxx.xxxActivity",
            "trace_save_path": "/path/to/trace",
            "timeout": 10
        }
    ]
    Attention: there are only packed apks in the packed_apk_folder, no other folder in this folder.
    
    timeout_json:{
        "pakcage_name": 10
    }
    
    '''
    
    def init_apk_info(self, packed_apk_folder: str, nmmp_so_folder: str, timeout_json_path: str):
        
        self.apk_info = []
        with open(timeout_json_path, "r") as f:
            timeout_json = json.load(f)
        
        
        for root, _, files in os.walk(packed_apk_folder):
            
            for file in files:
                apk_path = os.path.join(root, file)
                apk = APK(apk_path)
                
                match = re.search(r"signed_(.*?)-protect\.apk", file)
                if match:
                    apk_base_name =  match.group(1)  # 提取匹配到的 XXXX 部分
                else:
                    logger.error(f"fail to parse nmmp so of {file}")
                    continue
                nmmp_path = os.path.join(nmmp_so_folder, apk_base_name, "libnmmp.so")
                package_name = apk.get_package()
                main_activity = apk.get_main_activity()
                trace_save_path = os.path.join(self.trace_folder, f"{package_name}.txt")
                timeout = timeout_json[package_name]
                self.apk_info.append({
                    "apk_path": apk_path,
                    "nmmp_path": nmmp_path,
                    "package_name": package_name,
                    "activity_name": main_activity,
                    "trace_save_path": trace_save_path,
                    "timeout": timeout
                })
        

    def trace_all_apks(self):
        for apk_item in tqdm(self.apk_info):
            package_name = apk_item["package_name"]
            main_activity_name = apk_item["activity_name"]
            timeout = apk_item["timeout"]
            trace_path = apk_item["trace_save_path"]
            apk_path = apk_item["apk_path"]
            nmmp_path = apk_item["nmmp_path"]
            logger.info(f"Begin to process {apk_path}")
            
            
            # Check the trace file
            if os.path.exists(trace_path):
                # Once the trace file has more than 100 lines content, continue to another one 
                with open(trace_path, "r") as f:
                    content = f.readlines()
                    if len(content) > 100:
                        logger.info(f"{trace_path} exist, process next one")
                        continue
                    else:
                        logger.warning(f"{trace_path} exist, but too few lines, re-process it")
            else:
                logger.info(f"{trace_path} does not exist, begin to process")

            # Install and check
            is_installed = Util.install_apk(apk_path)
            if not is_installed:
                logger.error(f"Fail to install {apk_path}, process next one")
                continue
        
            # Re-assign the timeout
            if timeout >= 900:
                timeout = 900
            
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout)
            
            logger.info(f"Timeout set as:{timeout}")
            # Begin to process it 
            try:
                self.trace_single_file(package_name=package_name, main_activity_name=main_activity_name, 
                                   trace_save_path=trace_path, nmmp_path=nmmp_path, timeout=timeout)
            except TimeoutException as e:
                logger.warning("Process timeout, continue")
            except AndroidProcessNotFound as e:
                logger.warning("Program has been killed, continue")
            except Exception as e:
                logger.warning("Other exception catched, continue")
            finally:
                signal.alarm(0)
            
            
            # Uninstall the apk
            logger.info(f"begin to uninstall {package_name}")
            Util.uninstall_apk(package_name)
            
            # close all of the popup
            Util.close_popup()
            
            # This sleep is used to make the next loop work as usual
            sleep(5)
            
            
    
    # def prepare_apk(self):
    #     '''
    #     Here, we should install the apk, get its package name and full class name of MainActivity
    #     Now, this part can be ignored
    #     '''
    #     self.package_name = "com.example.moran.emptyapplication"
    #     self.main_activity_name = "com.example.moran.emptyapplication.MainActivity"
    
    def config(self):
        # For frida
        self.frida_server_path = "/data/local/tmp/frida-server-12.11.17-android-arm64"
        self.js_script_path = "/home/zhao/bigtest/android_project/nmmp/src/hook_vminterpret.js"
        
        # For lldb
        self.lldb_port = "9708"
        self.lldb_path = "/home/zhao/HotFix/Android/Sdk/ndk/22.0.7026061/toolchains/llvm/prebuilt/linux-x86_64/bin/lldb"
        self.lldb_server_path = "/data/local/tmp/lldb-server-1105-arm"
        
    
    def trace_single_file(self, package_name: str, main_activity_name: str, trace_save_path: str, nmmp_path: str, timeout: int):
        frida_semaphore = threading.Semaphore(0)
        lldb_semaphore = threading.Semaphore(0)
        lldb_server_semaphore = threading.Semaphore(0)
        Util.forward_tcp_port(self.lldb_port)
        
        
        
        # Start all frida thread
        frida_server_thread = FridaServer(frida_semaphore=frida_semaphore, frida_server_path=self.frida_server_path)
        frida_controler_thread = FridaControler(frida_semaphore=frida_semaphore, lldbserver_semaphore=lldb_server_semaphore,
                                                package_name=package_name, main_activity=main_activity_name, 
                                                js_script_path=self.js_script_path)
        
        frida_server_thread.start()
        frida_controler_thread.start()
        
        # lldb parameter preparation
        self.pid = frida_controler_thread.get_pid()
        target_activity_name = "Java_{}_onCreate".format(main_activity_name.replace(".", "_"))
        
        # Once get pid, start the watch dog
        exception_queue = queue.Queue()
        watch_dog = AndroidWatchdog(package_name=package_name, exception_queue=exception_queue)
        watch_dog.start()
        
        lldb_server = LLDBServer(lldbserver_semaphore=lldb_server_semaphore, lldb_semaphore=lldb_semaphore, port=self.lldb_port,
                                 pid=self.pid, lldb_server_path=self.lldb_server_path)
        lldb_client = LLDBClient(lldb_semaphore=lldb_semaphore, lldb_path=self.lldb_path, lldb_port=self.lldb_port, 
                                 trace_save_path=trace_save_path, nmmp_path=nmmp_path, activity_name= target_activity_name, 
                                 timeout=timeout)
        lldb_server.start()
        lldb_client.start()
        
        frida_controler_thread.join(timeout=30)
        # Once frida_controler_thread
        if frida_controler_thread.is_alive():
            logger.error("Frida timeout, something wrong, quitting")
            raise ProgramException("Fail to hook the program", 200)
        
        frida_server_thread.join()
        
        try:
            while lldb_client.is_alive():
                time.sleep(3)
                
                try:
                    exception = exception_queue.get_nowait()
                    raise exception
                
                except queue.Empty:
                    pass
        finally:
            watch_dog.stop()
            watch_dog.join()
        
        
        lldb_client.join()
        
        lldb_server.join()
        
        return 
    
    # This is a good one, I backup it by comments
    # def trace_single_file(self):
    #     frida_semaphore = threading.Semaphore(0)
    #     lldb_semaphore = threading.Semaphore(0)
    #     lldb_server_semaphore = threading.Semaphore(0)
    #     Util.forward_tcp_port(self.lldb_port)
        
    #     # Start all frida thread
    #     frida_server_thread = FridaServer(frida_semaphore=frida_semaphore, frida_server_path=self.frida_server_path)
    #     frida_controler_thread = FridaControler(frida_semaphore=frida_semaphore, lldbserver_semaphore=lldb_server_semaphore,
    #                                             package_name=self.package_name, main_activity=self.main_activity_name, 
    #                                             js_script_path=self.js_script_path)
        
    #     frida_server_thread.start()
    #     frida_controler_thread.start()
        
    #     # lldb parameter preparation
    #     self.pid = frida_controler_thread.get_pid()
        
    #     lldb_server = LLDBServer(lldbserver_semaphore=lldb_server_semaphore, lldb_semaphore=lldb_semaphore, port=self.lldb_port,
    #                              pid=self.pid, lldb_server_path=self.lldb_server_path)
    #     lldb_client = LLDBClient(lldb_semaphore=lldb_semaphore, lldb_path=self.lldb_path, lldb_port=self.lldb_port, 
    #                              trace_save_path=self.trace_save_path)
    #     lldb_server.start()
    #     lldb_client.start()
        
    #     frida_controler_thread.join()
    #     frida_server_thread.join()
    #     lldb_client.join()
    #     lldb_server.join()
        
    #     return 
        
    


'''
TODO: 
1. change the function name in hook_vminterpret.js

Input: the packed applications and the original applications
Action: install the application, after tracing, uninstall the application
Output: the package name, the target activity name, the save path 



'''


# # Successfully result:
# auto_tracer = AutoTracer("", "/home/zhao/bigtest/android_project/nmmp/data/traces/sayhello.log")
# auto_tracer.trace_single_file()





# Test for androguard

# start_time = time.time()
# apk_path = "/home/zhao/bigtest/android_project/nmmp/data/only-say-hello/app-release.apk"
# apk = APK(apk_path)

# package_name = apk.get_package()
# main_activity = apk.get_main_activity()

# end_time = time.time()
# elapsed_time = end_time - start_time  # 计算执行时间
# print(f"Execution Time: {elapsed_time:.6f} seconds")
# print(package_name)
# print(main_activity)

# dex_files = apk.get_all_dex()

# for dex in dex_files:
#     dvm = DalvikVMFormat(dex)
    
#     for clazz in dvm.get_classes():
#         if clazz.get_name() == f"L{main_activity.replace('.', '/')};":
#             print(f"Found class: {main_activity}")
            
#             for method in clazz.get_methods():
#                 if method.get_name() == "sayHello":
#                     print(f"Found method: {method.get_name()}")

#                     code = method.get_code()
#                     if code:
#                         bytecode = code.get_raw()
#                         bytecode_length = len(bytecode)
                        
#                         print(f"Bytecode: {bytecode.hex()}")
#                         print(f"Bytecode Length: {bytecode_length} bytes")
#                     else:
#                         print("No bytecode found for onCreate.")

#                     exit(0)


# This is test case
# packed_apk_folder = "/home/zhao/bigtest/android_project/nmmp/test/packed_apks"
# trace_folder = "/home/zhao/bigtest/android_project/nmmp/test/trace_folder"
# timeout_json = "/home/zhao/bigtest/android_project/nmmp/test/apk_timeout.json"

# auto_tracer = AutoTracer(packed_apk_folder, trace_folder, timeout_json)
# auto_tracer.trace_all_apks()



# This is the real case:
packed_apk_folder = "/home/zhao/HotFix/VMC/nmmp/all_packed_apks"
# packed_apk_folder = "/home/zhao/bigtest/android_project/nmmp/test/packed_apks"
nmmp_so_folder = "/home/zhao/HotFix/VMC/nmmp/all_nmmp_so"
trace_folder = "/home/zhao/bigtest/android_project/nmmp/data/traces"
timeout_json = "/home/zhao/bigtest/android_project/nmmp/data/apk_timeout.json"

auto_tracer = AutoTracer(packed_apk_folder, nmmp_so_folder, trace_folder, timeout_json)
auto_tracer.trace_all_apks()
