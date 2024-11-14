import pexpect
from time import sleep
import threading
from loguru import logger
import sys



class FridaServer(threading.Thread):
    def __init__(self, frida_semaphore: threading.Semaphore, frida_server_path: str) -> None:
        super(FridaServer, self).__init__()
        self.name = "FridaServer"
        self.logger = logger.bind(tag=self.name)
        self.frida_semaphore = frida_semaphore
        self.frida_server_path = frida_server_path
    

    def run(self):
        command = 'adb shell -t "su 0 {}"'.format(self.frida_server_path)
        self.logger.info("Begin to start frida server by {}".format(command))
        pexpect.spawn(command)
        self.logger.info("Sleep 5s waiting for starting server")
        sleep(5)
        self.frida_semaphore.release()
        # input("Release semaphore, frida started")
        self.logger.info("Sleep 1s to wait frida client working")
        sleep(2)
        # self.client_semaphore.acquire()
        self.frida_semaphore.acquire()
        self.logger.info("Frida server work end, bids farewell")
