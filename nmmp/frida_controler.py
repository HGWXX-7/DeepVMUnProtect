from time import sleep
import frida
from util import Util
from loguru import logger
import os
import sys
import threading



class FridaControler(threading.Thread):
    def __init__(self, frida_semaphore: threading.Semaphore, lldbserver_semaphore: threading.Semaphore, 
                 package_name: str, main_activity: str, js_script_path: str) -> None:
        super(FridaControler, self).__init__()
        self.name = "FridaControler"
        self.logger = logger.bind(tag=self.name)
        self.frida_semaphore = frida_semaphore
        self.lldbserver_semaphore = lldbserver_semaphore
        self.js_py_semaphore = threading.Semaphore(0)
        self.package_name = package_name
        self.main_activity = main_activity
        self.pid = 0
        with open(js_script_path, "r") as f:
            self.inject_script = f.read()
        
        
    def get_pid(self):
        counter = 0
        while self.pid == 0:
            self.logger.warning("no pid now")
            counter += 1
            sleep(1)
            if counter > 30:
                break
        return self.pid
    
    def on_message(self, message, data):
        if message['type'] == 'error':
            self.logger.error(f"Frida script error: {message['stack']}")
        else:
            self.logger.info(f"Frida message: {message['payload']}")
        if message['type'] == 'send':
            data = message['payload']
            if 'start_attach' in data:
                self.logger.info("Release semaphore for lldbserver")
                self.lldbserver_semaphore.release()
            elif 'js_end' in data:
                self.js_py_semaphore.release()
    
    def run(self):
        self.logger.info("Waiting for frida server start")
        self.frida_semaphore.acquire()
        
        device = frida.get_usb_device(timeout=5)
        logger.info(f"Device: {device}")
        self.pid = device.spawn([self.package_name])
        
        if self.pid == 0:
            raise RuntimeError
        
        session = device.attach(self.pid)
        if session is None:
            self.logger.error("Failed to create Frida session.")
        else:
            self.logger.info("Session created successfully.")
        script = session.create_script(self.inject_script)
        script.on('message', self.on_message)
        script.load()
        self.logger.info(f"main activity name is {self.main_activity}")
        self.logger.info(f"package name is {self.package_name}")
        script.exports.exporthookoncreate(self.main_activity)
        
        device.resume(self.pid)
        
        
        # We only start the main activty, so here, we only call one function in the script

        
        self.logger.info("Wait for frida script end")
        self.js_py_semaphore.acquire()
        
        self.logger.info("frida bid farewell, begin to release frida server")
        self.frida_semaphore.release()
        
    
    