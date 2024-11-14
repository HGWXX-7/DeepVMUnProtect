import pexpect
from time import sleep
import threading
from loguru import logger
import sys


class LLDBServer(threading.Thread):
    def __init__(self, lldbserver_semaphore: threading.Semaphore,lldb_semaphore: threading.Semaphore,
                 port: str, pid: str, lldb_server_path: str) -> None:
        super(LLDBServer, self).__init__()
        self.name = "LLDBServer"
        self.logger = logger.bind(tag=self.name)
        self.pid = pid
        self.port = port 
        self.lldb_server_path = lldb_server_path
        self.lldbserver_semaphore = lldbserver_semaphore
        self.lldb_semaphore = lldb_semaphore
    
    def run(self) -> bool:
        self.lldbserver_semaphore.acquire()
        
        # setup lldb server
        command = 'adb shell -t "su 0 {} g :{} --attach {}"'.format(self.lldb_server_path, self.port, self.pid)
        process = pexpect.spawn(command=command, timeout=30)
        self.logger.info("command = {}".format(command))
        
        try:
            process.expect("lldb-server-local_build")
        except:
            self.logger.fatal("fail to setup lldbserver")
            self.logger.fatal("process.before = {}".format(process.before))
            self.logger.fatal("process.after = {}".format(process.after))
            self.logger.fatal("process.buffer = {}".format(process.buffer))
        
        self.logger.info("lldb server started")
        self.lldb_semaphore.release()
        self.logger.info("Releasing semaphore for lldb")
        
        # connect with lldb client
        process.expect("Connection established")
        self.logger.info("LLDB client connected to LLDB server")
        
        sleep(5)
        # waiting lldb client quit, once execute to the end, lldb_semaphore will be released
        self.lldb_semaphore.acquire()
        self.logger.info("LLDB has quitted, LLDB server also quits")