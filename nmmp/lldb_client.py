import pexpect
from time import sleep
import threading
from loguru import logger
import sys



class LLDBClient(threading.Thread):
    def __init__(self, lldb_semaphore: threading.Semaphore, lldb_path: str, lldb_port: str, trace_save_path: str, nmmp_path:str, activity_name: str, timeout: int) -> None:
        super(LLDBClient, self).__init__()
        self.name = "LLDBClient"
        self.logger = logger.bind(tag=self.name)
        self.lldb_semaphore = lldb_semaphore
        self.lldb_path = lldb_path
        self.lldb_port = lldb_port
        self.trace_save_path = trace_save_path
        self.activity_name = activity_name
        self.nmmp_path = nmmp_path
        self.timeout = timeout
    
    def clear_pexpect_buffer(self):
        self.lldb_process.expect(r".+")
    
    
    def exe_cmd_by_send(self, command: str, expect_retval: list, clear_buffer: bool, timeout=30):        
        all_expect = [pexpect.TIMEOUT, pexpect.EOF]
        all_expect.extend(expect_retval)
        error_code = {
            0: "TIMEOUT", 
            1: "EOF"
        }
        
        self.logger.info("command: {}".format(command))
        self.logger.info("expect words: {}".format(all_expect))
        
        self.lldb_process.sendline(command)
        
        retval = self.lldb_process.expect(all_expect, timeout=timeout)
        self.logger.info("retval is {}".format(retval))
            
        if retval == 0 or retval == 1:
            # fail to execute the command here
            self.logger.fatal("command \"{}\" execute failed, error msg is:{}".format(command, error_code[retval]))
            return 0
        
        if clear_buffer:
            self.lldb_process.expect(r".+")
        return retval
    
    def connect_lldb_server(self):
        command = "gdb-remote {}".format(self.lldb_port)
        expect_retval = ["stop reason"]
        
        # retval = self.exe_cmd_by_send(command=command, expect_retval=expect_retval, clear_buffer=True, timeout=None)
        retval = self.exe_cmd_by_send(command=command, expect_retval=expect_retval, clear_buffer=True)
        
        if not retval:
            self.logger.fatal("Fail to attach gdb server")
            self.logger.fatal("Command is {}".format(command))
            self.logger.fatal("Pexpect return value is {}, Sleep 10000 seconds".format(self.lldb_process.before))
            # TODO: Add Handler here
            sleep(10000)
    
    def start_trace(self):
        command = "nmmp_unpack -f {} -p {} -a {}".format(self.trace_save_path, self.nmmp_path, self.activity_name)
        expect_retval = ["\[ENDSIGNAL\]"]
        
        # self.logger.info(f"Trace by {command}")
        
        retval = self.exe_cmd_by_send(command=command, expect_retval=expect_retval, clear_buffer=True, timeout=self.timeout)
        
        if not retval:
            self.logger.fatal("Fail to get the [ENDSIGNAL], may the function stopped somewhere")
            self.logger.fatal("Command is {}".format(command))
            self.logger.fatal("Pexpect return value is {}".format(self.lldb_process.before))
        
        if retval == 2:
            self.logger.success("lldb logging successfully, quitting")
        self.lldb_semaphore.release()            
    
    def run(self):
        self.lldb_semaphore.acquire()
        self.logger.info("Starting lldb using command {}".format(self.lldb_path))
        lldb_expect = "\(lldb\)"
        self.lldb_process = pexpect.spawn(self.lldb_path)
        self.lldb_process.expect(lldb_expect)
        self.logger.info("lldb client started, begin to connect lldb server")
        
        # Clear the buffer of pexpect
        self.clear_pexpect_buffer()
        
        # Connect to lldb server
        self.connect_lldb_server()
        
        # start to trace
        self.start_trace()
        
        
        
        
        

