import os
import re
import time
from loguru import logger


class GetTime(object):
    def __init__(self, folder_path: str, save_path):
        # self.init_path(folder_path)
        self.folder_path = folder_path
        logger.add(save_path)
    
    def init_path(self, folder_path):
        pattern = re.compile("txt")
        file_names = os.listdir(folder_path)
        self.file_paths = []
        
        for file_name in file_names:
            if pattern.search(file_name):
                self.file_paths.append(os.path.join(folder_path, file_name))
    
    def get_all_times(self):
        for file_path in self.file_paths:
            logger.info("Path:{}".format(file_path))
            logger.info("Create time is {}".format(time.ctime(os.path.getctime(file_path))))
            logger.info("Access time is {}".format(time.ctime(os.path.getatime(file_path))))
            logger.info("Modify time is {}".format(time.ctime(os.path.getmtime(file_path))))
            logger.info("Access time - create time is {}".format((os.path.getatime(file_path) - os.path.getctime(file_path))))
            
    def calculate_execution_time(self):
        pkg_names = os.listdir(self.folder_path)
        
        cost_times = []

        for pkg_name in pkg_names:
            current_pkg_pth = os.path.join(self.folder_path, pkg_name)
            trace_names = os.listdir(current_pkg_pth)
            
            pkg_time_counter = []

            for trace_name in trace_names:
                current_trace_path = os.path.join(current_pkg_pth, trace_name)
                
                create_time = os.path.getctime(current_trace_path)
                modify_time = os.path.getmtime(current_trace_path)
                                
                logger.info("Processing: {}".format(current_trace_path))
                logger.info("Create time: {}".format(time.ctime(create_time)))
                logger.info("Modify time: {}".format(time.ctime(modify_time)))
                
                pkg_time_counter.append(create_time)
            
            pkg_time_counter = sorted(pkg_time_counter)
            cost_time = pkg_time_counter[-1] - pkg_time_counter[0]
            cost_times.append(cost_time)
            
            logger.info("Package name: {}. Cost time: {}(s)".format(pkg_name, cost_time))

        logger.info("Min: {}, Max: {}, AVG: {}".format(min(cost_times), max(cost_times), sum(cost_times) / len(cost_times)))


# get_time = GetTime("/home/morangeous/workspace/test/Deep-Android-Malware-Detection/arranged_dataset/Benign")
get_time = GetTime("/home/morangeous/MalwareSample/PackedMalware/Result/Trace", "./test_data.log")
get_time.calculate_execution_time()
