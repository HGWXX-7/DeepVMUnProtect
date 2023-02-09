import os
import re
import shutil

from automaticvmcracker.dex_finder import DexFinder
from automaticvmcracker.Util.dexparser import Dexparser
from tqdm import tqdm
from time import sleep

def sleep_with_tqdm(second):
    for i in tqdm(range(second)):
        sleep(1)


class OffsetParser(object):
    def __init__(self, apk_path) -> None:
        super().__init__()
        self.dex_finder = DexFinder(apk_path)
        self.dex_finder.grant_write_permission()
        #TODO: remember to change the launch method write in dex_finder
        #TODO: you need to implement this method by frida
        # Maybe it is also ok for you to launch the app directly
        self.dex_finder.launch_app()
        print("we are waiting for app running")
        sleep_with_tqdm(5)
        self.dex_finder.delete_dex_and_text()
        self.dex_finder.pull_dex_file()
        self.entrance_activity = self.dex_finder.apk_analyzer.get_main_activity()
        self.dex_path = self.dex_finder.select_dex_file()
        self.dex_parser = Dexparser(self.dex_path)
        self.save_dex_file()

    def get_dex_path(self):
        return self.dex_path

    def get_apk_activities(self):
        activities = self.dex_finder.apk_analyzer.get_activities()
        return [x.replace(".", "/") for x in activities]

    def get_native_oncreate(self):
        method_index = []
        target_activities = []
        native_method, native_class = self.dex_parser.get_native_method()
        package_name = self.dex_finder.apk_analyzer.get_package().replace(".", "/")
        # FIXME: delete following 3 lines after debug
        print("native method is listed below:")
        print(native_method)
        print("native class is listed below:")
        print(native_class)
        print("debug info end")
        activities = self.get_apk_activities()



        for index, method in enumerate(native_method):
            klass = native_class[index]
            oncreate_pattern = re.compile("oncreate", re.IGNORECASE)
            oncreate_matcher = oncreate_pattern.findall(method)
            '''
                Not all activities names start with the package name, "activity" also doesn't exist in every activity
                So it is unnecessary for us to check class name
            '''

            # activity_pattern = re.compile("activity", re.IGNORECASE)
            # activity_matcher = activity_pattern.findall(klass)
            # package_pattern = re.compile(package_name, re.IGNORECASE)
            # package_matcher = package_pattern.findall(klass)

            activity_matcher = None
            for activity in activities:
                activity_pattern = re.compile(activity, re.IGNORECASE)
                activity_matcher = activity_pattern.findall(klass)
                if len(activity_matcher) > 0:
                    temp_activity = activity.replace("/", ".")
                    target_activities.append(activity.replace("/", "."))
                    break

            # if len(oncreate_matcher) > 0 and len(activity_matcher) > 0 and len(package_matcher) > 0:
            if len(oncreate_matcher) > 0 and len(activity_matcher) > 0:
                method_index.append(index)

        entrance_index = None
        for index, activity_name in enumerate(target_activities):
            if self.entrance_activity in activity_name:
                entrance_index = index
                break

        target_activities[entrance_index], target_activities[0] = target_activities[0], target_activities[entrance_index]

        return method_index, target_activities
    @staticmethod
    def clean_raw_method_name(raw_method_name:str) -> str:
        '''
        input: protected native onCreate
        output: onCreate
        '''
        method_name = raw_method_name.split()[-1]
        return method_name
    @staticmethod
    def clean_raw_class_name(raw_class_name:str) -> str:
        '''
        input: class_data_off: 1891829 Lcom/example/multiactivity/SecondActivity;
        output: com.example.multiactivity.SecondActivity
        '''
        class_name = raw_class_name.split()[-1]
        class_name = class_name[1:-1]
        return class_name.replace("/", ".")

    @staticmethod
    def seperate_package_from_activities(package:str, activities: list) -> list:
        length = len(package)
        for i, activity in enumerate(activities):
            index = activity.find(package)
            if index != -1:
                activities[i] = activity[length + 1:]
            else:
                assert False, "[OffsetParser]: we didn't find package name in activity name"

        return activities

    def get_offset_of_native(self, method_index):
        '''
        class_name actually means  class name + activity name
        e.g. com.example.multiactivity.SecondActivity
        |----------class name----------||-activityname-|
        '''
        method_names = []
        class_names = []
        # offset_list = self.dex_parser.get_debug_info_offset(method_index)
        print("method_index is: {}".format(method_index))
        # input("we reach get_offset_of_native")
        entrance_index = None
        for index, i in enumerate(method_index):
            method_name = OffsetParser.clean_raw_method_name(self.dex_parser.native_method[i])
            class_name = OffsetParser.clean_raw_class_name(self.dex_parser.native_class[i].split()[-2])
            if self.entrance_activity in class_name:
                entrance_index = index
            method_names.append(method_name)
            class_names.append(class_name)

        # swap the entrance activity, onCreate and offset to the position 0 of list
        method_names[entrance_index], method_names[0] = method_names[0], method_names[entrance_index]
        class_names[entrance_index], class_names[0] = class_names[0], class_names[entrance_index]

        class_names = OffsetParser.seperate_package_from_activities(self.dex_finder.apk_analyzer.get_package(), class_names)

        return method_names, class_names

    def save_dex_file(self):
        dex_name = os.path.basename(self.dex_path)
        saving_root = "/home/morangeous/PackedMalware/Result/dex_file"
        saving_path = os.path.join(saving_root, self.dex_finder.apk_analyzer.get_package())
        if not os.path.exists(saving_path):
            os.mkdir(saving_path)

        saving_path = os.path.join(saving_path, dex_name)
        shutil.copy(self.dex_path, saving_path)

