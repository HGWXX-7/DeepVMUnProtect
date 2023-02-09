import os
import pexpect
import glob
from pyaxmlparser import APK


class APKAnalyzer(object):
    def __init__(self, apk_path):
        self.apk = APK(apk_path)

    def get_main_activity(self):
        return self.apk.get_main_activity()

    def get_self_activities(self):
        activities = self.apk.get_activities()
        package_name = self.apk.get_package()
        result = []
        for activity in activities:
            if activity.startswith(package_name):
                result.append(activity)

        return result

    def get_activities(self):
        return self.apk.get_activities()

    def get_package(self):
        return self.apk.get_package()

    def has_request_write(self):
        permissions = self.apk.get_permissions()
        if "android.permission.WRITE_EXTERNAL_STORAGE" in permissions:
            return True
        return False

def get_zygote64_pid():
    command = 'adb shell "ps -A | grep zygote64"'
    content = os.popen(command).readlines()[0]
    pid = content.split()[1]
    return pid

def get_apk_parent_pid(package_name):
    command = 'adb shell "ps -A | grep {}"'.format(package_name)
    content = os.popen(command).readlines()[0]
    pid = content.split()[2]
    return pid

def install_start_apk(apk_path):
    command = 'adb install {}'.format(apk_path)
    process = pexpect.spawn(command, timeout=30)
    ret_val = ['Success', 'Failure']
    index = process.expect(ret_val)

    return index

def uninstall_apk(package_name):
    command = 'adb uninstall {}'.format(package_name)
    os.popen(command)

def get_apk_package(apk_path):
    command = "aapt dump badging {} | grep package".format(apk_path)
    result = os.popen(command).readlines()
    package_name = "error"
    try:
        package_name = result[0].split(" ")[1]
    except:
        print("Fail to get package name")
    return package_name[6:-1]

def mv_app(source, dest):
    command = "mv {} {}".format(source, dest)
    os.popen(command)


# FIXME: you should start the app before you get parent pid
def start():
    source_path = input("input the source path\n")
    dest_path = input("input the destination path\n")
    apk_paths = glob.glob(os.path.join(source_path, "*.apk"))
    zygote64_pid = get_zygote64_pid()
    print("zygote64 {}".format(zygote64_pid))
    for apk_path in apk_paths:
        apk = APK(apk_path)
        package_name = apk.get_package()
        main_activity = apk.get_main_activity()
        print("package_name {}".format(package_name))
        print("main_activity {}".format(main_activity))
        # ret_code = install_start_apk(apk_path)
        # if ret_code == 1:
        #     continue
        # parent_pid = get_apk_parent_pid(package_name)
        # if parent_pid != zygote64_pid:
        #     mv_app(apk_path, dest_path)
        # uninstall_apk(package_name)
start()
