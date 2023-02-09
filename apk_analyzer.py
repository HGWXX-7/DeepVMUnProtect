from pyaxmlparser import APK
import os
import shutil

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

# def save_dex_file():
#     dex_path = "/home/morangeous/bigtest/android_project/useful_tools/frida/FRIDA-DEXDump" \
#                "/python_test/automaticvmcracker/Data/dex_and_txt/1916212_dexfile_execute.dex"
#     dex_name = os.path.basename(dex_path)
#     saving_root = "/media/morangeous/morangeous/Work/VMCracker/Data/dex_and_txt/"
#     saving_path = os.path.join(saving_root, "com.example.automatic")
#     if not os.path.exists(saving_path):
#         os.mkdir(saving_path)
#
#     saving_path = os.path.join(saving_path, dex_name)
#     shutil.copy(dex_path, saving_path)
#
# if __name__ == "__main__":
#     save_dex_file()

# apk = APKAnalyzer("../Data/apk/1k_10_jiagu_sign.apk")
# print(apk.get_main_activity())
# activities = apk.get_self_activities()
# for activity in activities:
#     print(activity)
# apk = APK("../Data/com.fosung.lighthouse_3615.apk")
# print(apk.get_permissions())
# print(apk.has_request_write())
