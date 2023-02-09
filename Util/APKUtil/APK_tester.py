import os
import pexpect
import glob
from time import sleep

class APKTester(object):
    def __init__(self, apk_path, save_path):
        self.apk_paths = glob.glob(os.path.join(apk_path, "*.apk"))
        self.save_path = save_path

    def install_apks(self, apk_path):
        command = "adb install {}".format(apk_path)
        process = pexpect.spawn(command)
        ret_val = ["Success", "Failure"]
        index = process.expect(ret_val)
        return index

    def uninstall_apks(self, package_name):
        command = "adb uninstall {}".format(package_name)
        process = pexpect.spawn(command)
        ret_val = ["Success", "Failure", "Unknown"]
        index = process.expect(ret_val)
        if index == 0:
            print("Successfully uninstall")
        else:
            print("Fail to uninstall")

    def get_package_name(self, apk_path):
        command = "aapt dump badging {} | grep package".format(apk_path)
        result  = os.popen(command).readlines()
        package_name = result[0].split(" ")[1]
        return package_name[6:-1]

    def get_launcher_activity(self, apk_path):
        command = "aapt dump badging {} | grep activity".format(apk_path)
        result  = os.popen(command).readlines()
        package_name = result[0].split(" ")[1]
        return package_name[6:-1]

    def sign_apks(self):
        key_path = "/home/morangeous/Android/key_for_sign_apk/key.jks"
        password = "iamsmtwtfs"
        command = "jarsigner -verbose -keystore {} -storepass {} -keypass {} -signerjar"


    def launch_activity(self, package_name, apk_path):
        main_activity = self.get_launcher_activity(apk_path)
        command = "adb shell am start -W -n {}/{}".format(package_name, main_activity)
        process = pexpect.spawn(command)
        ret_val = True
        try:
            process.expect("complete", timeout=2)
        except:
            print("cannot launch, quiting")
            command = "adb shell input tap 100 500"
            os.popen(command)
            ret_val = False
        return ret_val

    def get_processed_apk(self, apk_list):
        result = []
        for apk in apk_list:
            result.append(apk.split(" ")[0].strip())

        return result



    def start_test(self):
        with open(self.save_path, 'a+') as f:
            existing_file = f.readlines()
            existing_file = self.get_processed_apk(existing_file)
            for apk_path in self.apk_paths:
                flag = False
                if apk_path in existing_file:
                    continue
                ret_val = self.install_apks(apk_path)
                package_name = self.get_package_name(apk_path)
                if ret_val == 0:
                    print("install successfully, launching app...")
                    try:
                        success = self.launch_activity(package_name, apk_path)
                        if success:
                            flag = True
                    except:
                        print("something wrong, quiting...")
                else:
                    print("fail to install")
                f.write("{} {}".format(apk_path, flag))
                self.uninstall_apks(package_name)


# def sign_apk(apk_path, new_path):
#     key_path = "/data/morangeous/VMCracker/KeyForSign/key.jks"
#     password = "iamsmtwtfs"
#     apks = os.listdir(apk_path)
#     counter = 0
#     for apk in apks:
#         new_name = os.path.join(new_path, "signed_{}".format(apk))
#         old_name = os.path.join(apk_path, apk)
#         command = "jarsigner -verbose -keystore {} -storepass {} -keypass {} -signedjar {} {} key0"\
#             .format(key_path, password, password, new_name, old_name)
#         print("{}.{}".format(str(counter), command))
#         os.popen(command)
#         counter += 1
#         if counter % 50 == 0:
#             print("begin to sleep")
#             sleep(5)

apk_tester = APKTester("/media/zhao/MalwareSample/VMPCracker/signed_data/", "./result.txt")
apk_tester.start_test()

# sign_apk("/media/zhao/MalwareSample/VMPCracker/original_data/", "/media/zhao/MalwareSample/VMPCracker/signed_data/")
