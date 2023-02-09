import os

class APKParser(object):
    def __init__(self, apk_path) -> None:
        super().__init__()
        self.apt_path = apk_path
    
    def get_entrace_activity(self):
        command = "aapt dump badging "+ self.apt_path + " | grep launchable-activity"
        content = os.popen(command)
        result = content.read()
        result = result.split()
        entrance_activity = ""
        for item in result:
            if "name=" in item:
                entrance_activity = item.split("=")[1].strip()
                break
        
        return entrance_activity
        