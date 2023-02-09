var function_name = "com.example.helloworld.MainActivity.onCreate"
function sleep(time){
    var sleepaddr = Module.getExportByName("libc.so", "sleep");
    console.log("libc.so:sleep addr:" + sleepaddr);
    var sleep = new NativeFunction(sleepaddr, 'pointer', ['pointer']);
    Interceptor.attach(sleepaddr, {
        onEnter: function (args) {
            console.log(Process.getCurrentThreadId() + "--go into sleep,time:" + args[0]);
        }, onLeave: function (retval) {
            console.log(Process.getCurrentThreadId() + "--leave sleep");
        }
    });
    sleep(ptr(time))
}

function debug_template() {
    var libcmodule = Process.getModuleByName("libc.so");
    var strstr = libcmodule.getExportByName("strstr");
    var flag = false;
    Interceptor.attach(strstr, {
        onEnter: function (args) {
            this.haystack = Memory.readUtf8String(args[0]);
            this.needle = Memory.readUtf8String(args[1]);
            //flag=true
            if (this.needle.indexOf("JniMethodStart") !== -1) {
                // console.log(Process.getCurrentThreadId() + "---" + "[JniMethodStart]:" + this.haystack);
                if (this.haystack.indexOf(function_name) !== -1) {
                    console.log(Process.getCurrentThreadId() + "---go into strstr:" + this.haystack);
                    console.log("start sleep,press ctrl+c");
                    sleep(25)
                }
            }
        }, onLeave: function (retval) {
        }
    })
    console.log("leaving")
}

// function attach_activity(activity_name){
//     Java.perform(()=>{
//         const Activity = Java.use(activity_name)
//         Activity.onCreate.implementation=function(){
//             console.log("I came in")
//             this.onCreate()
//         }
//     })
// }

function start_another_activity(activity_name){
    Java.perform(function () {
        const FLAG_ACTIVITY_NEW_TASK = 0x10000000;
        const ActivityThread = Java.use("android.app.ActivityThread");
        const currentApplication = ActivityThread.currentApplication();
        const context = currentApplication.getApplicationContext();
        const androidIntent = Java.use("android.content.Intent");
        const newActivity = Java.use(activity_name).class;
        const newIntent = androidIntent.$new(context, newActivity);
        newIntent.setFlags(FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(newIntent);
        console.log("switched finished")
    })
}

function main(){
    console.log("enter main function")
    debug_template()
    console.log("exit main")
}

setImmediate(main);
