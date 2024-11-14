
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


function hook(){
    // Module.findExportByName("libnmmvm.so", "vmInterpret")

    var vmLib = Process.getModuleByName("libnmmp.so");
    var addr = vmLib.getExportByName("sayHello");
    Interceptor.attach(addr,{
        onEnter:function (args){
            console.log("find vmInterpret, begin to sleep");
            sleep(5);
        }, onLeave:function (retval){
            console.log("weak up, leaving..")
        }
    })
    console.log("successful");

}

function hookC(){
    var addr = Module.findExportByName("libc.so", "strcmp");
    Interceptor.attach(addr,{
        onEnter:function (args){
            console.log("find vmInterpret, begin to sleep");
            sleep(5);
        }, onLeave:function (retval){
            console.log("weak up, leaving..")
        }
    })
    console.log("successful");
}


function directHook(){
    var MainActivity = Java.use('com.example.moran.emptyapplication.MainActivity');

    MainActivity.sayHello.implementation = function(context){
        console.log("sayHello function called");
        var libaddr = Module.findExportByName("libnmmp.so", "vmInterpret");
        console.log("libaddr is ", libaddr);

        sleep(5)
        var ret = this.sayHello(context);
        console.log("sayHello returned: ", ret)
        return ret;
    };
}

function directHookOnCreate(activity_name){
    var TargetActivity = Java.use(activity_name);

    TargetActivity.onCreate.implementation = function(context){
        console.log("onCreate iscalled");
        var libaddr = Module.findExportByName("libnmmp.so", "vmInterpret");
        console.log("libaddr is ", libaddr);
        
        sleep(5)
        var ret = this.onCreate(context);
        return ret;
    };
}

function testHookOnSayHello(activity_name){
    var TargetActivity = Java.use(activity_name);
    TargetActivity.sayHello.implementation = function(context){
        console.log("sayHello iscalled");
        
        sleep(5)
        var ret = this.sayHello(context);
        return ret;
    };
}


function testHookStub(activity_name){
    Java.perform(function(){
    var TargetActivity = Java.use(activity_name)
    TargetActivity.sayHello.implementation = function(context){
        console.log("sayHello function called");

        // Tell lldb to attach
        send({
            'start_attach': true
        })
        sleep(5)

        send({
            'js_end': true
        })

        console.log("Javascript end here, release semaphore for lldbserver")
        var ret = this.sayHello(context);
        return ret;
    };
    })    
}

// This is used to hook the onCreate method eventually
function hookOnCreate(activity_name){
    Java.perform(function(){
        console.log("Java layer ready, hooking...");
    var TargetActivity = Java.use(activity_name)
    TargetActivity.onCreate.implementation = function(context){
        console.log("onCreate function called");

        var libaddr = Module.findExportByName("libnmmp.so", "vmInterpret");
        console.log("libaddr is ", libaddr);
        // Tell lldb to attach
        send({
            'start_attach': true
        })
        sleep(10)

        send({
            'js_end': true
        })

        console.log("Javascript end here, release semaphore for lldbserver")
        var ret = this.onCreate(context);
        return ret;
    };
    })    
}





function main(){
    Java.perform(function(){
        directHook()
    })
}


setImmediate(main);

rpc.exports = {
    exporttesthookstub: testHookStub,
    exporthookoncreate: hookOnCreate
}
