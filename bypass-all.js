
/*
This script is a collection of useful frida scripts that have been improved 
and brought together with the ability to run concurrently.
Collected and optimized by Mohammad Aramjoo*/

Java.perform(function() {
    //system exit bypass
     const System = Java.use('java.lang.System')

    console.log("--> System.exit() Bypass - Script Loaded")
    System.exit.implementation = function(){
        console.log("System.exit() Bypassed!");
    }
    //AES Key
    var secret_key_spec = Java.use("javax.crypto.spec.SecretKeySpec");
    //SecretKeySpec is inistantiated with the bytes of the key, so we hook the constructor and get the bytes of the key from it
    //We will get the key but we won't know what data is decrypted/encrypted with it
    secret_key_spec.$init.overload("[B", "java.lang.String").implementation = function (x, y) {
        send('{"my_type" : "KEY"}', new Uint8Array(x));
        //console.log(xx.join(" "))
        return this.$init(x, y);
    }
    //hooking IvParameterSpec's constructor to get the IV as we got the key above.
    var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
    iv_parameter_spec.$init.overload("[B").implementation = function (x) {
        send('{"my_type" : "IV"}', new Uint8Array(x));
        return this.$init(x);
    }
    //now we will hook init function in class Cipher, we will be able to tie keys,IVs with Cipher objects
    var cipher = Java.use("javax.crypto.Cipher");
    cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (x, y, z) {
        //console.log(z.getClass()); 
        if (x == 1) // 1 means Cipher.MODE_ENCRYPT
            send('{"my_type" : "hashcode_enc", "hashcode" :"' + this.hashCode().toString() + '" }');
        else // In this android app it is either 1 (Cipher.MODE_ENCRYPT) or 2 (Cipher.MODE_DECRYPT)
            send('{"my_type" : "hashcode_dec", "hashcode" :"' + this.hashCode().toString() + '" }');
        //We will have two lists in the python code, which keep track of the Cipher objects and their modes.


        //Also we can obtain the key,iv from the args passed to init call
        send('{"my_type" : "Key from call to cipher init"}', new Uint8Array(y.getEncoded()));
        //arg z is of type AlgorithmParameterSpec, we need to cast it to IvParameterSpec first to be able to call getIV function
        send('{"my_type" : "IV from call to cipher init"}', new Uint8Array(Java.cast(z, iv_parameter_spec).getIV()));
        //init must be called this way to work properly
        return cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").call(this, x, y, z);

    }
    //now hooking the doFinal method to intercept the enc/dec process
    //the mode specified in the previous init call specifies whether this Cipher object will decrypt or encrypt, there is no functions like cipher.getopmode() that we can use to get the operation mode of the object (enc or dec)
    //so we will send the data before and after the call to the python code, where we will decide which one of them is cleartext data
    //if the object will encrypt, so the cleartext data is availabe in the argument before the call, else if the object will decrypt, we need to send the data returned from the doFinal call and discard the data sent before the call
    cipher.doFinal.overload("[B").implementation = function (x) {
        send('{"my_type" : "before_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(x));
        var ret = cipher.doFinal.overload("[B").call(this, x);
        send('{"my_type" : "after_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(ret));

        return ret;
    }
       

    //end of aes key
    //trace
    function trace(pattern)
{
    var classsss = ["c.h.a"];
    var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";
    console.log("Class Triggered: " + type);
    if (type === "module") {
        var res = new ApiResolver("module");
        var matches = res.enumerateMatchesSync(pattern);
        var targets = uniqBy(matches, JSON.stringify);
        targets.forEach(function(target) {
            traceModule(target.address, target.name);
        });

    } else if (type === "java") {
        var found = false;
        Java.enumerateLoadedClasses({
            onMatch: function(aClass) {
                if(aClass.indexOf(pattern)>=0)
                {
                    traceClass(aClass);
                }
                
            },
            onComplete: function() {}
        });
        /*if (!found) {
            try {
                traceMethod(pattern);
            }
            catch(err) {
                console.error(err);
            }
        }*/
    }
}

function traceClass(targetClass)
{
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();
    hook.$dispose;

    var parsedMethods = [];
    methods.forEach(function(method) {
        parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
    });

    var targets = uniqBy(parsedMethods, JSON.stringify);
    targets.forEach(function(targetMethod) {
        //if(targetMethod =="toString")
            traceMethod(targetClass + "." + targetMethod);
    });
}

function traceMethod(targetClassMethod)
{
    var delim = targetClassMethod.lastIndexOf(".");
    if (delim === -1) return;

    var targetClass = targetClassMethod.slice(0, delim)
    var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

    var hook = Java.use(targetClass);
    var overloadCount = hook[targetMethod].overloads.length;

    console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

    for (var i = 0; i < overloadCount; i++) {

        hook[targetMethod].overloads[i].implementation = function() {
            console.warn("\n*** entered " + targetClassMethod);

            // print backtrace
            // Java.perform(function() {
            //  var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            //  console.log("\nBacktrace:\n" + bt);
            // });   
            //if (arguments.length) console.log();
            for (var j = 0; j < arguments.length; j++) {
                if(typeof arguments[j] == 'string' &&arguments[j].indexOf("2018-12-22")>=0){
                    arguments[j] = "2018-12-24T17:40:14";
                } 
                console.log(targetClassMethod + " arg[" + j + "]: " + arguments[j]);
            }

            
            // print retval
            /*var retval = this[targetMethod].apply(this, arguments);
            console.log("\nretval: " + retval);
            console.warn("\n*** exiting " + targetClassMethod);*/
            var retval;
            try {
                retval = this[targetMethod].apply(this, arguments);
            }
            catch(err) {
                console.error(err);
            }
            //var retval = this[targetMethod].apply(this, arguments);
            if(retval==1994986406)
                arguments[j] = 444376755;
            else if(retval=="1994986406")
                arguments[j] = "444376755";
            console.log("\n" + targetClassMethod + " retval: " + retval);
            return retval;
        }
    }
}

function traceModule(impl, name)
{
    console.log("Tracing " + name);

    Interceptor.attach(impl, {

        onEnter: function(args) {

            this.flag = false;
            
                this.flag = true;

            if (this.flag) {
                console.warn("\n*** entered " + name);

                //console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    //  .map(DebugSymbol.fromAddress).join("\n"));
            }
        },

        onLeave: function(retval) {

            /*if (this.flag) {
                // print retval
                console.log("\nretval: " + retval);
                console.warn("\n*** exiting " + name);
            }*/
        }

    });
}

        function uniqBy(array, key)
        {
                var seen = {};
                return array.filter(function(item) {
                        var k = key(item);
                        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
                });
        }
        
       
        //trace("null");
      
        //traceClass("null");
        //traceMethod("null");
    //ssl unpin
    console.log("");
        console.log("[.] Android Cert Pinning Bypass");

        
        
        var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        var FileInputStream = Java.use("java.io.FileInputStream");
        var BufferedInputStream = Java.use("java.io.BufferedInputStream");
        var X509Certificate = Java.use("java.security.cert.X509Certificate");
        var KeyStore = Java.use("java.security.KeyStore");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        console.log("[.] TrustManagerImpl detection...");
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[+] TrustManagerImpl verifyChain() called. Not throwing an exception.");
                return untrustedChain;
            }

            PinningTrustManager.checkServerTrusted.implementation = function() {
                console.log("[+] Appcelerator checkServerTrusted() called. Not throwing an exception.");
            }
        } catch (err) {
            console.log("[-] TrustManagerImpl Not Found");
        }
        console.log("[.] TrustManager detection...");
        var TrustManager = Java.registerClass({
            name: 'com.sensepost.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

        try {
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log("[+] Overriding SSLContext.init() with the custom TrustManager android");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch (err) {
            console.log("[-] TrustManager Not Found");
        }
        console.log("[.] OkHTTP detection...");
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            console.log("[+] OkHTTP 3.x Found");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log("[+] OkHTTP check() called. Not throwing an exception.");
            };
        } catch (err) {
            console.log("[-] OkHTTP Not Found")
        }
        console.log("[.] Appcelerator Titanium detection...");
        try {
            var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
            console.log("[+] Appcelerator Titanium Found");
            PinningTrustManager.checkServerTrusted.implementation = function() {
                console.log("[+] Appcelerator checkServerTrusted() called. Not throwing an exception.");
            }

        } catch (err) {
            console.log("[-] Appcelerator Titanium Not Found");
        }

        
    
    //anti root starts here
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {
            //useProcessManager = true;
            //var ProcessManager = Java.use('java.lang.ProcessManager');
        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {
            //useKeyInfo = true;
            //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen");
            }
        },
        onLeave: function(retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {

        }
    });

    /*

    TO IMPLEMENT:

    Exec Family

    int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
    int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
    int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
    int execv(const char *path, char *const argv[]);
    int execve(const char *path, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int execvpe(const char *file, char *const argv[], char *const envp[]);

    */


    BufferedReader.readLine.implementation = function() {
        var text = this.readLine.call(this);
        if (text === null) {
            // just pass , i know it's ugly as hell but test != null won't work :(
        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };

    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }

});
