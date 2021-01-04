type OnLoadCallback = (module: Module, wasAlreadyLoaded: boolean) => void;

declare global {
    namespace Java {
        /**
         * It waits for a "java.lang.Class" to be defined, if necessary.
         * @param className The name of the class to wait for.
         * @return A promise containing the given class, or
         * "null" if a "NoClassDefFoundError" happened.
         */
        function waitFor(className: string): Promise<Java.Wrapper | null>;
    }

    namespace Module {
        /**
         * Executes a sync callback when a new "Module" is loaded,
         * before "DT_INIT" and "DT_INIT_ARRAY".
         * @param moduleName The name of the target module.
         * @param callback The callback to execute.
         */
        function onLoad(moduleName: string, callback: OnLoadCallback): void;

        /**
         * It waits for a "Module" to be loaded, if necessary.
         * @param moduleName The name of the target module.
         */
        function waitFor(moduleName: string): Promise<Module>;
    }
}

Java.waitFor = function (className) {
    return new Promise<Java.Wrapper | null>(resolve => {
        const responsible = Process.getModuleByName(Java.use("dalvik.system.VMRuntime").getRuntime().vmLibrary());
        const defineClassNative = responsible.enumerateSymbols().find(symbol => symbol.name.includes("defineClassNative"))!;

        const JavaString = Java.use("java.lang.String");
        const JavaClass = Java.use("java.lang.Class");

        try {
            resolve(Java.use(className));
        } catch (e) {
            const interceptor = Interceptor.attach(defineClassNative.address, {
                onEnter(args) {
                    this.isTargetClass = Java.cast(args[2], JavaString).toString() == className;
                },
                onLeave(klassHandle) {
                    if (this.isTargetClass) {
                        setTimeout(() => interceptor.detach());
                        resolve(klassHandle.isNull() ? null : Java.cast(klassHandle, JavaClass));
                    }
                }
            });
        }
    });
};

Module.onLoad = function (moduleName: string, callback: OnLoadCallback) {
    if (!isAndroid && !isWindows) throw new Error("Platform ${Process.platform} is not supported.");

    function returner() {
        setTimeout(() => interceptors.forEach(i => i.detach()));
        callback(Process.getModuleByName(moduleName), false);
    }

    const targets = getTargets();

    const module = Process.findModuleByName(moduleName);
    if (module) {
        callback(module, true);
        return;
    }

    const interceptors = targets.map(target => {
        const callbacks: ScriptInvocationListenerCallbacks = {};

        if (isAndroid) {
            callbacks.onLeave = function (returnValue) {
                if (returnValue.readUtf8String()?.endsWith(moduleName)) {
                    returner();
                }
            };
        } else if (isWindows) {
            callbacks.onEnter = function (args) {
                this.modulePath = target.name.endsWith("A") ? args[0].readAnsiString() : args[0].readUtf16String();
            };
            callbacks.onLeave = function () {
                if (this.modulePath.endsWith(moduleName)) {
                    returner();
                }
            };
        }

        return Interceptor.attach(target.address, callbacks);
    });
};

Module.waitFor = function (moduleName) {
    return new Promise<Module>(resolve => Module.onLoad(moduleName, resolve));
};

let getTargets = () => {
    const responsibleName = isAndroid ? (Process.arch.endsWith("64") ? "linker64" : "linker") : "kernel32.dll";

    const targetNames = isAndroid ? ["get_realpath"] : ["LoadLibraryA", "LoadLibraryExA", "LoadLibraryW", "LoadLibraryExW"];

    const targets = Process.getModuleByName(responsibleName)
        .enumerateSymbols()
        .filter(symbol => targetNames.some(target => symbol.name.includes(target)));

    return (getTargets = () => targets)();
};

const isAndroid = Java.available;
const isWindows = Process.platform == "windows";

export {};
