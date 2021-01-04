declare global {
    namespace Java {
        /**
         * It waits for a `java.lang.Class` to be defined, if necessary.
         * @param className The name of the class to wait for.
         * @return A promise containing the given class, or
         * `null` if a `NoClassDefFoundError` happened.
         */
        function waitFor(className: string): Promise<Java.Wrapper | null>;
    }

    namespace Module {
        /**
         * Executes a sync callback as soon as a new `Module` is loaded
         * (e.g. before `DT_INIT` and `DT_INIT_ARRAY` on Android).
         * @param moduleName The name of the target module.
         * @param callback The callback to execute.
         */
        function onLoad(moduleName: string, callback: (module: Module, wasAlreadyLoaded: boolean) => void): void;

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

Module.onLoad = function (moduleName, callback) {
    if (!isAndroid && !isWindows) {
        throw new Error(`Platform ${Process.platform} is not supported.`);
    }

    const targets = getTargets();

    const module = Process.findModuleByName(moduleName);
    if (module) {
        callback(module, true);
    } else {
        const interceptors = targets.map(target =>
            Interceptor.attach(target.address, {
                onEnter(args) {
                    if (isWindows) {
                        this.modulePath = target.name.endsWith("A") ? args[0].readAnsiString() : args[0].readUtf16String();
                    }
                },
                onLeave(returnValue) {
                    const modulePath = isAndroid ? returnValue.readUtf8String() : (this.modulePath as string | null);
                    if (modulePath?.endsWith(moduleName)) {
                        setTimeout(() => interceptors.forEach(i => i.detach()));
                        callback(Process.getModuleByName(moduleName), false);
                    }
                }
            })
        );
    }
};

Module.waitFor = moduleName => new Promise<Module>(resolve => Module.onLoad(moduleName, resolve));

let getTargets = () => {
    const responsible = Process.getModuleByName(isAndroid ? (Process.pointerSize == 8 ? "linker64" : "linker") : "kernel32.dll");
    const targetNames = isAndroid ? ["get_realpath"] : ["LoadLibraryA", "LoadLibraryExA", "LoadLibraryW", "LoadLibraryExW"];

    const list: (ModuleExportDetails | ModuleSymbolDetails)[] = isAndroid ? responsible.enumerateSymbols() : responsible.enumerateExports();
    const targets = list.filter(symbolOrExport => targetNames.some(targetName => symbolOrExport.name.includes(targetName)));

    return (getTargets = () => targets)();
};

const isAndroid = Java.available;
const isWindows = Process.platform == "windows";

export {};
