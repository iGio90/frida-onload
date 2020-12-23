export module OnLoadInterceptor {
    const interceptors: InvocationListener[] = [];
    let onLoadCallback: OnLoadCallback | null = null;
    let onJavaClassLoadCallback: OnJavaClassLoadCallback | null = null;

    let attached = false;
    let javaAttached = false;

    type OnLoadCallback = (name: string, base: NativePointer) => void;
    type OnJavaClassLoadCallback = (clazz: string) => void;

    export function attach(callback: OnLoadCallback): boolean {
        onLoadCallback = callback;
        if (!attached) {
            attached = attachInternals();
        }
        return attached;
    }

    export function attachJava(callback: OnJavaClassLoadCallback): boolean {
        onJavaClassLoadCallback = callback;
        if (!javaAttached) {
            javaAttached = attachJavaInternals(true);
        }
        return javaAttached;
    }

    export function detach(): void {
        interceptors.forEach(interceptor => {
            interceptor.detach();
        });
        attached = false;
    }

    export function detachJava(): void {
        attachJavaInternals(false);
        javaAttached = false;
    }

    function attachInternals(): boolean {
        if (Process.platform === 'windows') {
            return attachWindows();
        } else if (Java.available) {
            return attachAndroid();
        }

        return false;
    }

    function attachJavaInternals(attach: boolean): boolean {
        if (Java.available) {
            Java.performNow(() => {
                const handler = Java.use('java.lang.ClassLoader');
                const overload = handler.loadClass.overload('java.lang.String', 'boolean');
                if (!attach) {
                    overload.implementation = null;
                } else {
                    overload.implementation = function (clazz: string, resolve: boolean) {
                        if (onJavaClassLoadCallback) {
                            onJavaClassLoadCallback(clazz);
                        }
                        return overload.call(this, clazz, resolve);
                    };
                }
            });
            return true;
        }
        return false;
    }

    function attachAndroid(): boolean {
        const linker = Process.findModuleByName(Process.arch.indexOf('64') >= 0 ? 'linker64' : "linker");
        if (linker) {
            const symbols = linker.enumerateSymbols();
            let doDlOpenPtr = NULL;
            let callCtor = NULL;

            for (let index in symbols) {
                if (symbols[index].name.indexOf("call_constructor") >= 0) {
                    callCtor = symbols[index].address;
                } else if (symbols[index].name.indexOf('do_dlopen') >= 0) {
                    doDlOpenPtr = symbols[index].address;
                }

                if (callCtor.compare(NULL) > 0 && doDlOpenPtr.compare(NULL) > 0) {
                    break;
                }
            }

            if (callCtor.compare(NULL) > 0 && doDlOpenPtr.compare(NULL) > 0) {
                let moduleName: string | null = null;

                interceptors.push(Interceptor.attach(callCtor, function (args) {
                    if (moduleName && onLoadCallback) {
                        const targetModule = Process.findModuleByName(moduleName);
                        if (targetModule !== null) {
                            onLoadCallback(moduleName, targetModule.base);
                            moduleName = null;
                        }
                    }
                }));

                interceptors.push(Interceptor.attach(doDlOpenPtr, function (args) {
                    moduleName = args[0].readCString();
                }));

                return true;
            }
        }

        return false;
    }

    function attachWindows(): boolean {
        const kernel32 = Process.findModuleByName('kernel32.dll');
        if (kernel32) {
            const symbols = kernel32.enumerateSymbols();
            let loadlibaPtr = NULL;
            let loadlibexaPtr = NULL;
            let loadlibwPtr = NULL;
            let loadlibexwPtr = NULL;

            for (const symbol in symbols) {
                if (symbols[symbol].name.indexOf('LoadLibraryA') >= 0) {
                    loadlibaPtr = symbols[symbol].address;
                } else if (symbols[symbol].name.indexOf('LoadLibraryW') >= 0) {
                    loadlibwPtr = symbols[symbol].address;
                } else if (symbols[symbol].name.indexOf('LoadLibraryExA') >= 0) {
                    loadlibexaPtr = symbols[symbol].address;
                } else if (symbols[symbol].name.indexOf('LoadLibraryExW') >= 0) {
                    loadlibexwPtr = symbols[symbol].address;
                }

                if ((loadlibaPtr.compare(NULL) !== 0) && (loadlibwPtr.compare(NULL) !== 0) &&
                    (loadlibexaPtr.compare(NULL) !== 0) && (loadlibexwPtr.compare(NULL) !== 0)) {
                    break;
                }
            }
            if ((loadlibaPtr.compare(NULL) !== 0) && (loadlibwPtr.compare(NULL) !== 0) &&
                (loadlibexaPtr.compare(NULL) !== 0) && (loadlibexwPtr.compare(NULL) !== 0)) {
                interceptors.push(Interceptor.attach(loadlibaPtr, function (args) {
                    const moduleName = args[0].readAnsiString();
                    if (moduleName && onLoadCallback) {
                        onLoadCallback(moduleName, args[2]);
                    }
                }));
                interceptors.push(Interceptor.attach(loadlibexaPtr, function (args) {
                    const moduleName = args[0].readAnsiString();
                    if (moduleName && onLoadCallback) {
                        onLoadCallback(moduleName, args[2]);
                    }
                }));
                interceptors.push(Interceptor.attach(loadlibwPtr, function (args) {
                    const moduleName = args[0].readUtf16String();
                    if (moduleName && onLoadCallback) {
                        onLoadCallback(moduleName, args[2]);
                    }
                }));
                interceptors.push(Interceptor.attach(loadlibexwPtr, function (args) {
                    const moduleName = args[0].readUtf16String();
                    if (moduleName && onLoadCallback) {
                        onLoadCallback(moduleName, args[2]);
                    }
                }));

                return true;
            }
        }

        return false;
    }
}