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
            const androidMasterVersion = parseInt(Java.androidVersion.substring(0, 1));
            if (androidMasterVersion >= 6) {
                const symb = linker.enumerateSymbols();
                let phdrtgdsPtr = NULL;
                let dodlopenPtr = NULL;

                for (let sym in symb) {
                    if (symb[sym].name.indexOf("phdr_table_get_dynamic_section") >= 0) {
                        phdrtgdsPtr = symb[sym].address;
                    } else if (symb[sym].name.indexOf('do_dlopen') >= 0) {
                        dodlopenPtr = symb[sym].address;
                    }
                    if (phdrtgdsPtr.compare(NULL) > 0 && dodlopenPtr.compare(NULL) > 0) {
                        break;
                    }
                }

                if (phdrtgdsPtr.compare(NULL) > 0 && dodlopenPtr.compare(NULL) > 0) {
                    let moduleName: string | null = null;

                    interceptors.push(Interceptor.attach(phdrtgdsPtr, function (args) {
                        if (moduleName && onLoadCallback) {
                            onLoadCallback(moduleName, args[2]);
                        }
                    }));

                    interceptors.push(Interceptor.attach(dodlopenPtr, function (args) {
                        moduleName = args[0].readCString();
                    }));

                    return true;
                }
            } else {
                if (Process.arch === 'ia32') {
                    // this suck hard but it's the best way i can think
                    // working on latest nox emulator 5.1.1
                    const linkerRanges = linker.enumerateRanges('r-x');
                    if (linkerRanges) {
                        for (let i = 0; i < linkerRanges.length; i++) {
                            let range = linkerRanges[i];
                            let res = Memory.scanSync(range.base, range.size, '89 FD C7 44 24 30 00 00 00 00');
                            if (res.length > 0) {
                                interceptors.push(Interceptor.attach(res[0].address, function () {
                                    const context = this.context as Ia32CpuContext;
                                    if (context.ecx.toInt32() !== 0x8) {
                                        return;
                                    }

                                    const w = context.esi.readCString();
                                    if (w && onLoadCallback !== null) {
                                        const module = Process.findModuleByName(w);
                                        if (module) {
                                            onLoadCallback(w, module.base);
                                        }
                                    }
                                }));
                                return true;
                            }
                        }
                    }
                }
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