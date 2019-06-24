const nullPtr = ptr(0);
const interceptors: InvocationListener[] = [];
let onLoadCallback: OnLoadCallback | null = null;
let attached = false;

type OnLoadCallback = (name: string, base: NativePointer) => void;

export function attach(callback: OnLoadCallback): void {
    onLoadCallback = callback;
    if (!attached) {
        attachInternals();
    }
}

export function detach(): void {
    interceptors.forEach(interceptor => {
        interceptor.detach();
    });
    attached = false;
}

function attachInternals() {
    const linker = Process.findModuleByName(Process.arch.indexOf('64') >= 0 ? 'linker64' : "linker");
    if (linker) {
        Java.performNow(function () {
            const sdk = Java.use('android.os.Build$VERSION')['SDK_INT']['value'];

            if (sdk >= 23) {
                const symb = linker.enumerateSymbols();
                let phdr_tgds_ptr = nullPtr;
                let do_dlopen_ptr = nullPtr;

                for (let sym in symb) {
                    if (symb[sym].name.indexOf("phdr_table_get_dynamic_section") >= 0) {
                        phdr_tgds_ptr = symb[sym].address;
                    } else if (symb[sym].name.indexOf('do_dlopen') >= 0) {
                        do_dlopen_ptr = symb[sym].address;
                    }
                    if (phdr_tgds_ptr.compare(nullPtr) > 0 && do_dlopen_ptr.compare(nullPtr) > 0) {
                        break;
                    }
                }

                if (phdr_tgds_ptr.compare(nullPtr) > 0 && do_dlopen_ptr.compare(nullPtr) > 0) {
                    let moduleName: string | null = null;

                    interceptors.push(Interceptor.attach(phdr_tgds_ptr, function (args) {
                        if (moduleName && onLoadCallback) {
                            onLoadCallback(moduleName, args[2]);
                        }
                    }));

                    interceptors.push(Interceptor.attach(do_dlopen_ptr, function (args) {
                        moduleName = args[0].readCString();
                    }));
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
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
    attached = true;
}