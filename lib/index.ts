/**
 Frida onload - Copyright (C) 2019 Giovanni (iGio90) Rocca

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

const nullPtr = ptr(0);

class _OnLoadInterceptor {
    private moduleFilters = new Map<string, OnLoadCallback>();

    constructor() {
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
                        let callback: OnLoadCallback | null = null;
                        let moduleName: string | null = null;

                        Interceptor.attach(phdr_tgds_ptr, function (args) {
                            if (moduleName && callback) {
                                callback(moduleName, args[2]);
                                callback = null;
                            }
                        });

                        Interceptor.attach(do_dlopen_ptr, function (args) {
                            moduleName = args[0].readCString();
                            if (moduleName) {
                                callback = OnLoadInterceptor.getModuleLoadCallback(moduleName);
                            }
                        });
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
                                    Interceptor.attach(res[0].address, function () {
                                        const context = this.context as Ia32CpuContext;
                                        if (context.ecx.toInt32() !== 0x8) {
                                            return;
                                        }

                                        const w = context.esi.readCString();
                                        if (w) {
                                            const callback = OnLoadInterceptor.getModuleLoadCallback(w);
                                            if (callback) {
                                                const module = Process.findModuleByName(w);
                                                if (module) {
                                                    callback(w, module.base);
                                                }
                                            }
                                        }
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            });

        }
    }

    attach(moduleFilter: string, callback: OnLoadCallback): void {
        this.moduleFilters.set(moduleFilter, callback);
    }

    detach(moduleFilter: string): boolean {
        return this.moduleFilters.delete(moduleFilter);
    }

    private getModuleLoadCallback(what: string | null): OnLoadCallback | null {
        let res: OnLoadCallback | null = null;
        if (what) {
            Array.from(this.moduleFilters.keys()).forEach(moduleFilter => {
                if (what.indexOf(moduleFilter) >= 0) {
                    const callback = this.moduleFilters.get(moduleFilter);
                    if (callback) {
                        res = callback;
                    }
                }
            });
        }
        return res;
    }
}

export const OnLoadInterceptor = new _OnLoadInterceptor();

type OnLoadCallback = (name: string, base: NativePointer) => void;
